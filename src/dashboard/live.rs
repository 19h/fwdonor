//! Live dashboards: the summary is pushed to the pages over server-sent
//! events (`/api/dashboard/live`, `/api/dash/<key>/live`), and query results
//! are shared between viewers.
//!
//! The number of viewers doesn't multiply the work:
//! - One task (`run`) computes each summary at most once per interval, and
//!   only while a stream or a poll wants it. Every stream and every poll gets
//!   the same serialized bytes. The channels hold only the latest frame, so a
//!   slow connection skips frames instead of queueing them.
//! - A stream costs a connection and a small task, and per frame one write
//!   of shared bytes. Streams are capped in total and per address (`[live]`);
//!   past that the page polls `…/summary`. Public polls get the same frames;
//!   private ones are computed for each request (operators are few, and
//!   they expect to see what they just did).
//! - A stream starts with a random `retry:` and ends after a random lifetime
//!   and at shutdown, so reconnections spread out instead of arriving at once.
//! - The frame tells pages how often to refresh their table (`refresh`):
//!   every 10 s, less often as viewers grow, so that all of them together
//!   stay near `table_refreshes_per_sec`.
//! - Query results are cached by their parameters: computed once for any
//!   number of identical requests, kept while the catalog is unchanged and
//!   a few seconds past a change, and stored gzipped as well.

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use rand::Rng;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify, OnceCell};

use crate::analyze::zrax_label;
use crate::config;
use crate::error::ApiError;
use crate::http::AppState;
use crate::limits::ClientKey;
use crate::uploads::unix_now;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Public,
    Private,
}

const PRIVATE_INTERVAL: Duration = Duration::from_secs(1);
/// The catalog summary is computed again after this even without changes
/// (`last_hour` and `last_day` move with the clock).
const SUMMARY_MAX_AGE: Duration = Duration::from_secs(15);
/// An idle stream sends a ping this often (the page's watchdog, and dead
/// connections show up when the write fails).
const PING: Duration = Duration::from_secs(20);
const PING_EVENT: &[u8] = b"event: ping\ndata: 0\n\n";
/// A stream ends after a random time in this range, in seconds (the page
/// reconnects at once).
const LIFETIME: (u64, u64) = (10 * 60, 20 * 60);
/// The `retry:` a stream starts with, in ms: how long the page waits before
/// it reconnects after the stream breaks.
const RETRY_MS: (u64, u64) = (2_000, 12_000);
/// A poll waits at most this long for a summary being computed.
const POLL_WAIT: Duration = Duration::from_secs(10);
/// Seconds between table refreshes the frame asks for.
const MIN_REFRESH: u64 = 10;
const MAX_REFRESH: u64 = 300;
/// Query results kept: entries, and bytes (plain and gzipped).
const QUERY_SLOTS: usize = 256;
const QUERY_BYTES: usize = 32 << 20;
/// Public query results stay in use this long after the catalog changes.
/// Private ones only while it is unchanged: operators expect to see what
/// they just did.
pub const PUBLIC_QUERY_TTL: Duration = Duration::from_secs(5);
pub const PRIVATE_QUERY_TTL: Duration = Duration::ZERO;

/// A summary as polls and streams send it.
#[derive(Clone, Default)]
pub struct Frame {
    /// When it was last computed (None: never yet).
    pub at: Option<Instant>,
    pub json: Bytes,
    /// The same as a server-sent event.
    pub event: Bytes,
}

struct Channel {
    /// Streams: told when the content changes.
    frame: watch::Sender<Frame>,
    /// Polls: told at every computation, changed or not.
    tick: watch::Sender<u64>,
}

impl Channel {
    fn new() -> Self {
        Self { frame: watch::Sender::new(Frame::default()), tick: watch::Sender::new(0) }
    }

    fn wanted(&self) -> bool {
        self.frame.receiver_count() > 0 || self.tick.receiver_count() > 0
    }

    fn at(&self) -> Option<Instant> {
        self.frame.borrow().at
    }
}

#[derive(Default)]
struct Streams {
    total: usize,
    public: usize,
    by_client: HashMap<ClientKey, usize>,
}

pub struct Live {
    cfg: config::Live,
    public: Channel,
    private: Channel,
    wake: Notify,
    closing: watch::Sender<bool>,
    streams: Mutex<Streams>,
    pub public_queries: QueryCache,
    pub private_queries: QueryCache,
}

impl Live {
    pub fn new(cfg: &config::Live) -> Arc<Self> {
        Arc::new(Self {
            cfg: cfg.clone(),
            public: Channel::new(),
            private: Channel::new(),
            wake: Notify::new(),
            closing: watch::Sender::new(false),
            streams: Mutex::default(),
            public_queries: QueryCache::new(PUBLIC_QUERY_TTL),
            private_queries: QueryCache::new(PRIVATE_QUERY_TTL),
        })
    }

    fn channel(&self, scope: Scope) -> &Channel {
        match scope {
            Scope::Public => &self.public,
            Scope::Private => &self.private,
        }
    }

    fn interval(&self, scope: Scope) -> Duration {
        match scope {
            Scope::Public => Duration::from_millis(self.cfg.interval_ms),
            Scope::Private => PRIVATE_INTERVAL,
        }
    }

    /// Streams open: all, and on the public dashboard.
    pub fn streams(&self) -> (usize, usize) {
        let s = self.streams.lock().unwrap();
        (s.total, s.public)
    }

    /// Seconds between table refreshes for each public viewer.
    fn refresh(&self) -> u64 {
        let public = self.streams().1 as u64;
        (public / u64::from(self.cfg.table_refreshes_per_sec)).clamp(MIN_REFRESH, MAX_REFRESH)
    }

    /// End every stream and stop computing (at shutdown).
    pub fn close(&self) {
        self.closing.send_replace(true);
        self.wake.notify_one();
    }

    /// The summary for a public poll: the latest frame if it is fresh, else
    /// the next one computed (every poll waiting then shares that computation).
    pub async fn summary(&self, scope: Scope) -> Result<Response, ApiError> {
        let ch = self.channel(scope);
        let interval = self.interval(scope);
        let fresh = || {
            let f = ch.frame.borrow();
            f.at.is_some_and(|at| at.elapsed() < interval).then(|| f.json.clone())
        };
        if let Some(json) = fresh() {
            return Ok(json_response(json));
        }
        let mut tick = ch.tick.subscribe();
        self.wake.notify_one();
        let deadline = tokio::time::Instant::now() + POLL_WAIT;
        loop {
            // It may have been computed between the first look and subscribing.
            if let Some(json) = fresh() {
                return Ok(json_response(json));
            }
            match tokio::time::timeout_at(deadline, tick.changed()).await {
                Ok(Ok(())) => continue,
                _ => break,
            }
        }
        let f = ch.frame.borrow();
        match f.at {
            Some(_) => Ok(json_response(f.json.clone())),
            None => Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "the summary isn't ready yet").retry_after(2)),
        }
    }

    /// A server-sent event stream of the summary, for `client`.
    pub fn stream(self: &Arc<Self>, scope: Scope, client: ClientKey) -> Result<Response, ApiError> {
        let guard = self.open(scope, client)?;
        let mut frames = self.channel(scope).frame.subscribe();
        let closing = self.closing.subscribe();
        self.wake.notify_one();
        let (retry, lifetime) = {
            let mut rng = rand::rng();
            (rng.random_range(RETRY_MS.0..=RETRY_MS.1), rng.random_range(LIFETIME.0..=LIFETIME.1))
        };
        // The latest frame at once, even if a fresher one is being computed.
        let first = {
            let f = frames.borrow_and_update();
            let mut b = format!("retry: {retry}\n\n").into_bytes();
            if f.at.is_some() {
                b.extend_from_slice(&f.event);
            }
            Bytes::from(b)
        };
        let conn = Conn {
            frames,
            closing,
            deadline: tokio::time::Instant::now() + Duration::from_secs(lifetime),
            first: Some(first),
            _guard: guard,
        };
        let body = futures_util::stream::unfold(conn, |mut c| async move {
            if let Some(first) = c.first.take() {
                return Some((Ok::<_, std::convert::Infallible>(first), c));
            }
            enum Step {
                End,
                Frame,
                Ping,
            }
            let step = tokio::select! {
                biased;
                _ = c.closing.wait_for(|closing| *closing) => Step::End,
                _ = tokio::time::sleep_until(c.deadline) => Step::End,
                changed = c.frames.changed() => if changed.is_ok() { Step::Frame } else { Step::End },
                _ = tokio::time::sleep(PING) => Step::Ping,
            };
            match step {
                Step::End => None,
                Step::Frame => {
                    let event = c.frames.borrow_and_update().event.clone();
                    Some((Ok(event), c))
                }
                Step::Ping => Some((Ok(Bytes::from_static(PING_EVENT)), c)),
            }
        });
        let mut response = Response::new(Body::from_stream(body));
        let h = response.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert("x-accel-buffering", HeaderValue::from_static("no"));
        Ok(response)
    }

    fn open(self: &Arc<Self>, scope: Scope, client: ClientKey) -> Result<StreamGuard, ApiError> {
        if *self.closing.borrow() {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "live_closing", "the server is restarting").retry_after(5));
        }
        let mut s = self.streams.lock().unwrap();
        if s.total >= self.cfg.max_streams {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "live_full", "too many live viewers right now")
                .retry_after(60));
        }
        let n = s.by_client.entry(client).or_default();
        if *n >= self.cfg.streams_per_address {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "live_limit", "too many live views from this address")
                .retry_after(60));
        }
        *n += 1;
        s.total += 1;
        if scope == Scope::Public {
            s.public += 1;
        }
        Ok(StreamGuard { live: self.clone(), scope, client })
    }
}

struct Conn {
    frames: watch::Receiver<Frame>,
    closing: watch::Receiver<bool>,
    deadline: tokio::time::Instant,
    first: Option<Bytes>,
    _guard: StreamGuard,
}

/// One open stream (counted until the connection goes away).
struct StreamGuard {
    live: Arc<Live>,
    scope: Scope,
    client: ClientKey,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut s = self.live.streams.lock().unwrap();
        s.total -= 1;
        if self.scope == Scope::Public {
            s.public -= 1;
        }
        if let Some(n) = s.by_client.get_mut(&self.client) {
            *n -= 1;
            if *n == 0 {
                s.by_client.remove(&self.client);
            }
        }
    }
}

fn json_response(json: Bytes) -> Response {
    let mut response = Response::new(Body::from(json));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// Computes the summaries while someone wants them (runs until shutdown).
pub async fn run(state: AppState) {
    let live = state.dashboard.live.clone();
    let mut closing = live.closing.subscribe();
    // The catalog's summary, shared by both frames: (catalog version, when, value).
    let mut summary: Option<(u64, Instant, Value)> = None;
    let mut last_public: Option<Value> = None;
    loop {
        if *closing.borrow() {
            return;
        }
        let now = Instant::now();
        let due = |scope: Scope| {
            let ch = live.channel(scope);
            ch.wanted() && ch.at().is_none_or(|at| now >= at + live.interval(scope))
        };
        let (public, private) = (due(Scope::Public), due(Scope::Private));
        if public || private {
            let catalog = &state.dashboard.catalog;
            let stale = match &summary {
                Some((version, at, _)) => *version != catalog.version() || at.elapsed() >= SUMMARY_MAX_AGE || !catalog.ready(),
                None => true,
            };
            if stale {
                let (catalog, version) = (catalog.clone(), catalog.version());
                let computed = tokio::task::spawn_blocking(move || catalog.summary(unix_now(), &zrax_label())).await;
                match computed {
                    Ok(v) => summary = Some((version, Instant::now(), v)),
                    Err(e) => {
                        tracing::error!("live: computing the summary failed: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            let full = &summary.as_ref().expect("computed above").2;
            if public {
                let v = public_frame(full, live.refresh());
                let changed = last_public.as_ref().is_none_or(|last| !same_but_now(last, &v));
                publish(&live.public, &v, changed);
                if changed {
                    last_public = Some(v);
                }
            }
            if private {
                publish(&live.private, &private_frame(&state, full.clone()), true);
            }
            continue;
        }
        // Until the next frame is due, someone new turns up, or shutdown.
        let next = [Scope::Public, Scope::Private]
            .into_iter()
            .filter(|&s| live.channel(s).wanted())
            .map(|s| live.channel(s).at().map_or(now, |at| at + live.interval(s)))
            .min();
        let sleep = async {
            match next {
                Some(t) => tokio::time::sleep_until(t.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = live.wake.notified() => {}
            _ = closing.changed() => {}
            _ = sleep => {}
        }
    }
}

/// The private frame: the catalog's `full` summary, the server's state, and
/// the live viewers.
pub(super) fn private_frame(state: &AppState, full: Value) -> Value {
    let live = &state.dashboard.live;
    let mut v = super::http::private_summary(state, full);
    let (streams, public) = live.streams();
    v["live"] = json!({ "streams": streams, "public": public, "max": live.cfg.max_streams });
    v["refresh"] = json!(MIN_REFRESH);
    v
}

/// The public frame: the summary fields the public dashboard shows.
fn public_frame(full: &Value, refresh: u64) -> Value {
    let mut v = serde_json::Map::new();
    for f in super::public::SUMMARY_FIELDS {
        v.insert(f.into(), full[f].clone());
    }
    v.insert("now".into(), json!(unix_now()));
    v.insert("public".into(), json!(true));
    v.insert("refresh".into(), json!(refresh));
    Value::Object(v)
}

fn same_but_now(a: &Value, b: &Value) -> bool {
    match (a.as_object(), b.as_object()) {
        (Some(a), Some(b)) => a.len() == b.len() && a.iter().all(|(k, v)| k == "now" || b.get(k) == Some(v)),
        _ => a == b,
    }
}

/// Store a computed frame; open streams hear of it only if it `changed`.
/// It is stored either way, so polls and new streams get the current `now`.
fn publish(ch: &Channel, v: &Value, changed: bool) {
    let json = serde_json::to_vec(v).unwrap_or_default();
    let mut event = Vec::with_capacity(json.len() + 24);
    event.extend_from_slice(b"event: summary\ndata: ");
    event.extend_from_slice(&json);
    event.extend_from_slice(b"\n\n");
    let frame = Frame { at: Some(Instant::now()), json: Bytes::from(json), event: Bytes::from(event) };
    ch.frame.send_if_modified(|f| {
        *f = frame;
        changed
    });
    ch.tick.send_modify(|t| *t += 1);
}

// ------------------------------------------------------------------ queries

/// Query results by their parameters.
pub struct QueryCache {
    ttl: Duration,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
}

struct Slot {
    made: Instant,
    /// The catalog's version when it was made.
    version: u64,
    result: OnceCell<Cached>,
}

impl Slot {
    fn bytes(&self) -> usize {
        self.result.get().map_or(0, |c| c.json.len() + c.gzip.as_ref().map_or(0, Bytes::len))
    }
}

/// A query result, plain and (when it is worth it) gzipped.
#[derive(Clone)]
pub struct Cached {
    json: Bytes,
    gzip: Option<Bytes>,
}

impl Cached {
    /// Serialize (and compress) a result: call it off the async threads.
    pub fn encode(v: &Value) -> Cached {
        let json = serde_json::to_vec(v).unwrap_or_default();
        let gzip = (json.len() >= 1024).then(|| {
            let mut gz = flate2::write::GzEncoder::new(Vec::with_capacity(json.len() / 6), flate2::Compression::new(5));
            gz.write_all(&json).and_then(|_| gz.finish()).ok().map(Bytes::from)
        });
        Cached { json: Bytes::from(json), gzip: gzip.flatten() }
    }

    pub fn respond(&self, request: &HeaderMap) -> Response {
        match &self.gzip {
            Some(gz) if accepts_gzip(request) => {
                let mut response = json_response(gz.clone());
                response.headers_mut().insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                response.headers_mut().insert(header::VARY, HeaderValue::from_static("accept-encoding"));
                response
            }
            _ => {
                let mut response = json_response(self.json.clone());
                response.headers_mut().insert(header::VARY, HeaderValue::from_static("accept-encoding"));
                response
            }
        }
    }
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers.get_all(header::ACCEPT_ENCODING).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|part| {
        let mut it = part.split(';');
        let name = it.next().unwrap_or("").trim();
        let refused = it.any(|p| matches!(p.trim().strip_prefix("q="), Some(q) if q.trim().parse::<f32>().is_ok_and(|q| q == 0.0)));
        (name.eq_ignore_ascii_case("gzip") || name == "*") && !refused
    })
}

/// The cache key for query parameters (order doesn't matter).
pub fn query_key(params: &HashMap<String, String>) -> String {
    let mut pairs: Vec<_> = params.iter().map(|(k, v)| (k.as_str(), v.trim())).filter(|(_, v)| !v.is_empty()).collect();
    pairs.sort_unstable();
    let mut key = String::new();
    for (k, v) in pairs {
        key.push_str(k);
        key.push('=');
        key.push_str(v);
        key.push('&');
    }
    key
}

impl QueryCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, slots: Mutex::default() }
    }

    /// The result for `key` at catalog `version`: cached, being computed by
    /// another request (then this one waits for it), or `compute`d now.
    pub async fn get<F>(&self, key: String, version: u64, compute: F) -> Result<Cached, ApiError>
    where
        F: Future<Output = Result<Cached, ApiError>>,
    {
        let slot = {
            let mut slots = self.slots.lock().unwrap();
            match slots.get(&key) {
                Some(s) if s.version == version || s.made.elapsed() < self.ttl => s.clone(),
                _ => {
                    self.evict(&mut slots, version);
                    let s = Arc::new(Slot { made: Instant::now(), version, result: OnceCell::new() });
                    slots.insert(key, s.clone());
                    s
                }
            }
        };
        // A failure isn't kept: the next request for it tries again.
        slot.result.get_or_try_init(|| compute).await.cloned()
    }

    /// Make room for one more: drop what is out of date, then the oldest.
    fn evict(&self, slots: &mut HashMap<String, Arc<Slot>>, version: u64) {
        slots.retain(|_, s| s.version == version || s.made.elapsed() < self.ttl);
        while slots.len() >= QUERY_SLOTS || slots.values().map(|s| s.bytes()).sum::<usize>() > QUERY_BYTES {
            let Some(oldest) = slots.iter().min_by_key(|(_, s)| s.made).map(|(k, _)| k.clone()) else { break };
            slots.remove(&oldest);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cfg(max_streams: usize, per_address: usize) -> config::Live {
        config::Live { max_streams, streams_per_address: per_address, ..config::Live::default() }
    }

    #[tokio::test]
    async fn identical_queries_are_computed_once_until_the_catalog_moves_on() {
        let cache = Arc::new(QueryCache::new(Duration::from_millis(200)));
        let runs = Arc::new(AtomicUsize::new(0));
        let get = |version: u64| {
            let (cache, runs) = (cache.clone(), runs.clone());
            async move {
                cache
                    .get("q=a&".into(), version, async move {
                        runs.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(Cached::encode(&json!({ "version": version })))
                    })
                    .await
            }
        };
        // 50 at once share one computation.
        let all = futures_util::future::join_all((0..50).map(|_| get(1))).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(all.iter().all(|r| r.as_ref().unwrap().json == all[0].as_ref().unwrap().json));
        // The same version: still cached. A newer one: cached for the TTL, then computed again.
        get(1).await.unwrap();
        get(2).await.unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(&get(2).await.unwrap().json[..], br#"{"version":2}"#);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn failures_are_not_cached() {
        let cache = QueryCache::new(Duration::from_secs(60));
        let failed = cache.get("k".into(), 1, async { Err(ApiError::bad_request("no")) }).await;
        assert!(failed.is_err());
        let ok = cache.get("k".into(), 1, async { Ok(Cached::encode(&json!(1))) }).await;
        assert_eq!(&ok.unwrap().json[..], b"1");
    }

    #[test]
    fn big_results_are_gzipped_for_clients_that_take_it() {
        let rows: Vec<Value> = (0..200).map(|i| json!({ "sha256": format!("{i:064}"), "name": "firmware.bin" })).collect();
        let cached = Cached::encode(&json!({ "rows": rows }));
        let gz = cached.gzip.as_ref().expect("compressed");
        assert!(gz.len() * 5 < cached.json.len());
        let mut plain = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut plain).unwrap();
        assert_eq!(plain, cached.json);

        let mut h = HeaderMap::new();
        assert!(!accepts_gzip(&h));
        for (value, ok) in [("gzip, deflate, br", true), ("br;q=1.0, gzip;q=0.5", true), ("gzip;q=0", false), ("*", true), ("identity", false)] {
            h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(value));
            assert_eq!(accepts_gzip(&h), ok, "{value}");
        }
        h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(cached.respond(&h).headers()[header::CONTENT_ENCODING], "gzip");
        assert!(Cached::encode(&json!(1)).gzip.is_none(), "small results stay plain");
    }

    #[test]
    fn query_keys_ignore_order_and_empty_parameters() {
        let a: HashMap<String, String> = [("q", "arm"), ("limit", "100"), ("isa", "")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let b: HashMap<String, String> = [("limit", "100"), ("q", " arm ")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(query_key(&a), query_key(&b));
    }

    #[tokio::test]
    async fn streams_are_capped_in_total_and_per_address() {
        let live = Live::new(&cfg(3, 2));
        let a = ClientKey::from_ip("10.0.0.1".parse().unwrap());
        let b = ClientKey::from_ip("10.0.0.2".parse().unwrap());
        let s1 = live.stream(Scope::Public, a).unwrap();
        let _s2 = live.stream(Scope::Private, a).unwrap();
        assert_eq!(live.stream(Scope::Public, a).unwrap_err().status, StatusCode::TOO_MANY_REQUESTS);
        let _s3 = live.stream(Scope::Public, b).unwrap();
        assert_eq!(live.stream(Scope::Public, b).unwrap_err().status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(live.streams(), (3, 2));
        drop(s1);
        assert_eq!(live.streams(), (2, 1));
        let _s4 = live.stream(Scope::Public, a).unwrap();
        live.close();
        assert_eq!(live.stream(Scope::Public, b).unwrap_err().code, "live_closing");
    }

    #[tokio::test]
    async fn a_stream_starts_with_the_latest_frame_and_ends_at_shutdown() {
        use futures_util::StreamExt;
        let live = Live::new(&cfg(10, 10));
        publish(&live.public, &json!({ "files": 1, "now": 1 }), true);
        let a = ClientKey::from_ip("10.0.0.1".parse().unwrap());
        let mut body = live.stream(Scope::Public, a).unwrap().into_body().into_data_stream();
        let first = String::from_utf8(body.next().await.unwrap().unwrap().to_vec()).unwrap();
        assert!(first.starts_with("retry: "), "{first}");
        assert!(first.ends_with("event: summary\ndata: {\"files\":1,\"now\":1}\n\n"), "{first}");
        // Unchanged frames aren't sent again; changed ones are.
        publish(&live.public, &json!({ "files": 1, "now": 2 }), false);
        publish(&live.public, &json!({ "files": 2, "now": 3 }), true);
        let next = body.next().await.unwrap().unwrap();
        assert_eq!(&next[..], b"event: summary\ndata: {\"files\":2,\"now\":3}\n\n");
        live.close();
        assert!(body.next().await.is_none());
        assert_eq!(live.streams(), (0, 0));
        assert!(same_but_now(&json!({ "a": 1, "now": 1 }), &json!({ "a": 1, "now": 2 })));
        assert!(!same_but_now(&json!({ "a": 1, "now": 1 }), &json!({ "a": 2, "now": 1 })));
    }
}
