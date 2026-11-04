//! HTTP API and static frontend.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::analyze::{isa_display_name, raw_isas, zrax_label};
use crate::bulk::Bulk;
use crate::config::Config;
use crate::dashboard::Dashboard;
use crate::error::ApiError;
use crate::jobs::PostQueue;
use crate::ledger::Ledger;
use crate::limits::ClientKey;
use crate::pow::PowGate;
use crate::uploads::{unix_now, InitRequest, Uploads};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pow: Arc<PowGate>,
    pub uploads: Arc<Uploads>,
    pub queue: Arc<PostQueue>,
    pub ledger: Arc<Ledger>,
    pub bulk: Arc<Bulk>,
    pub dashboard: Arc<Dashboard>,
}

const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; \
                   style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                   object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn router(state: AppState) -> Router {
    let chunk_limit = state.config.limits.chunk_bytes as usize + 4096;
    let api = Router::new()
        .route("/api/policy", get(policy))
        .route("/api/health", get(health))
        .route("/api/stats", get(stats))
        .route("/api/challenge", get(challenge))
        .route("/api/known", post(known))
        .route("/api/uploads", post(init_upload))
        .route("/api/uploads/{id}", get(upload_status).delete(cancel_upload))
        .route("/api/uploads/{id}/complete", post(complete_upload))
        .route("/api/uploads/{id}/{index}", put(put_chunk).layer(DefaultBodyLimit::max(chunk_limit)))
        .merge(crate::bulk::http::api_routes(state.config.bulk.chunk_bytes as usize + 4096))
        .merge(crate::dashboard::http::api_routes())
        .merge(crate::dashboard::public::api_routes())
        .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store")));

    let files = ServeDir::new(&state.config.dist_dir)
        .precompressed_br()
        .precompressed_gzip()
        .append_index_html_on_directories(true);

    api.merge(crate::bulk::http::page_routes())
        .merge(crate::dashboard::http::page_routes())
        .merge(crate::dashboard::public::page_routes())
        .fallback_service(files)
        .layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, HeaderValue::from_static("no-cache")))
        .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .with_state(state)
}

/// The donor's address: the proxy's X-Forwarded-For entry when the peer is a
/// trusted proxy (pyx replaces any client-supplied value), else the peer.
pub(crate) fn client_ip(config: &Config, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    let trusted = config.trusted_proxies.iter().any(|p| *p == peer_ip || p.to_canonical() == peer_ip.to_canonical());
    if trusted {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer_ip
}

#[derive(Deserialize)]
struct PolicyQuery {
    /// The zrax revision the page was built with.
    rev: Option<String>,
}

async fn policy(State(state): State<AppState>, Query(q): Query<PolicyQuery>) -> impl IntoResponse {
    let c = &state.config;
    let revs = state.uploads.revisions();
    let now = unix_now();
    // `zrax_rev` is the revision the page must have to upload. A page on a
    // replaced revision gets its own back while that is still accepted (pages
    // that don't say compare with the oldest accepted one), and `zrax_latest`
    // tells it a reload would bring a newer classifier.
    let accepted = match q.rev {
        Some(rev) if revs.accepts(&rev, now) => rev,
        Some(_) => revs.current().to_string(),
        None => revs.oldest_accepted(now).to_string(),
    };
    Json(json!({
        "zrax_rev": accepted,
        "zrax_latest": revs.current(),
        "zrax": zrax_label(),
        "max_file_bytes": c.limits.max_file_bytes,
        "min_file_bytes": c.limits.min_file_bytes,
        "chunk_bytes": c.limits.chunk_bytes,
        "pow_bits": state.pow.bits(),
        "paused": c.is_paused(),
        "policy": c.policy,
    }))
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let bulk = state.bulk.activity();
    Json(json!({
        "ok": true,
        "queued": state.queue.len(),
        "posted": state.ledger.len(),
        "spooled_bytes": state.uploads.reserved_bytes(),
        // For deploys: restart only when nothing is active and no donor has
        // talked to us for a while.
        "active": state.uploads.active(),
        "idle_secs": state.uploads.idle_secs(),
        "paused": state.config.is_paused(),
        // Bulk uploads survive restarts (the page resumes them), so they
        // don't hold deploys back and aren't part of `active`.
        "bulk_unfinished": bulk.unfinished,
        "bulk_active": bulk.active,
    }))
}

/// The corpus as classified now (the dashboard's index, without the files
/// the current zrax rejects), or the ledger's view until the index is built.
async fn corpus(state: &AppState, now: u64) -> crate::ledger::Snapshot {
    static CACHE: std::sync::Mutex<Option<(std::time::Instant, crate::ledger::Snapshot)>> = std::sync::Mutex::new(None);
    let since = now.saturating_sub(3600);
    let catalog = state.dashboard.catalog.clone();
    if !catalog.ready() {
        return state.ledger.snapshot(since);
    }
    if let Some((at, snap)) = CACHE.lock().unwrap().as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(2) {
            return snap.clone();
        }
    }
    match tokio::task::spawn_blocking(move || catalog.corpus_stats(since)).await {
        Ok(snap) => {
            *CACHE.lock().unwrap() = Some((std::time::Instant::now(), snap.clone()));
            snap
        }
        Err(_) => state.ledger.snapshot(since),
    }
}

/// Corpus statistics for the page: totals, files per ISA (every ISA the
/// raw-code model knows is listed, with zero when nobody donated one yet),
/// and files per format.
async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    let now = unix_now();
    let snap = corpus(&state, now).await;
    let raw = raw_isas();
    let is_raw = |key: &str| raw.iter().any(|r| r.key == key);
    let mut isas: Vec<serde_json::Value> = snap
        .isas
        .iter()
        .map(|(key, t)| {
            json!({
                "isa": key,
                "name": isa_display_name(key).unwrap_or(key.as_str()),
                "files": t.files,
                "bytes": t.bytes,
                "raw": is_raw(key),
            })
        })
        .collect();
    let seen: std::collections::HashSet<&str> = snap.isas.iter().map(|(k, _)| k.as_str()).collect();
    isas.extend(raw.iter().filter(|r| !seen.contains(r.key.as_str())).map(|r| {
        json!({ "isa": r.key, "name": r.name, "files": 0, "bytes": 0, "raw": true })
    }));
    let formats: Vec<_> =
        snap.formats.iter().map(|(f, t)| json!({ "format": f, "files": t.files, "bytes": t.bytes })).collect();
    Json(json!({
        "files": snap.total.files,
        "bytes": snap.total.bytes,
        "last_hour": snap.recent,
        "donors": snap.donors,
        "first_at": snap.first_at,
        "last_at": snap.last_at,
        "no_isa": snap.no_isa,
        "isas": isas,
        "formats": formats,
        "now": now,
    }))
}

async fn challenge(State(state): State<AppState>) -> impl IntoResponse {
    state.uploads.touch();
    let c = state.pow.issue();
    Json(json!({ "token": c.token, "bits": c.bits, "expires": c.expires }))
}

const KNOWN_MAX: usize = 1000;

#[derive(Deserialize)]
struct KnownRequest {
    sha256: Vec<String>,
}

/// Which of these hashes are already in the collection (or being donated
/// right now). Lets the page skip duplicates before any proof of work.
async fn known(State(state): State<AppState>, Json(req): Json<KnownRequest>) -> Result<impl IntoResponse, ApiError> {
    state.uploads.touch();
    if req.sha256.len() > KNOWN_MAX {
        return Err(ApiError::bad_request(format!("at most {KNOWN_MAX} hashes per request")));
    }
    let mut known = serde_json::Map::new();
    for raw in &req.sha256 {
        let sha = raw.trim().to_ascii_lowercase();
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request("sha256 values must be 64 hex digits"));
        }
        if let Some(at) = state.ledger.posted_at(&sha) {
            known.insert(sha, json!({ "posted_at": at, "date": crate::ledger::date(at) }));
        } else if state.uploads.in_flight(&sha) {
            known.insert(sha, json!({ "in_progress": true }));
        }
    }
    Ok(Json(json!({ "known": known })))
}

async fn init_upload(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<InitRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let key = ClientKey::from_ip(client_ip(&state.config, peer, &headers));
    let response = state.uploads.init(req, key)?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn put_chunk(
    State(state): State<AppState>,
    Path((id, index)): Path<(String, u64)>,
    body: Body,
) -> Result<impl IntoResponse, ApiError> {
    state.uploads.put_chunk(&id, index, body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn complete_upload(State(state): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    state.uploads.complete(&id)?;
    Ok((StatusCode::ACCEPTED, Json(state.uploads.status(&id)?)))
}

async fn upload_status(State(state): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.uploads.status(&id)?))
}

async fn cancel_upload(State(state): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    state.uploads.cancel(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_for_only_from_trusted_peers() {
        let config = Config::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        assert_eq!(client_ip(&config, local, &headers), "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&config, remote, &headers), remote.ip());
        assert_eq!(client_ip(&config, local, &HeaderMap::new()), local.ip());
    }
}
