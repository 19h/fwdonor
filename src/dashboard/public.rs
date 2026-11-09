//! The public dashboard (`/dashboard`, API under `/api/dashboard/…`): the
//! firmware view without a key and without anything operational. No bulk
//! uploads, no origin (uploaded or recovered from Telegram), no store status
//! or backfill, no uploads in progress, no server paths, no disk space. Those
//! dimensions can't be filtered, sorted or grouped by either.
//!
//! Downloads need a proof of work bound to the file: as much work as one
//! solution `pow.download_extra_bits` harder than an upload's, split into
//! PROOFS solutions of PROOF_BITS less each. That costs the same on average
//! but takes a steady time (one big proof is pure luck), and the page finds
//! them on all cores at once. A proof stays good for its file until the
//! token expires, so an interrupted download can be resumed with Range.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use super::catalog::{ExportKind, Query as CatalogQuery};
use super::http::{attachment, export_kind, indexing, serve_download, sha_param, stream_export};
use super::live::{query_key, Cached, Scope};
use crate::config::Config;
use crate::error::ApiError;
use crate::http::{client_ip, AppState};
use crate::limits::ClientKey;
use crate::pow::PowGate;

/// Dimensions the public dashboard leaves out.
const HIDDEN: [&str; 2] = ["origin", "status"];
/// Row fields it leaves out (`stored` says whether the file can be downloaded).
const HIDDEN_FIELDS: [&str; 3] = ["origin", "status", "reason"];
/// Summary fields it shows.
pub(super) const SUMMARY_FIELDS: [&str; 16] = [
    "ready", "progress", "version", "files", "bytes", "kinds", "donors", "named_donors", "isas", "formats", "last_hour",
    "last_day", "first_at", "last_at", "zrax", "wanted",
];
pub const CSV_COLUMNS: [&str; 21] = [
    "sha256", "name", "size", "donor", "kind", "isa", "isas", "family", "format", "variant", "bits", "endian", "confidence", "class",
    "basis", "slices", "stored", "received_at", "posted_at", "telegram", "zrax",
];
/// Solutions a download proof consists of, and the bits that saves on each.
pub const PROOFS: usize = 16;
const PROOF_BITS: u8 = 4;
/// Queries computed at once (they queue beyond that).
const QUERIES: usize = 4;

pub struct Public {
    pub download_pow: PowGate,
    queries: Arc<Semaphore>,
    /// NDJSON exports read every record from disk: one at a time.
    full_exports: Arc<Semaphore>,
}

impl Public {
    pub fn new(config: &Config) -> Self {
        Self {
            download_pow: PowGate::new(
                (config.pow.bits + config.pow.download_extra_bits).saturating_sub(PROOF_BITS).max(1),
                config.pow.ttl_secs,
            ),
            queries: Arc::new(Semaphore::new(QUERIES)),
            full_exports: Arc::new(Semaphore::new(1)),
        }
    }
}

/// A row as the public dashboard shows it.
pub fn row(mut row: Value) -> Value {
    let stored = matches!(row["status"].as_str(), Some("stored" | "queued"));
    if let Some(o) = row.as_object_mut() {
        for f in HIDDEN_FIELDS {
            o.remove(f);
        }
        o.insert("stored".into(), json!(stored));
    }
    row
}

/// A store record as the public dashboard shows it (no `source`, nothing
/// about reclassification or post edits).
pub fn record(mut record: Value) -> Value {
    if let Some(o) = record.as_object_mut() {
        for key in ["source", "checked", "unclassified"] {
            o.remove(key);
        }
        if let Some(t) = o.get_mut("telegram").and_then(Value::as_object_mut) {
            t.remove("shows");
            t.remove("edit_failed");
        }
    }
    record
}

/// Drop the hidden dimensions from filters, sorting, the tree and the matrix.
fn params(mut p: HashMap<String, String>) -> HashMap<String, String> {
    for d in HIDDEN {
        p.remove(d);
    }
    let visible = |list: &str| {
        list.split(',')
            .filter(|part| !HIDDEN.contains(&part.split(':').next().unwrap_or("").trim()))
            .collect::<Vec<_>>()
            .join(",")
    };
    for key in ["tree", "sort"] {
        if let Some(v) = p.get(key).map(|v| visible(v)) {
            p.insert(key.into(), v);
        }
    }
    if p.get("matrix").is_some_and(|m| m.split(',').any(|d| HIDDEN.contains(&d.trim()))) {
        p.remove("matrix");
    }
    p
}

pub fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(page))
        .route("/dashboard/", get(|| async { Redirect::permanent("/dashboard") }))
}

pub fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/api/dashboard/summary", get(summary))
        .route("/api/dashboard/live", get(live_stream))
        .route("/api/dashboard/query", get(query))
        .route("/api/dashboard/export", get(export))
        .route("/api/dashboard/challenge", get(challenge))
        .route("/api/dashboard/files/{sha}", get(detail))
        .route("/api/dashboard/files/{sha}/inspect", get(inspect))
        .route("/api/dashboard/files/{sha}/download", get(download))
}

/// The dashboard page itself (it sees from its URL that it is the public one).
async fn page(State(state): State<AppState>) -> Response {
    let html = match tokio::fs::read_to_string(state.config.dist_dir.join("d").join("index.html")).await {
        Ok(html) => html,
        Err(e) => return ApiError::internal(format!("reading the dashboard page: {e}")).into_response(),
    };
    // The page is shared with the private dashboard, which is never indexed.
    axum::response::Html(html.replace(r#"<meta name="robots" content="noindex, nofollow">"#, "")).into_response()
}

/// The summary for pages that poll (the same frames the live stream sends).
async fn summary(State(state): State<AppState>) -> Result<Response, ApiError> {
    state.dashboard.live.summary(Scope::Public).await
}

/// The summary as server-sent events (src/dashboard/live.rs).
async fn live_stream(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let client = ClientKey::from_ip(client_ip(&state.config, peer, &headers));
    state.dashboard.live.stream(Scope::Public, client)
}

/// Shared between viewers asking the same: computed once per catalog change
/// (or every few seconds while it keeps changing), served gzipped.
async fn query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(raw): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let d = &state.dashboard;
    if !d.catalog.ready() {
        return Err(indexing(d));
    }
    let p = params(raw);
    let q = CatalogQuery::parse(&p).map_err(ApiError::bad_request)?;
    let (queries, catalog) = (d.public.queries.clone(), d.catalog.clone());
    let cached = d
        .live
        .public_queries
        .get(query_key(&p), d.catalog.version(), async move {
            let _permit = queries.acquire_owned().await.map_err(ApiError::internal)?;
            tokio::task::spawn_blocking(move || {
                let mut v = catalog.query(&q);
                if let Some(rows) = v["rows"].as_array_mut() {
                    for r in rows.iter_mut() {
                        *r = row(r.take());
                    }
                }
                if let Some(facets) = v["facets"].as_object_mut() {
                    for dim in HIDDEN {
                        facets.remove(dim);
                    }
                }
                Cached::encode(&v)
            })
            .await
            .map_err(ApiError::internal)
        })
        .await?;
    Ok(cached.respond(&headers))
}

async fn export(
    State(state): State<AppState>,
    Query(raw): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let d = &state.dashboard;
    if !d.catalog.ready() {
        return Err(indexing(d));
    }
    let kind = export_kind(&raw)?;
    if matches!(kind, ExportKind::Rsync) {
        return Err(ApiError::bad_request("rsync lists are for the private dashboard"));
    }
    let permit = match kind {
        ExportKind::Ndjson => d.public.full_exports.clone().try_acquire_owned().map_err(|_| {
            ApiError::new(StatusCode::TOO_MANY_REQUESTS, "busy", "another full export is running; try again shortly")
                .retry_after(10)
        })?,
        // Cheap (from memory): a permit nobody else waits for.
        _ => Arc::new(Semaphore::new(1)).try_acquire_owned().expect("a fresh semaphore"),
    };
    let q = CatalogQuery::parse(&params(raw)).map_err(ApiError::bad_request)?;
    let body = stream_export(d, q, &kind, Some(permit));
    Ok(attachment(&kind, "fwdonor-firmware", body))
}

async fn detail(State(state): State<AppState>, Path(sha): Path<String>) -> Result<Json<Value>, ApiError> {
    let d = &state.dashboard;
    let sha = sha_param(&sha)?;
    let Some((r, same_name)) = d.catalog.detail(&sha) else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such image"));
    };
    let bytes = tokio::fs::read(d.firmware_dir.join(format!("{sha}.json"))).await.ok();
    let rec = bytes.as_deref().map_or(Value::Null, |b| record(serde_json::from_slice::<Value>(b).unwrap_or(Value::Null)));
    let kind = super::http::kind_detail(d.firmware_dir.clone(), &sha, bytes, &r).await;
    Ok(Json(json!({
        "row": row(r),
        "kind": kind,
        "record": rec,
        "same_name": same_name.into_iter().map(row).collect::<Vec<_>>(),
    })))
}

async fn inspect(State(state): State<AppState>, Path(sha): Path<String>) -> Result<Json<Value>, ApiError> {
    let d = &state.dashboard;
    let sha = sha_param(&sha)?;
    if d.catalog.stored_name(&sha).is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not_stored", "this image is not available (yet)"));
    }
    let v = d.inspector.inspect(&sha, d.firmware_dir.join(&sha)).await.map_err(ApiError::internal)?;
    Ok(Json((*v).clone()))
}

/// A download challenge. Unlike `/api/challenge` it isn't donation traffic
/// (it doesn't hold back deploys).
async fn challenge(State(state): State<AppState>) -> impl IntoResponse {
    let c = state.dashboard.public.download_pow.issue();
    Json(json!({ "token": c.token, "bits": c.bits, "proofs": PROOFS, "expires": c.expires }))
}

#[derive(Deserialize)]
struct Proof {
    token: Option<String>,
    /// PROOFS nonces, comma-separated, in increasing order.
    nonces: Option<String>,
}

async fn download(
    State(state): State<AppState>,
    Path(sha): Path<String>,
    Query(proof): Query<Proof>,
    req: Request,
) -> Response {
    let d = &state.dashboard;
    let sha = match sha_param(&sha) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let nonces: Option<Vec<u64>> =
        proof.nonces.as_deref().and_then(|n| n.split(',').map(|x| x.trim().parse().ok()).collect());
    let (Some(token), Some(nonces)) = (proof.token, nonces) else {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "pow",
            format!("downloads need a proof of work: GET /api/dashboard/challenge, then ?token=…&nonces=… ({PROOFS} solutions)"),
        )
        .into_response();
    };
    let digest: [u8; 32] = hex::decode(&sha).ok().and_then(|b| b.try_into().ok()).expect("checked hex");
    if let Err(e) = d.public.download_pow.check_all(&token, &digest, &nonces, PROOFS) {
        return ApiError::new(StatusCode::FORBIDDEN, "pow", e.to_string()).into_response();
    }
    match d.catalog.stored_name(&sha) {
        Some(name) => serve_download(req, d.firmware_dir.join(&sha), &name).await,
        None => ApiError::new(StatusCode::NOT_FOUND, "not_stored", "this image is not available (yet)").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_dimensions_are_dropped() {
        let p = params(HashMap::from([
            ("origin".to_string(), "ledger".to_string()),
            ("status".to_string(), "pending".to_string()),
            ("tree".to_string(), "family,status,isa".to_string()),
            ("sort".to_string(), "origin:desc,size".to_string()),
            ("matrix".to_string(), "isa,origin".to_string()),
            ("donor".to_string(), "kenan".to_string()),
        ]));
        assert!(!p.contains_key("origin") && !p.contains_key("status") && !p.contains_key("matrix"));
        assert_eq!(p["tree"], "family,isa");
        assert_eq!(p["sort"], "size");
        assert_eq!(p["donor"], "kenan");

        let r = row(json!({ "sha256": "ab", "origin": "telegram", "status": "queued", "reason": null }));
        assert_eq!(r, json!({ "sha256": "ab", "stored": true }));
        assert_eq!(row(json!({ "status": "pending" }))["stored"], false);
        assert_eq!(record(json!({ "sha256": "ab", "source": "telegram" })), json!({ "sha256": "ab" }));
    }
}
