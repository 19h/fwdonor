//! Routes of the dashboard: the pages (`/d/<key>`, `/d/<key>/bulk`) and the
//! API (`/api/dash/<key>/…`). A wrong key gets 404, like a missing page.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::services::ServeFile;

use super::catalog::{csv_line, csv_row, ExportKind, Query as CatalogQuery, CSV_HEADER};
use super::Dashboard;
use crate::analyze::zrax_label;
use crate::error::ApiError;
use crate::http::AppState;
use crate::uploads::unix_now;

pub fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/api/dash/{key}/summary", get(summary))
        .route("/api/dash/{key}/query", get(query))
        .route("/api/dash/{key}/export", get(export))
        .route("/api/dash/{key}/files/{sha}", get(detail))
        .route("/api/dash/{key}/files/{sha}/inspect", get(inspect))
        .route("/api/dash/{key}/files/{sha}/download", get(download))
        .route("/api/dash/{key}/bulk", get(bulk))
        .route("/api/dash/{key}/bulk/export", get(bulk_export))
        .route("/api/dash/{key}/bulk/{sha}/download", get(bulk_download))
}

pub fn page_routes() -> Router<AppState> {
    Router::new().route("/d/{key}", get(firmware_page)).route("/d/{key}/bulk", get(bulk_page))
}

async fn firmware_page(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    let ok = state.dashboard.key_ok(&key);
    crate::bulk::http::page(&state, "d", ok).await
}

async fn bulk_page(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    let ok = state.dashboard.key_ok(&key);
    crate::bulk::http::page(&state, "d/bulk", ok).await
}

fn dash<'a>(state: &'a AppState, key: &str) -> Result<&'a Dashboard, ApiError> {
    if state.dashboard.key_ok(key) {
        Ok(&state.dashboard)
    } else {
        Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "not found"))
    }
}

/// What kind of binary an image is, and why (reads the stored file's
/// headers). `record` is the store record's bytes, if there is one.
pub(super) async fn kind_detail(firmware_dir: PathBuf, sha: &str, record: Option<Vec<u8>>, row: &Value) -> Value {
    let (sha, name, format) = (sha.to_string(), row["name"].as_str().unwrap_or("").to_string(), row["format"].as_str().unwrap_or("").to_string());
    let verdict = tokio::task::spawn_blocking(move || match record.and_then(|b| serde_json::from_slice::<crate::firmwares::Record>(&b).ok()) {
        Some(r) => super::catalog::record_verdict(&r, &firmware_dir.join(&sha)),
        None => super::kind::classify(None, &format, "", &name),
    })
    .await;
    match verdict {
        Ok(v) => json!({ "key": v.kind.key(), "label": v.kind.label(), "why": v.why }),
        Err(_) => Value::Null,
    }
}

pub(super) fn sha_param(sha: &str) -> Result<String, ApiError> {
    let sha = sha.trim().to_ascii_lowercase();
    if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(sha)
    } else {
        Err(ApiError::bad_request("expected a SHA-256 in hex"))
    }
}

pub(super) fn indexing(d: &Dashboard) -> ApiError {
    let (done, total) = d.catalog.progress();
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "indexing", format!("indexing the store: {done} of {total}"))
        .retry_after(2)
}

async fn summary(State(state): State<AppState>, Path(key): Path<String>) -> Result<Json<Value>, ApiError> {
    let d = dash(&state, &key)?;
    let now = unix_now();
    let catalog = d.catalog.clone();
    let mut v = tokio::task::spawn_blocking(move || catalog.summary(now, &zrax_label())).await.map_err(ApiError::internal)?;
    v["backfill"] = serde_json::to_value(&*d.backfill.lock().unwrap()).unwrap_or(Value::Null);
    let mut reclassify = serde_json::to_value(&*d.reclassify.lock().unwrap()).unwrap_or(Value::Null);
    reclassify["edits"] = serde_json::to_value(d.edits.counts()).unwrap_or(Value::Null);
    v["reclassify"] = reclassify;
    v["arriving"] = Value::Array(state.uploads.arriving());
    v["queue"] = json!({
        "queued": state.queue.len(),
        "active": state.uploads.active(),
        "spooled_bytes": state.uploads.reserved_bytes(),
        "idle_secs": state.uploads.idle_secs(),
        "paused": state.config.is_paused(),
    });
    let (free, total) = crate::bulk::disk_space(&d.firmware_dir).unwrap_or((0, 0));
    v["disk"] = json!({ "free": free, "total": total });
    v["ledger"] = json!(state.ledger.len());
    v["firmware_dir"] = json!(d.firmware_dir);
    v["bulk"] = state.bulk.brief();
    v["now"] = json!(now);
    Ok(Json(v))
}

async fn query(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let d = dash(&state, &key)?;
    if !d.catalog.ready() {
        return Err(indexing(d));
    }
    let q = CatalogQuery::parse(&params).map_err(ApiError::bad_request)?;
    let catalog = d.catalog.clone();
    let v = tokio::task::spawn_blocking(move || catalog.query(&q)).await.map_err(ApiError::internal)?;
    Ok(Json(v))
}

async fn detail(
    State(state): State<AppState>,
    Path((key, sha)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let d = dash(&state, &key)?;
    let sha = sha_param(&sha)?;
    let Some((row, same_name)) = d.catalog.detail(&sha) else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such image"));
    };
    let path = d.firmware_dir.join(&sha);
    let bytes = tokio::fs::read(d.firmware_dir.join(format!("{sha}.json"))).await.ok();
    let record = bytes.as_deref().map_or(Value::Null, |b| serde_json::from_slice::<Value>(b).unwrap_or(Value::Null));
    let stored = tokio::fs::try_exists(&path).await.unwrap_or(false);
    let kind = kind_detail(d.firmware_dir.clone(), &sha, bytes, &row).await;
    Ok(Json(json!({
        "row": row,
        "kind": kind,
        "record": record,
        "same_name": same_name,
        "path": stored.then(|| path.to_string_lossy().into_owned()),
    })))
}

async fn inspect(
    State(state): State<AppState>,
    Path((key, sha)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let d = dash(&state, &key)?;
    let sha = sha_param(&sha)?;
    if d.catalog.stored_name(&sha).is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not_stored", "this image is not in the store (yet)"));
    }
    let v = d.inspector.inspect(&sha, d.firmware_dir.join(&sha)).await.map_err(ApiError::internal)?;
    Ok(Json((*v).clone()))
}

/// `attachment` with the original name: an ASCII fallback and the UTF-8 name.
pub(super) fn disposition(name: &str) -> HeaderValue {
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' })
        .collect();
    let encoded: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    HeaderValue::from_str(&format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

/// A stored file with Range support (`curl -C -` resumes).
pub(super) async fn serve_download(req: Request, path: PathBuf, name: &str) -> Response {
    let mut svc = ServeFile::new(&path).with_buf_chunk_size(256 * 1024);
    match svc.try_call(req).await {
        Ok(res) => {
            let mut res = res.map(Body::new);
            if res.status().is_success() {
                res.headers_mut().insert(header::CONTENT_DISPOSITION, disposition(name));
                res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            }
            res
        }
        Err(e) => ApiError::internal(format!("serving {}: {e}", path.display())).into_response(),
    }
}

async fn download(State(state): State<AppState>, Path((key, sha)): Path<(String, String)>, req: Request) -> Response {
    let d = match dash(&state, &key) {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    let sha = match sha_param(&sha) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match d.catalog.stored_name(&sha) {
        Some(name) => serve_download(req, d.firmware_dir.join(&sha), &name).await,
        None => ApiError::new(StatusCode::NOT_FOUND, "not_stored", "this image is not in the store (yet)").into_response(),
    }
}

async fn bulk_download(State(state): State<AppState>, Path((key, sha)): Path<(String, String)>, req: Request) -> Response {
    if let Err(e) = dash(&state, &key) {
        return e.into_response();
    }
    let sha = match sha_param(&sha) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match state.bulk.stored_file(&sha) {
        Some((path, name)) => serve_download(req, path, &name).await,
        None => ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such bulk file").into_response(),
    }
}

pub(super) fn export_kind(params: &HashMap<String, String>) -> Result<ExportKind, ApiError> {
    Ok(match params.get("as").map(String::as_str).unwrap_or("csv") {
        "csv" => ExportKind::Csv,
        "ndjson" => ExportKind::Ndjson,
        "sha256sum" => ExportKind::Sha256sum,
        "rsync" => ExportKind::Rsync,
        other => return Err(ApiError::bad_request(format!("cannot export as {other}"))),
    })
}

pub(super) fn attachment(kind: &ExportKind, stem: &str, body: Body) -> Response {
    let (mime, ext) = match kind {
        ExportKind::Csv => ("text/csv; charset=utf-8", "csv"),
        ExportKind::Ndjson => ("application/x-ndjson", "ndjson"),
        ExportKind::Sha256sum => ("text/plain; charset=utf-8", "sha256"),
        ExportKind::Rsync => ("text/plain; charset=utf-8", "files.txt"),
    };
    let name = format!("{stem}-{}.{ext}", crate::ledger::date(unix_now()));
    let mut res = Response::new(body);
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    res.headers_mut().insert(header::CONTENT_DISPOSITION, disposition(&name));
    res
}

/// Every image the filters match, in their order, streamed.
async fn export(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let d = dash(&state, &key)?;
    if !d.catalog.ready() {
        return Err(indexing(d));
    }
    let kind = export_kind(&params)?;
    let q = CatalogQuery::parse(&params).map_err(ApiError::bad_request)?;
    let body = stream_export(d, q, &kind, None);
    Ok(attachment(&kind, "fwdonor-firmware", body))
}

/// The export as a streamed body. `public`: rows and records as the public
/// dashboard shows them (`super::public`), and the permit held until done.
pub(super) fn stream_export(
    d: &Dashboard,
    q: CatalogQuery,
    kind: &ExportKind,
    public: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Body {
    let (catalog, dir) = (d.catalog.clone(), d.firmware_dir.clone());
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let ndjson = matches!(kind, ExportKind::Ndjson);
    let is_public = public.is_some();
    let csv = matches!(kind, ExportKind::Csv);
    let line_of: fn(&str, bool, &Value) -> String = match kind {
        ExportKind::Csv if is_public => |_, _, row| csv_row(row, &super::public::CSV_COLUMNS),
        ExportKind::Csv => |_, _, row| csv_line(row),
        ExportKind::Ndjson => |_, _, row| format!("{row}\n"),
        ExportKind::Sha256sum => |sha, stored, _| if stored { format!("{sha}  {sha}\n") } else { String::new() },
        ExportKind::Rsync => |sha, stored, _| if stored { format!("{sha}\n{sha}.json\n") } else { String::new() },
    };
    tokio::task::spawn_blocking(move || {
        let _permit = public;
        let ids = catalog.matching(&q);
        if csv {
            let header = if is_public { format!("{}\n", super::public::CSV_COLUMNS.join(",")) } else { CSV_HEADER.to_string() };
            if tx.blocking_send(Bytes::from(header)).is_err() {
                return;
            }
        }
        for batch in ids.chunks(1000) {
            let mut out = String::new();
            for (sha, stored, mut row) in catalog.export_rows(batch) {
                if ndjson && stored {
                    if let Ok(bytes) = std::fs::read(dir.join(format!("{sha}.json"))) {
                        let record = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        row["record"] = if is_public { super::public::record(record) } else { record };
                    }
                }
                if is_public {
                    row = super::public::row(row);
                }
                out.push_str(&line_of(&sha, stored, &row));
            }
            if tx.blocking_send(Bytes::from(out)).is_err() {
                return; // the client went away
            }
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|b| (Ok::<_, Infallible>(b), rx)) });
    Body::from_stream(stream)
}

/// The bulk view, with each file marked when the firmware index has it too.
async fn bulk(State(state): State<AppState>, Path(key): Path<String>) -> Result<Json<Value>, ApiError> {
    let d = dash(&state, &key)?;
    let mut v = state.bulk.dashboard_view();
    if let Some(files) = v["files"].as_array_mut() {
        for f in files {
            let sha = f["sha256"].as_str().unwrap_or("").to_string();
            f["in_firmware"] = json!(d.catalog.contains(&sha));
        }
    }
    v["now"] = json!(unix_now());
    Ok(Json(v))
}

async fn bulk_export(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    dash(&state, &key)?;
    let kind = export_kind(&params)?;
    let grant = params.get("grant").filter(|g| !g.is_empty());
    let view = state.bulk.dashboard_view();
    let files = view["files"].as_array().cloned().unwrap_or_default();
    let mut out = String::new();
    if matches!(kind, ExportKind::Csv) {
        out.push_str("sha256,grant,name,path,size,started_at,completed_at,last_modified\n");
    }
    let cell = |v: &Value| -> String {
        let s = match v {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    };
    for f in files.iter().filter(|f| grant.is_none_or(|g| f["grant"] == **g)) {
        let sha = f["sha256"].as_str().unwrap_or("");
        match kind {
            ExportKind::Csv => {
                let cols = ["sha256", "grant_name", "name", "path", "size", "started_at", "completed_at", "last_modified"];
                out.push_str(&cols.iter().map(|c| cell(&f[*c])).collect::<Vec<_>>().join(","));
                out.push('\n');
            }
            ExportKind::Ndjson => {
                out.push_str(&f.to_string());
                out.push('\n');
            }
            ExportKind::Sha256sum => out.push_str(&format!("{sha}  {sha}\n")),
            ExportKind::Rsync => out.push_str(&format!("{sha}\n{sha}.json\n")),
        }
    }
    Ok(attachment(&kind, "fwdonor-bulk", Body::from(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_disposition() {
        let v = disposition("router 🛜 v2.bin");
        assert_eq!(v.to_str().unwrap(), "attachment; filename=\"router _ v2.bin\"; filename*=UTF-8''router%20%F0%9F%9B%9C%20v2.bin");
        assert!(disposition("a\"b\\c").to_str().unwrap().starts_with("attachment; filename=\"a_b_c\""));
    }
}
