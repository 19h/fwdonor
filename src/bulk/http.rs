//! Routes for bulk donations: the admin page and API (`/g/<key>`,
//! `/api/admin/<key>/…`) and the grant page and API (`/r/<token>`,
//! `/api/bulk/<token>/…`).

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;

use super::InitRequest;
use crate::error::ApiError;
use crate::http::{client_ip, AppState};

pub fn api_routes(chunk_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/api/admin/{key}/grants", get(list_grants).post(create_grant))
        .route("/api/admin/{key}/grants/{token}", delete(revoke_grant))
        .route("/api/bulk/{token}", get(grant_info))
        .route("/api/bulk/{token}/uploads", post(init_upload))
        .route("/api/bulk/{token}/uploads/{id}", get(upload_status).delete(discard_upload))
        .route("/api/bulk/{token}/uploads/{id}/{index}", put(put_chunk).layer(DefaultBodyLimit::max(chunk_limit)))
}

pub fn page_routes() -> Router<AppState> {
    Router::new().route("/g/{key}", get(admin_page)).route("/r/{token}", get(grant_page))
}

const NOT_FOUND_PAGE: &str = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>fwdonor</title>\
    <link rel=\"stylesheet\" href=\"/fwdonor.css\"></head><body><main class=\"main\"><h1>[ not found ]</h1>\
    <p>This link is not valid (any more). <a href=\"/\">fwdonor</a></p></main></body></html>";

/// Pages behind a secret URL: never cached or indexed.
pub(crate) async fn page(state: &AppState, dir: &str, ok: bool) -> Response {
    let headers = [
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (header::HeaderName::from_static("x-robots-tag"), HeaderValue::from_static("noindex, nofollow")),
    ];
    if !ok {
        return (StatusCode::NOT_FOUND, headers, Html(NOT_FOUND_PAGE.to_string())).into_response();
    }
    match tokio::fs::read_to_string(state.config.dist_dir.join(dir).join("index.html")).await {
        Ok(html) => (headers, Html(html)).into_response(),
        Err(e) => ApiError::internal(format!("reading the {dir} page: {e}")).into_response(),
    }
}

async fn admin_page(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    let ok = state.bulk.admin_ok(&key);
    page(&state, "g", ok).await
}

async fn grant_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let ok = state.bulk.grant_live(&token);
    page(&state, "r", ok).await
}

fn admin(state: &AppState, key: &str) -> Result<(), ApiError> {
    if state.bulk.admin_ok(key) {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "not found"))
    }
}

async fn list_grants(State(state): State<AppState>, Path(key): Path<String>) -> Result<impl IntoResponse, ApiError> {
    admin(&state, &key)?;
    Ok(Json(state.bulk.list_grants()))
}

#[derive(Deserialize)]
struct CreateGrant {
    name: String,
    ceiling_bytes: u64,
    #[serde(default)]
    note: String,
}

async fn create_grant(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(req): Json<CreateGrant>,
) -> Result<impl IntoResponse, ApiError> {
    admin(&state, &key)?;
    let grant = state.bulk.create_grant(&req.name, req.ceiling_bytes, &req.note)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "token": grant.token,
            "path": format!("/r/{}", grant.token),
            "name": grant.name,
            "ceiling": grant.ceiling_bytes,
        })),
    ))
}

async fn revoke_grant(
    State(state): State<AppState>,
    Path((key, token)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    admin(&state, &key)?;
    state.bulk.revoke(&token)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn grant_info(State(state): State<AppState>, Path(token): Path<String>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.bulk.grant_info(&token)?))
}

async fn init_upload(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(req): Json<InitRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let ip = client_ip(&state.config, peer, &headers);
    let view = state.bulk.init(&token, req, ip)?;
    let status = if view.resumed { StatusCode::OK } else { StatusCode::CREATED };
    Ok((status, Json(view)))
}

async fn upload_status(
    State(state): State<AppState>,
    Path((token, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.bulk.status(&token, &id)?))
}

async fn discard_upload(
    State(state): State<AppState>,
    Path((token, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    state.bulk.discard(&token, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_chunk(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((token, id, index)): Path<(String, String, u64)>,
    body: Body,
) -> Result<impl IntoResponse, ApiError> {
    let ip = client_ip(&state.config, peer, &headers);
    let sha = headers.get("x-chunk-sha256").and_then(|v| v.to_str().ok());
    state.bulk.put_chunk(&token, &id, index, sha, ip, body).await?;
    Ok(StatusCode::NO_CONTENT)
}
