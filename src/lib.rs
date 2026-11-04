use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub const MAX_HEADERS: usize = 8192;
pub const MAX_IN_FLIGHT: usize = 32;

// Deliberately does not implement Debug: the token must not reach diagnostics.
pub struct AppState {
    token: String,
    started: Instant,
    requests: AtomicU64,
    pub stopping: AtomicBool,
    permits: Arc<Semaphore>,
}

impl AppState {
    pub fn new(token: String) -> Arc<Self> {
        Arc::new(Self {
            token,
            started: Instant::now(),
            requests: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        })
    }
}

pub fn validate_token(value: &str) -> Result<String, &'static str> {
    let token = value.trim_end_matches(['\r', '\n']);
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("token must contain exactly 64 hexadecimal characters");
    }
    Ok(token.to_owned())
}

pub fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let all = headers.get_all(header::AUTHORIZATION);
    let mut values = all.iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Some(candidate) = value.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")) else {
        return false;
    };
    bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
}

fn json_error(status: StatusCode, error: &'static str) -> Response {
    let mut response = (status, Json(serde_json::json!({ "error": error }))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
    }
    response
}

fn finish(mut response: Response, route: &'static str) -> Response {
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    // Fixed route labels only. No URI, query, peer address, body, or header logging.
    eprintln!("{}", serde_json::json!({
        "event": "request", "route": route, "status": response.status().as_u16()
    }));
    response
}

async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let route = match request.uri().path() {
        "/healthz" => "health",
        "/api/v1/status" => "status",
        _ => "unknown",
    };
    let reject = |status, error| finish(json_error(status, error), route);
    if state.stopping.load(Ordering::Relaxed) {
        return reject(StatusCode::SERVICE_UNAVAILABLE, "stopping");
    }
    let Ok(_permit) = state.permits.clone().try_acquire_owned() else {
        return reject(StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    state.requests.fetch_add(1, Ordering::Relaxed);
    if request.method() != Method::GET {
        return reject(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    }
    let header_bytes: usize = request.headers().iter().map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4).sum();
    if header_bytes > MAX_HEADERS || request.uri().to_string().len() > 1024 {
        return reject(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "headers_too_large");
    }
    if request.headers().get_all(header::AUTHORIZATION).iter().count() > 1 {
        return reject(StatusCode::BAD_REQUEST, "ambiguous_authorization");
    }
    let lengths = request.headers().get_all(header::CONTENT_LENGTH);
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || lengths.iter().count() > 1
        || lengths.iter().any(|v| v.as_bytes() != b"0")
    {
        return reject(StatusCode::BAD_REQUEST, "body_not_allowed");
    }
    let (parts, body) = request.into_parts();
    match timeout(Duration::from_secs(1), to_bytes(body, 0)).await {
        Ok(Ok(bytes)) if bytes.is_empty() => {}
        _ => return reject(StatusCode::BAD_REQUEST, "body_not_allowed"),
    }
    let request = Request::from_parts(parts, Body::empty());
    let response = match timeout(Duration::from_secs(2), next.run(request)).await {
        Ok(response) => response,
        Err(_) => json_error(StatusCode::GATEWAY_TIMEOUT, "request_timeout"),
    };
    finish(response, route)
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    if state.stopping.load(Ordering::Relaxed) {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "stopping");
    }
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

#[derive(Serialize)]
struct Status {
    service: &'static str,
    scope: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    requests: u64,
    max_in_flight: usize,
}

async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &state.token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    Json(Status {
        service: "gravenlace-management",
        scope: "management-only",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started.elapsed().as_secs(),
        requests: state.requests.load(Ordering::Relaxed),
        max_in_flight: MAX_IN_FLIGHT,
    }).into_response()
}

async fn not_found() -> Response {
    json_error(StatusCode::NOT_FOUND, "not_found")
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/status", get(status))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn requires_the_exact_bearer_credential() {
        let token = "ab".repeat(32);
        assert!(authorized(&headers(&format!("Bearer {token}")), &token));
        for wrong in ["Bearer wrong".to_owned(), format!("bearer {token}"), format!("Bearer {}", "cd".repeat(32))] {
            assert!(!authorized(&headers(&wrong), &token));
        }
        assert!(!authorized(&HeaderMap::new(), &token));
    }

    #[test]
    fn rejects_duplicate_authorization() {
        let token = "ab".repeat(32);
        let mut headers = headers(&format!("Bearer {token}"));
        headers.append(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        assert!(!authorized(&headers, &token));
    }

    #[test]
    fn validates_private_token_configuration() {
        let token = "ab".repeat(32);
        assert_eq!(validate_token(&format!("{token}\n")).unwrap(), token);
        for bad in ["replace-me".to_owned(), "g".repeat(64), format!("{token}\nextra")] {
            assert!(validate_token(&bad).is_err());
        }
    }
}
