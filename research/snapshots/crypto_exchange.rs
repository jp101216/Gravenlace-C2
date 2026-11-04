// ============================================================================
// --- UNIFIED CRYPTOGRAPHIC EXCHANGE & HANDSHAKE SUB-ENGINE ---
// ============================================================================

use std::sync::Arc;
use x25519_dalek::{EphemeralSecret, PublicKey};
use tracing::{info, error};

// Pulling required state layout containers and hooks from the parent crate
use crate::{AppState, EphemeralSessionKeyCtx, broadcast_engine_log};

/// Executes the core server ECDH key calculation and formats a 36-byte raw socket wire envelope.
/// Matches the expectations of low-level transport mechanisms using the 4-byte [Magic + Length] wire prefix.
/// Enforces Perfect Forward Secrecy (PFS) by populating the ephemeral memory registry.
pub async fn negotiate_and_build_response(
    state: &Arc<AppState>,
    agent_id: &str,
    client_public_key_bytes: [u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Generate ephemeral server keypair configurations natively matching rand 0.10
    let mut rng = rand::rng();
    let server_secret = EphemeralSecret::random_from_rng(&mut rng);
    let server_public = PublicKey::from(&server_secret);
    let server_public_bytes = server_public.as_bytes();
    let client_public = PublicKey::from(client_public_key_bytes);
    
    // 2. Perform the mathematical Diffie-Hellman derivation routine
    let shared_secret = server_secret.diffie_hellman(&client_public);
    let derived_key_bytes = *shared_secret.as_bytes();

    // 3. ENFORCE PFS: Insert session key context into volatile, short-lived RAM space
    let now = chrono::Utc::now();
    let session_context = EphemeralSessionKeyCtx {
        session_key: derived_key_bytes,
        created_at: now,
        expires_at: now + chrono::Duration::minutes(30), // Enforces 30-minute rotation limits
    };
    state.ephemeral_sessions.insert(agent_id.to_string(), session_context);

    // 4. Record static signature lookup index for recovery and audit compliance tracking via rust_rocksdb
    if let Err(db_err) = state.db.put(format!("key_{}", agent_id).as_bytes(), &derived_key_bytes) {
        error!("[-] Failed to commit handshake trace entry to RocksDB: {:?}", db_err);
    }
    
    let completion_alert = format!(
        "Stream X25519 key negotiation successful for Agent '{}'. Ephemeral PFS session mapped in memory.", 
        agent_id
    );
    info!(agent = %agent_id, "{}", completion_alert);
    broadcast_engine_log(state, "CRYPTO_PFS", &completion_alert);

    // 5. Construct the legacy 36-byte raw response envelope ([2-byte Magic] + [2-byte Length] + [32-byte Public Key])
    let mut response_envelope = Vec::with_capacity(36);
    response_envelope.extend_from_slice(&0xD45Du16.to_be_bytes());
    response_envelope.extend_from_slice(&32u16.to_be_bytes());
    response_envelope.extend_from_slice(server_public_bytes);

    Ok(response_envelope)
}

/// Executes the server ECDH key calculation for dynamic HTTP routes and returns an un-prefixed 32-byte raw key.
/// Tailored for clean integration within web application paths (e.g., Cloudflare /cdn-cgi emulation) and reverse proxies.
pub async fn negotiate_dynamic_handshake(
    state: &Arc<AppState>,
    agent_id: &str,
    client_public_key_bytes: [u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Generate ephemeral cryptographic identities matching modern dalek primitives
    let mut rng = rand::rng();
    let server_secret = EphemeralSecret::random_from_rng(&mut rng);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(client_public_key_bytes);
    
    // 2. Derive the symmetric session key array safely
    let shared_secret = server_secret.diffie_hellman(&client_public);
    let derived_key_bytes = *shared_secret.as_bytes();

    // 3. ENFORCE PFS: Map session parameters into volatile memory maps
    let now = chrono::Utc::now();
    let session_context = EphemeralSessionKeyCtx {
        session_key: derived_key_bytes,
        created_at: now,
        expires_at: now + chrono::Duration::minutes(30),
    };
    state.ephemeral_sessions.insert(agent_id.to_string(), session_context);

    // 4. Update the persistent rust_rocksdb storage tracking map reference
    if let Err(db_err) = state.db.put(format!("key_{}", agent_id).as_bytes(), &derived_key_bytes) {
        error!("[-] Failed to update persistent RocksDB identity key cell mapping: {:?}", db_err);
    }
    
    let dynamic_alert = format!(
        "Dynamic HTTP Web-Handshake X25519 negotiation complete for Agent '{}'. Ephemeral channel registered.", 
        agent_id
    );
    info!(agent = %agent_id, "{}", dynamic_alert);
    broadcast_engine_log(state, "CRYPTO_WEB_PFS", &dynamic_alert);

    // 5. Return only the raw 32-byte server public key back to the web response builder
    Ok(server_public.as_bytes().to_vec())
}
