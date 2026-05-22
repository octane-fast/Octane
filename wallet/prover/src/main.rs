mod pvac;

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

use crate::pvac::PvacContext;

const PORT: u16 = 19876;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Deserialize)]
struct ProveRequest {
    #[serde(rename = "secretKeyB64")]
    secret_key_b64: String,
    #[serde(rename = "currentCipherB64", default)]
    current_cipher_b64: String,
    #[serde(rename = "decAmountRaw", default)]
    dec_amount_raw: String,
    #[serde(rename = "amountRaw", default)]
    amount_raw: String,
    #[serde(rename = "seedB64")]
    seed_b64: String,
    #[serde(rename = "blindingB64")]
    blinding_b64: String,
    #[serde(rename = "jobId")]
    job_id: String,
    #[serde(default)]
    operation: String, // "shield" or "unshield" (default)
}

#[derive(Serialize)]
struct ProveResult {
    #[serde(rename = "type")]
    msg_type: &'static str,
    #[serde(rename = "jobId")]
    job_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<ProveData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ProveData {
    cipher: String,
    amount_commitment: String,
    zero_proof: String,
    blinding: String,
    range_proof_balance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    range_proof_delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    send_zero_proof: Option<String>,
}

/// Shared state: busy flag to reject concurrent jobs
struct AppState {
    busy: Mutex<bool>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "octane_prover=info".into()),
        )
        .init();

    let state = Arc::new(AppState {
        busy: Mutex::new(false),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/prove", get(ws_handler))
        .route("/decrypt", post(decrypt_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{PORT}"))
        .await
        .expect("Failed to bind port");

    info!("Octane Prover listening on http://127.0.0.1:{PORT}");
    info!("Waiting for wallet connections...");

    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        version: "0.1.0",
    })
}

#[derive(Deserialize)]
struct DecryptRequest {
    secret_key_b64: String,
    cipher_b64: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    value: u64,
}

async fn decrypt_handler(Json(req): Json<DecryptRequest>) -> Json<serde_json::Value> {
    let secret_key = match B64.decode(&req.secret_key_b64) {
        Ok(k) if k.len() >= 32 => k,
        _ => return Json(serde_json::json!({"error": "invalid secret_key_b64"})),
    };
    let cipher = match B64.decode(&req.cipher_b64) {
        Ok(c) if !c.is_empty() => c,
        _ => return Json(serde_json::json!({"error": "invalid cipher_b64"})),
    };

    let key32: [u8; 32] = secret_key[..32].try_into().unwrap();
    let result = tokio::task::spawn_blocking(move || {
        let ctx = PvacContext::new(&key32);
        match ctx {
            Some(c) => Ok(c.decrypt(&cipher)),
            None => Err("PVAC init failed"),
        }
    })
    .await;

    match result {
        Ok(Ok(val)) => Json(serde_json::json!({"value": val})),
        Ok(Err(e)) => Json(serde_json::json!({"error": e})),
        Err(e) => Json(serde_json::json!({"error": format!("task error: {e}")})),
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    // Wait for the prove request message
    let msg = match socket.recv().await {
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(Message::Binary(data))) => match String::from_utf8(data.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                let _ = send_error(&mut socket, "", "Invalid binary message").await;
                return;
            }
        },
        _ => return,
    };

    let req: ProveRequest = match serde_json::from_str(&msg) {
        Ok(r) => r,
        Err(e) => {
            let _ = send_error(&mut socket, "", &format!("Invalid request: {e}")).await;
            return;
        }
    };

    // Check if busy
    {
        let mut busy = state.busy.lock().await;
        if *busy {
            let _ = send_error(&mut socket, &req.job_id, "Prover is busy with another job").await;
            return;
        }
        *busy = true;
    }

    info!("Starting prove job: {}", req.job_id);

    // Run the prove in a blocking thread (it's CPU-heavy)
    let job_id = req.job_id.clone();
    let result = run_prove(req, &mut socket).await;

    match result {
        Ok(()) => info!("Job {} completed successfully", job_id),
        Err(e) => {
            error!("Job {} failed: {}", job_id, e);
            let _ = send_error(&mut socket, &job_id, &e).await;
        }
    }

    // Release busy lock
    *state.busy.lock().await = false;
}

async fn send_status(socket: &mut WebSocket, job_id: &str, step: &str) -> Result<(), String> {
    let msg = ProveResult {
        msg_type: "status",
        job_id: job_id.to_string(),
        data: None,
        step: Some(step.to_string()),
        error: None,
    };
    socket
        .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
        .await
        .map_err(|e| e.to_string())
}

async fn send_error(socket: &mut WebSocket, job_id: &str, error: &str) -> Result<(), String> {
    let msg = ProveResult {
        msg_type: "error",
        job_id: job_id.to_string(),
        data: None,
        step: None,
        error: Some(error.to_string()),
    };
    socket
        .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
        .await
        .map_err(|e| e.to_string())
}

async fn run_prove(req: ProveRequest, socket: &mut WebSocket) -> Result<(), String> {
    if req.operation == "shield" {
        run_prove_shield(req, socket).await
    } else if req.operation == "stealth" {
        run_prove_stealth(req, socket).await
    } else if req.operation == "claim" {
        run_prove_claim(req, socket).await
    } else {
        run_prove_unshield(req, socket).await
    }
}

async fn run_prove_shield(req: ProveRequest, socket: &mut WebSocket) -> Result<(), String> {
    let job_id = req.job_id.clone();

    // Decode inputs
    let secret_key = decode_b64_32(&req.secret_key_b64, "secretKey")?;
    let amount: u64 = req.amount_raw.parse().map_err(|e| format!("Bad amountRaw: {e}"))?;
    let seed = decode_b64_32(&req.seed_b64, "seed")?;
    let blinding = decode_b64_32(&req.blinding_b64, "blinding")?;

    send_status(socket, &job_id, "Initializing PVAC...").await?;

    let ctx = tokio::task::spawn_blocking(move || PvacContext::new(&secret_key))
        .await
        .map_err(|e| format!("Task join error: {e}"))?
        .ok_or("PVAC initialization failed")?;

    let ctx = Arc::new(ctx);

    // Encrypt amount
    send_status(socket, &job_id, "Encrypting amount...").await?;
    let cipher_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.encrypt(amount, &seed))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let cipher_str = format!("hfhe_v1|{}", B64.encode(&cipher_bytes));

    // Pedersen commit
    send_status(socket, &job_id, "Computing commitment...").await?;
    let commit_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.pedersen_commit(amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let commit_b64 = B64.encode(commit_bytes);

    // Zero proof
    send_status(socket, &job_id, "Generating zero proof...").await?;
    let zp_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.make_zero_proof_bound(&cb, amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Zero proof generation failed")?
    };
    let zp_str = format!("zkzp_v2|{}", B64.encode(&zp_bytes));

    // Send result (no range_proof needed for shield)
    let result = ProveResult {
        msg_type: "result",
        job_id,
        data: Some(ProveData {
            cipher: cipher_str,
            amount_commitment: commit_b64,
            zero_proof: zp_str,
            blinding: B64.encode(blinding),
            range_proof_balance: String::new(),
            range_proof_delta: None,
            commitment: None,
            send_zero_proof: None,
        }),
        step: None,
        error: None,
    };

    socket
        .send(Message::Text(serde_json::to_string(&result).unwrap().into()))
        .await
        .map_err(|e| format!("Send error: {e}"))?;

    Ok(())
}

async fn run_prove_stealth(req: ProveRequest, socket: &mut WebSocket) -> Result<(), String> {
    let job_id = req.job_id.clone();

    // Decode inputs
    let secret_key = decode_b64_32(&req.secret_key_b64, "secretKey")?;
    let current_cipher = B64.decode(&req.current_cipher_b64).map_err(|e| format!("Bad currentCipherB64: {e}"))?;
    let amount: u64 = req.amount_raw.parse().map_err(|e| format!("Bad amountRaw: {e}"))?;
    let seed = decode_b64_32(&req.seed_b64, "seed")?;
    let blinding = decode_b64_32(&req.blinding_b64, "blinding")?;

    send_status(socket, &job_id, "Initializing PVAC...").await?;

    let ctx = tokio::task::spawn_blocking(move || PvacContext::new(&secret_key))
        .await
        .map_err(|e| format!("Task join error: {e}"))?
        .ok_or("PVAC initialization failed")?;

    let ctx = Arc::new(ctx);

    // Verify balance
    send_status(socket, &job_id, "Verifying balance...").await?;
    let current_balance = {
        let ctx = ctx.clone();
        let cipher = current_cipher.clone();
        tokio::task::spawn_blocking(move || ctx.decrypt(&cipher))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };

    if current_balance < amount {
        return Err(format!(
            "Insufficient shielded balance: have {current_balance}, need {amount}"
        ));
    }

    // Encrypt delta
    send_status(socket, &job_id, "Encrypting amount...").await?;
    let cipher_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.encrypt(amount, &seed))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let cipher_str = format!("hfhe_v1|{}", B64.encode(&cipher_bytes));

    // Pedersen commit + zero proof
    send_status(socket, &job_id, "Generating commitment & zero proof...").await?;
    let pedersen_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.pedersen_commit(amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let pedersen_b64 = B64.encode(&pedersen_bytes);

    // Ciphertext commitment (commit_ct)
    let ct_commit_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.commit_ct(&cb))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("commit_ct failed")?
    };
    let ct_commit_b64 = B64.encode(&ct_commit_bytes);

    let zp_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.make_zero_proof_bound(&cb, amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Zero proof generation failed")?
    };
    let zp_str = format!("zkzp_v2|{}", B64.encode(&zp_bytes));

    // ct_sub: new balance = current - delta
    send_status(socket, &job_id, "Computing new balance...").await?;
    let new_bal_cipher = {
        let ctx = ctx.clone();
        let cc = current_cipher.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.ct_sub(&cc, &cb))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("ct_sub failed")?
    };
    let new_bal_value = current_balance - amount;

    // Range proof for delta
    send_status(socket, &job_id, "Range proof (delta)...").await?;
    let rp_delta_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.make_range_proof(&cb, amount))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Range proof (delta) failed")?
    };
    let rp_delta_str = format!("rp_v1|{}", B64.encode(&rp_delta_bytes));

    // Range proof for remaining balance
    send_status(socket, &job_id, "Range proof (balance)...").await?;
    let rp_bal_bytes = {
        let ctx = ctx.clone();
        let nbc = new_bal_cipher;
        tokio::task::spawn_blocking(move || ctx.make_range_proof(&nbc, new_bal_value))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Range proof (balance) failed")?
    };
    let rp_bal_str = format!("rp_v1|{}", B64.encode(&rp_bal_bytes));

    // Send result
    let result = ProveResult {
        msg_type: "result",
        job_id,
        data: Some(ProveData {
            cipher: cipher_str,
            amount_commitment: pedersen_b64,
            zero_proof: zp_str.clone(),
            blinding: B64.encode(blinding),
            range_proof_balance: rp_bal_str,
            range_proof_delta: Some(rp_delta_str),
            commitment: Some(ct_commit_b64),
            send_zero_proof: Some(zp_str),
        }),
        step: None,
        error: None,
    };

    socket
        .send(Message::Text(serde_json::to_string(&result).unwrap().into()))
        .await
        .map_err(|e| format!("Send error: {e}"))?;

    Ok(())
}

async fn run_prove_claim(req: ProveRequest, socket: &mut WebSocket) -> Result<(), String> {
    let job_id = req.job_id.clone();

    // Decode inputs — claim reuses amountRaw, seedB64, blindingB64
    let secret_key = decode_b64_32(&req.secret_key_b64, "secretKey")?;
    let amount: u64 = req.amount_raw.parse().map_err(|e| format!("Bad amountRaw: {e}"))?;
    let seed = decode_b64_32(&req.seed_b64, "seed")?;
    let blinding = decode_b64_32(&req.blinding_b64, "blinding")?;

    send_status(socket, &job_id, "Initializing PVAC...").await?;

    let ctx = tokio::task::spawn_blocking(move || PvacContext::new(&secret_key))
        .await
        .map_err(|e| format!("Task join error: {e}"))?
        .ok_or("PVAC initialization failed")?;

    let ctx = Arc::new(ctx);

    // Encrypt claim amount
    send_status(socket, &job_id, "Encrypting claim amount...").await?;
    let cipher_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.encrypt(amount, &seed))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let cipher_str = format!("hfhe_v1|{}", B64.encode(&cipher_bytes));

    // Ciphertext commitment
    send_status(socket, &job_id, "Computing commitment...").await?;
    let ct_commit_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.commit_ct(&cb))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("commit_ct failed")?
    };
    let ct_commit_b64 = B64.encode(&ct_commit_bytes);

    // Zero proof bound
    send_status(socket, &job_id, "Generating zero proof...").await?;
    let zp_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.make_zero_proof_bound(&cb, amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Zero proof generation failed")?
    };
    let zp_str = format!("zkzp_v2|{}", B64.encode(&zp_bytes));

    // Send result
    let result = ProveResult {
        msg_type: "result",
        job_id,
        data: Some(ProveData {
            cipher: cipher_str,
            amount_commitment: ct_commit_b64.clone(),
            zero_proof: zp_str,
            blinding: B64.encode(blinding),
            range_proof_balance: String::new(),
            range_proof_delta: None,
            commitment: Some(ct_commit_b64),
            send_zero_proof: None,
        }),
        step: None,
        error: None,
    };

    socket
        .send(Message::Text(serde_json::to_string(&result).unwrap().into()))
        .await
        .map_err(|e| format!("Send error: {e}"))?;

    Ok(())
}

async fn run_prove_unshield(req: ProveRequest, socket: &mut WebSocket) -> Result<(), String> {
    let job_id = req.job_id.clone();

    // Decode inputs
    let secret_key = decode_b64_32(&req.secret_key_b64, "secretKey")?;
    let current_cipher = B64.decode(&req.current_cipher_b64).map_err(|e| format!("Bad currentCipherB64: {e}"))?;
    let dec_amount: u64 = req.dec_amount_raw.parse().map_err(|e| format!("Bad decAmountRaw: {e}"))?;
    let seed = decode_b64_32(&req.seed_b64, "seed")?;
    let blinding = decode_b64_32(&req.blinding_b64, "blinding")?;

    send_status(socket, &job_id, "Initializing PVAC...").await?;

    // Initialize PVAC context (blocking)
    let ctx = tokio::task::spawn_blocking(move || PvacContext::new(&secret_key))
        .await
        .map_err(|e| format!("Task join error: {e}"))?
        .ok_or("PVAC initialization failed")?;

    let ctx = Arc::new(ctx);

    // Decrypt current balance to verify funds
    send_status(socket, &job_id, "Verifying balance...").await?;
    let current_balance = {
        let ctx = ctx.clone();
        let cipher = current_cipher.clone();
        tokio::task::spawn_blocking(move || ctx.decrypt(&cipher))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };

    if current_balance < dec_amount {
        return Err(format!(
            "Insufficient shielded balance: have {current_balance}, need {dec_amount}"
        ));
    }

    // Encrypt amount
    send_status(socket, &job_id, "Encrypting amount...").await?;
    let cipher_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.encrypt(dec_amount, &seed))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let cipher_str = format!("hfhe_v1|{}", B64.encode(&cipher_bytes));

    // Pedersen commit
    let commit_bytes = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || ctx.pedersen_commit(dec_amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
    };
    let commit_b64 = B64.encode(commit_bytes);

    // Zero proof
    send_status(socket, &job_id, "Generating zero proof...").await?;
    let zp_bytes = {
        let ctx = ctx.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.make_zero_proof_bound(&cb, dec_amount, &blinding))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Zero proof generation failed")?
    };
    let zp_str = format!("zkzp_v2|{}", B64.encode(&zp_bytes));

    // ct_sub: new balance cipher = current - amount
    send_status(socket, &job_id, "Computing new balance...").await?;
    let new_bal_cipher = {
        let ctx = ctx.clone();
        let cc = current_cipher.clone();
        let cb = cipher_bytes.clone();
        tokio::task::spawn_blocking(move || ctx.ct_sub(&cc, &cb))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("ct_sub failed")?
    };
    let new_bal_value = current_balance - dec_amount;

    // Range proof (THE SLOW STEP — but native should be much faster)
    send_status(socket, &job_id, "Generating range proof...").await?;
    let rp_bytes = {
        let ctx = ctx.clone();
        let nbc = new_bal_cipher;
        tokio::task::spawn_blocking(move || ctx.make_range_proof(&nbc, new_bal_value))
            .await
            .map_err(|e| format!("Task error: {e}"))?
            .ok_or("Range proof generation failed")?
    };
    let rp_str = format!("rp_v1|{}", B64.encode(&rp_bytes));

    // Send final result
    let result = ProveResult {
        msg_type: "result",
        job_id,
        data: Some(ProveData {
            cipher: cipher_str,
            amount_commitment: commit_b64,
            zero_proof: zp_str,
            blinding: B64.encode(blinding),
            range_proof_balance: rp_str,
            range_proof_delta: None,
            commitment: None,
            send_zero_proof: None,
        }),
        step: None,
        error: None,
    };

    socket
        .send(Message::Text(serde_json::to_string(&result).unwrap().into()))
        .await
        .map_err(|e| format!("Send error: {e}"))?;

    Ok(())
}

fn decode_b64_32(input: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = B64.decode(input).map_err(|e| format!("Bad {name}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name} must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
