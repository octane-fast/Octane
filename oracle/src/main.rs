use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{SigningKey, Signer};
use serde::Serialize;
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

// KMS derive server inside the Oyster enclave (port 1100)
// Override with KMS_URL env var for testing.
const DEFAULT_KMS_URL: &str = "http://127.0.0.1:1100/derive/ed25519?path=oracle-price-feed";

fn kms_url() -> String {
    std::env::var("KMS_URL").unwrap_or_else(|_| DEFAULT_KMS_URL.to_string())
}

// ---------------------------------------------------------------------------
// Query Specification
// ---------------------------------------------------------------------------

/// A single source: URL to fetch + result query expression to extract the value.
#[derive(Clone, Serialize)]
struct QuerySource {
    url: String,
    #[serde(rename = "resultQuery")]
    result_query: String,
}

/// How to aggregate values from multiple sources.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum Aggregation {
    Median,
    Mode,
}

/// The full oracle query specification.
#[derive(Clone, Serialize)]
struct QuerySpec {
    sources: Vec<QuerySource>,
    aggregation: Aggregation,
}

/// Default domain separator if none provided in request.
const DEFAULT_DOMAIN: &str = "octusd-price-v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Request body for POST /latest
#[derive(serde::Deserialize)]
struct QueryRequest {
    sources: Vec<QuerySourceInput>,
    aggregation: String,  // "median" or "mode"
    #[serde(default = "default_domain")]
    domain: String,
    /// If set, multiply the aggregated value by this factor and truncate to integer
    /// before signing. This ensures the signed value matches the on-chain integer format.
    scale: Option<u64>,
}

#[derive(serde::Deserialize)]
struct QuerySourceInput {
    url: String,
    #[serde(rename = "resultQuery")]
    result_query: String,
}

fn default_domain() -> String { DEFAULT_DOMAIN.to_string() }

#[derive(Debug, Serialize, serde::Deserialize)]
struct Outcome {
    value: f64,
    timestamp: u64,
    domain: String,
    spec_hash: String,
    message: String,
    signature: String,
    public_key: String,
    sources_used: usize,
    sources_total: usize,
}

struct OracleCtx {
    signing_key: SigningKey,
    pk_hex: String,
    pk_b64: String,
}

// ---------------------------------------------------------------------------
// KMS key derivation
// ---------------------------------------------------------------------------

fn derive_signing_key() -> SigningKey {
    let url = kms_url();
    let body = ureq::get(&url)
        .call()
        .expect("failed to contact KMS derive server")
        .into_body()
        .read_to_vec()
        .expect("failed to read KMS response");

    let key_bytes: [u8; 32] = body[..32]
        .try_into()
        .expect("invalid key length from KMS");

    SigningKey::from_bytes(&key_bytes)
}

/// Compute a deterministic hash of the query spec.
fn compute_spec_hash(spec: &QuerySpec) -> String {
    let canonical = serde_json::to_string(spec).expect("serialize spec");
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// JMESPath evaluation
// ---------------------------------------------------------------------------
    
fn query_extract(value: &Value, path: &str) -> Option<f64> {
    let expr = jmespath::compile(path).ok()?;
    let data = jmespath::Variable::from_json(&serde_json::to_string(value).ok()?).ok()?;
    let result = expr.search(&data).ok()?;
    result.as_number()
        .or_else(|| result.as_string().and_then(|s| s.parse::<f64>().ok()))
}

fn fetch_json(url: &str) -> Option<Value> {
    let bytes = ureq::get(url)
        .call()
        .ok()?
        .into_body()
        .read_to_vec()
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn fetch_source_value(source: &QuerySource) -> Option<f64> {
    let json = fetch_json(&source.url)?;
    query_extract(&json, &source.result_query)
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

fn aggregate_median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = values.len();
    if n % 2 == 0 {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    } else {
        values[n / 2]
    }
}

fn aggregate_mode(values: &[f64]) -> f64 {
    // Bucket by rounding to 6 decimal places to handle float imprecision
    let mut counts: Vec<(i64, usize)> = Vec::new();
    for &p in values {
        let key = (p * 1_000_000.0).round() as i64;
        if let Some(entry) = counts.iter_mut().find(|(k, _)| *k == key) {
            entry.1 += 1;
        } else {
            counts.push((key, 1));
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    counts[0].0 as f64 / 1_000_000.0
}

fn aggregate(values: &mut Vec<f64>, method: Aggregation) -> f64 {
    match method {
        Aggregation::Median => aggregate_median(values),
        Aggregation::Mode => aggregate_mode(values),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fetch_and_sign(ctx: &OracleCtx, req: QueryRequest) -> Result<Outcome, String> {
    // Parse aggregation method
    let agg = match req.aggregation.as_str() {
        "median" => Aggregation::Median,
        "mode" => Aggregation::Mode,
        other => return Err(format!("unknown aggregation: {}", other)),
    };

    // Build spec and hash it
    let spec = QuerySpec {
        sources: req.sources.iter().map(|s| QuerySource {
            url: s.url.clone(),
            result_query: s.result_query.clone(),
        }).collect(),
        aggregation: agg,
    };
    let spec_hash = compute_spec_hash(&spec);

    // Fetch from each source
    let mut values: Vec<f64> = Vec::new();
    for source in &spec.sources {
        match fetch_source_value(source) {
            Some(p) => {
                eprintln!("  [OK] {} -> {}", source.url, p);
                values.push(p);
            }
            None => {
                eprintln!("  [FAIL] {}", source.url);
            }
        }
    }

    if values.is_empty() {
        return Err("no sources returned data".into());
    }

    let sources_total = spec.sources.len();
    let sources_used = values.len();
    let raw_value = aggregate(&mut values, agg);

    // Apply scale factor: multiply and truncate to integer for on-chain compatibility
    let value = match req.scale {
        Some(s) => (raw_value * s as f64).trunc(),
        None => raw_value,
    };

    let timestamp = now_unix();

    // Sign: "{domain}:{spec_hash}:{value}:{timestamp}"
    // When scaled, value is an integer (e.g. 41499) matching the contract's to_string()
    let value_str = if req.scale.is_some() {
        format!("{}", value as u64)
    } else {
        format!("{}", value)
    };
    let message = format!("{}:{}:{}:{}", req.domain, spec_hash, value_str, timestamp);
    let signature = ctx.signing_key.sign(message.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());

    Ok(Outcome {
        value,
        timestamp,
        domain: req.domain,
        spec_hash,
        message,
        signature: sig_b64,
        public_key: ctx.pk_b64.clone(),
        sources_used,
        sources_total,
    })
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

fn handle_request(mut stream: TcpStream, ctx: &OracleCtx) {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);

    let (status, body) = if request.starts_with("POST /latest") {
        eprintln!("-> POST /latest");
        // Extract JSON body after the blank line
        let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("");
        match serde_json::from_str::<QueryRequest>(body_str) {
            Ok(req) => match fetch_and_sign(ctx, req) {
                Ok(att) => ("200 OK", serde_json::to_string_pretty(&att).unwrap()),
                Err(e) => (
                    "503 Service Unavailable",
                    format!(r#"{{"error":"{}"}}"#, e),
                ),
            },
            Err(e) => (
                "400 Bad Request",
                format!(r#"{{"error":"invalid request body: {}","example":{{"sources":[{{"url":"https://api.coingecko.com/api/v3/simple/price?ids=octra&vs_currencies=usd","resultQuery":"octra.usd"}}],"aggregation":"median","domain":"octusd-price-v1"}}}}"#, e),
            ),
        }
    } else if request.starts_with("GET /health") {
        ("200 OK", r#"{"status":"ok"}"#.to_string())
    } else if request.starts_with("GET /pubkey") {
        (
            "200 OK",
            format!(r#"{{"public_key":"{}","public_key_hex":"{}"}}"#, ctx.pk_b64, ctx.pk_hex),
        )
    } else {
        (
            "404 Not Found",
            r#"{"error":"not found","endpoints":["POST /latest","GET /health","GET /pubkey"]}"#.to_string(),
        )
    };

    let response = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn main() {
    eprintln!("=== Starting Oracle ===");

    let signing_key = derive_signing_key();
    let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let pk_b64 = BASE64.encode(signing_key.verifying_key().as_bytes());
    eprintln!("Oracle ed25519 public key (hex): {}", pk_hex);
    eprintln!("Oracle ed25519 public key (b64): {}", pk_b64);

    let ctx = OracleCtx {
        signing_key,
        pk_hex,
        pk_b64,
    };

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).expect("failed to bind HTTP server");
    eprintln!("HTTP server listening on {}", addr);

    // Leak ctx into a &'static ref so request threads can share it without Arc.
    // Enables simultaneous requests.
    let ctx: &'static OracleCtx = Box::leak(Box::new(ctx));

    for stream in listener.incoming().flatten() {
        thread::spawn(move || handle_request(stream, ctx));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use std::net::TcpListener as StdTcpListener;

    /// Spin up a tiny HTTP server that returns `body` for any request.
    /// Returns (addr, join_handle).
    fn fake_server(body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            // Serve requests until the test drops the handle
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        (addr, handle)
    }

    fn test_signing_key() -> SigningKey {
        // Deterministic test key (32 zero bytes)
        SigningKey::from_bytes(&[0u8; 32])
    }

    fn test_ctx() -> OracleCtx {
        let sk = test_signing_key();
        let pk_hex = hex::encode(sk.verifying_key().as_bytes());
        let pk_b64 = BASE64.encode(sk.verifying_key().as_bytes());
        OracleCtx { signing_key: sk, pk_hex, pk_b64 }
    }

    #[test]
    fn test_spec_hash_deterministic() {
        let spec = QuerySpec {
            sources: vec![QuerySource {
                url: "https://example.com/price".into(),
                result_query: "data.price".into(),
            }],
            aggregation: Aggregation::Median,
        };
        let h1 = compute_spec_hash(&spec);
        let h2 = compute_spec_hash(&spec);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_spec_hash_changes_with_spec() {
        let spec1 = QuerySpec {
            sources: vec![QuerySource {
                url: "https://a.com".into(),
                result_query: "x".into(),
            }],
            aggregation: Aggregation::Median,
        };
        let spec2 = QuerySpec {
            sources: vec![QuerySource {
                url: "https://b.com".into(),
                result_query: "x".into(),
            }],
            aggregation: Aggregation::Median,
        };
        assert_ne!(compute_spec_hash(&spec1), compute_spec_hash(&spec2));
    }

    #[test]
    fn test_query_extract_dot_path() {
        let json: Value = serde_json::from_str(r#"{"a":{"b":{"c":42.5}}}"#).unwrap();
        assert_eq!(query_extract(&json, "a.b.c"), Some(42.5));
    }

    #[test]
    fn test_query_extract_string_number() {
        let json: Value = serde_json::from_str(r#"{"price":"0.045"}"#).unwrap();
        assert_eq!(query_extract(&json, "price"), Some(0.045));
    }

    #[test]
    fn test_query_extract_quoted_key() {
        let json: Value =
            serde_json::from_str(r#"{"data":{"token_prices":{"0xabc":"1.23"}}}"#).unwrap();
        let result = query_extract(&json, r#"data.token_prices."0xabc""#);
        assert_eq!(result, Some(1.23));
    }

    #[test]
    fn test_query_extract_missing_path() {
        let json: Value = serde_json::from_str(r#"{"a":1}"#).unwrap();
        assert_eq!(query_extract(&json, "a.b.c"), None);
    }

    #[test]
    fn test_fetch_and_sign_valid() {
        // Set up a fake price API
        let price_json = br#"{"octra":{"usd":0.045}}"#.to_vec();
        let (price_addr, _handle) = fake_server(price_json);

        let ctx = test_ctx();
        let req = QueryRequest {
            sources: vec![QuerySourceInput {
                url: format!("http://{}", price_addr),
                result_query: "octra.usd".into(),
            }],
            aggregation: "median".into(),
            domain: "test-domain".into(),
            scale: None,
        };

        let result = fetch_and_sign(&ctx, req).unwrap();

        // Verify value was extracted correctly
        assert_eq!(result.value, 0.045);
        assert_eq!(result.domain, "test-domain");
        assert_eq!(result.sources_used, 1);
        assert_eq!(result.sources_total, 1);

        // Verify signature is valid
        let sig_bytes = BASE64.decode(&result.signature).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes[..64].try_into().unwrap());
        let vk = test_signing_key().verifying_key();
        assert!(vk.verify(result.message.as_bytes(), &sig).is_ok());

        // Verify message format
        let parts: Vec<&str> = result.message.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "test-domain");
        assert_eq!(parts[1], result.spec_hash);
        assert_eq!(parts[2], "0.045");
    }

    #[test]
    fn test_fetch_and_sign_multiple_sources_median() {
        // Two sources returning different prices
        let json1 = br#"{"price":0.040}"#.to_vec();
        let json2 = br#"{"price":0.060}"#.to_vec();
        let (addr1, _h1) = fake_server(json1);
        let (addr2, _h2) = fake_server(json2);

        let ctx = test_ctx();
        let req = QueryRequest {
            sources: vec![
                QuerySourceInput {
                    url: format!("http://{}", addr1),
                    result_query: "price".into(),
                },
                QuerySourceInput {
                    url: format!("http://{}", addr2),
                    result_query: "price".into(),
                },
            ],
            aggregation: "median".into(),
            domain: "test".into(),
            scale: None,
        };

        let result = fetch_and_sign(&ctx, req).unwrap();
        // Median of 0.040 and 0.060 = 0.050
        assert_eq!(result.value, 0.050);
        assert_eq!(result.sources_used, 2);
    }

    #[test]
    fn test_fetch_and_sign_bad_aggregation() {
        let price_json = br#"{"p":1.0}"#.to_vec();
        let (addr, _h) = fake_server(price_json);

        let ctx = test_ctx();
        let req = QueryRequest {
            sources: vec![QuerySourceInput {
                url: format!("http://{}", addr),
                result_query: "p".into(),
            }],
            aggregation: "invalid".into(),
            domain: "x".into(),
            scale: None,
        };

        let result = fetch_and_sign(&ctx, req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown aggregation"));
    }

    #[test]
    fn test_fetch_and_sign_all_sources_fail() {
        // Point to a port nothing listens on
        let ctx = test_ctx();
        let req = QueryRequest {
            sources: vec![QuerySourceInput {
                url: "http://127.0.0.1:1".into(),
                result_query: "x".into(),
            }],
            aggregation: "median".into(),
            domain: "x".into(),
            scale: None,
        };

        let result = fetch_and_sign(&ctx, req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no sources"));
    }

    #[test]
    fn test_kms_derive_via_env() {
        // Fake KMS server that returns 32 bytes
        let key_bytes = [7u8; 32];
        let (addr, _h) = fake_server(key_bytes.to_vec());

        std::env::set_var("KMS_URL", format!("http://{}", addr));
        let sk = derive_signing_key();
        std::env::remove_var("KMS_URL");

        assert_eq!(sk.to_bytes(), key_bytes);
    }

    #[test]
    fn test_e2e_http_post_latest() {
        // Fake price source
        let price_json = br#"{"data":{"price":0.123}}"#.to_vec();
        let (price_addr, _price_h) = fake_server(price_json);

        // Start the oracle server on a random port with a known key
        let key_bytes = [42u8; 32];
        let sk = SigningKey::from_bytes(&key_bytes);
        let pk_hex = hex::encode(sk.verifying_key().as_bytes());
        let pk_b64 = BASE64.encode(sk.verifying_key().as_bytes());

        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let oracle_addr = listener.local_addr().unwrap().to_string();
        let ctx = Box::leak(Box::new(OracleCtx { signing_key: sk, pk_hex, pk_b64 }));

        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let ctx = ctx as &OracleCtx;
                handle_request(stream, ctx);
            }
        });

        // Give server a moment
        thread::sleep(std::time::Duration::from_millis(50));

        // Send POST /latest
        let req_body = format!(
            r#"{{"sources":[{{"url":"http://{}","resultQuery":"data.price"}}],"aggregation":"median","domain":"e2e-test"}}"#,
            price_addr
        );
        let raw_req = format!(
            "POST /latest HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
            oracle_addr, req_body.len(), req_body
        );

        let mut stream = TcpStream::connect(&oracle_addr).unwrap();
        stream.write_all(raw_req.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        // Parse response body
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let att: Outcome = serde_json::from_str(body).unwrap();

        assert_eq!(att.value, 0.123);
        assert_eq!(att.domain, "e2e-test");
        assert_eq!(att.sources_used, 1);

        // Verify signature
        let vk = SigningKey::from_bytes(&key_bytes).verifying_key();
        let sig_bytes = BASE64.decode(&att.signature).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes[..64].try_into().unwrap());
        assert!(vk.verify(att.message.as_bytes(), &sig).is_ok());
    }
}
