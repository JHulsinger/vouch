use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<serde_json::Value>,
    error: Option<String>,
    id: u64,
}

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let mut line = String::new();
    if handle.read_line(&mut line)? > 0 {
        let req: JsonRpcRequest = serde_json::from_str(&line)?;
        
        match req.method.as_str() {
            "authenticator.perform" => {
                let domain = req.params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let key_auth = req.params.get("key_authorization").and_then(|v| v.as_str()).unwrap_or("");
                
                // In a real implementation:
                // 1. Parse Cloudflare API token from environment
                // 2. Use the `cloudflare` crate to find the zone for `domain`
                // 3. Create a TXT record for `_acme-challenge.<domain>` with value `key_auth`
                
                eprintln!("CF PLUGIN: Would create TXT record for {} with value {}", domain, key_auth);
                
                send_response(req.id, serde_json::json!({ "status" : "ok" }))?;
            }
            "authenticator.cleanup" => {
                let domain = req.params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                eprintln!("CF PLUGIN: Would delete ACME TXT record for {}", domain);
                send_response(req.id, serde_json::json!({ "status" : "ok" }))?;
            }
            _ => {
                send_error(req.id, format!("Unknown method: {}", req.method))?;
            }
        }
    }

    Ok(())
}

fn send_response(id: u64, result: serde_json::Value) -> anyhow::Result<()> {
    let resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(result),
        error: None,
        id,
    };
    println!("{}", serde_json::to_string(&resp)?);
    io::stdout().flush()?;
    Ok(())
}

fn send_error(id: u64, error: String) -> anyhow::Result<()> {
    let resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(error),
        id,
    };
    println!("{}", serde_json::to_string(&resp)?);
    io::stdout().flush()?;
    Ok(())
}
