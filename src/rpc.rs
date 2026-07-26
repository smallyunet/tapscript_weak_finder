use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

#[derive(Debug)]
pub enum Auth {
    None,
    CookieFile(PathBuf),
    UserPassword { user: String, password: String },
}

#[derive(Debug)]
enum ResolvedAuth {
    None,
    UserPassword { user: String, password: String },
}

pub struct RpcClient {
    url: String,
    auth: ResolvedAuth,
    client: Client,
    next_id: AtomicU64,
}

impl RpcClient {
    pub fn new(url: String, auth: Auth) -> Result<Self> {
        let auth = match auth {
            Auth::None => ResolvedAuth::None,
            Auth::UserPassword { user, password } => ResolvedAuth::UserPassword { user, password },
            Auth::CookieFile(path) => {
                let cookie = fs::read_to_string(&path)
                    .with_context(|| format!("read RPC cookie {}", path.display()))?;
                let (user, password) = cookie
                    .trim()
                    .split_once(':')
                    .context("RPC cookie must contain user:password")?;
                ResolvedAuth::UserPassword {
                    user: user.to_owned(),
                    password: password.to_owned(),
                }
            }
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            url,
            auth,
            client,
            next_id: AtomicU64::new(1),
        })
    }

    pub(crate) fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut request = self.client.post(&self.url).json(&body);
        if let ResolvedAuth::UserPassword { user, password } = &self.auth {
            request = request.basic_auth(user, Some(password));
        }
        let response = request
            .send()
            .with_context(|| format!("RPC {method} request failed"))?;
        let status = response.status();
        let envelope: RpcEnvelope<T> = response
            .json()
            .with_context(|| format!("decode RPC {method} response (HTTP {status})"))?;
        if let Some(error) = envelope.error {
            bail!("RPC {method} failed ({}): {}", error.code, error.message);
        }
        envelope
            .result
            .with_context(|| format!("RPC {method} returned no result"))
    }

    pub fn blockchain_info(&self) -> Result<BlockchainInfo> {
        self.call("getblockchaininfo", json!([]))
    }

    pub fn block_hash(&self, height: u64) -> Result<String> {
        self.call("getblockhash", json!([height]))
    }

    pub fn block(&self, hash: &str) -> Result<Block> {
        self.call("getblock", json!([hash, 2]))
    }
}

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    #[serde(default)]
    pub pruned: bool,
}

#[derive(Debug, Deserialize)]
pub struct Block {
    pub hash: String,
    pub height: u64,
    #[serde(default)]
    pub previousblockhash: Option<String>,
    pub tx: Vec<Transaction>,
}

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub txid: String,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
}

#[derive(Debug, Deserialize)]
pub struct TxIn {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    pub coinbase: Option<String>,
    #[serde(default)]
    pub txinwitness: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TxOut {
    pub value: BtcAmount,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

#[derive(Debug, Deserialize)]
pub struct ScriptPubKey {
    pub hex: String,
}

#[derive(Clone, Copy, Debug)]
pub struct BtcAmount(pub u64);

impl<'de> Deserialize<'de> for BtcAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let text = match value {
            Value::Number(number) => number.to_string(),
            Value::String(text) => text,
            _ => return Err(serde::de::Error::custom("BTC amount must be numeric")),
        };
        btc_to_sats(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

fn btc_to_sats(text: &str) -> Result<u64> {
    if text.starts_with('-') {
        bail!("negative BTC amount");
    }
    let (whole, fractional) = text.split_once('.').unwrap_or((text, ""));
    if fractional.len() > 8 {
        bail!("BTC amount has more than 8 decimal places: {text}");
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse()? };
    let mut frac = fractional.to_owned();
    while frac.len() < 8 {
        frac.push('0');
    }
    let frac: u64 = if frac.is_empty() { 0 } else { frac.parse()? };
    whole
        .checked_mul(100_000_000)
        .and_then(|n| n.checked_add(frac))
        .context("BTC amount overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_btc_amount_exactly() {
        assert_eq!(btc_to_sats("1").unwrap(), 100_000_000);
        assert_eq!(btc_to_sats("0.00000001").unwrap(), 1);
        assert_eq!(btc_to_sats("12.34000000").unwrap(), 1_234_000_000);
    }

    #[test]
    fn rejects_sub_satoshi_amounts() {
        assert!(btc_to_sats("0.000000001").is_err());
    }
}
