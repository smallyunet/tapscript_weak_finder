use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::RETRY_AFTER,
};
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
    options: RpcOptions,
}

#[derive(Clone, Copy, Debug)]
pub struct RpcOptions {
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_initial_delay: Duration,
    pub retry_max_delay: Duration,
    pub max_response_bytes: u64,
}

impl Default for RpcOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(180),
            max_retries: 5,
            retry_initial_delay: Duration::from_secs(1),
            retry_max_delay: Duration::from_secs(30),
            max_response_bytes: 64 * 1024 * 1024,
        }
    }
}

impl RpcClient {
    pub fn new(url: String, auth: Auth) -> Result<Self> {
        Self::with_options(url, auth, RpcOptions::default())
    }

    pub fn with_options(url: String, auth: Auth, options: RpcOptions) -> Result<Self> {
        if options.timeout.is_zero() {
            bail!("RPC timeout must be greater than zero");
        }
        if options.retry_max_delay < options.retry_initial_delay {
            bail!("RPC maximum retry delay must not be smaller than the initial delay");
        }
        if options.max_response_bytes == 0 {
            bail!("RPC maximum response size must be greater than zero");
        }
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
            .timeout(options.timeout)
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            url,
            auth,
            client,
            next_id: AtomicU64::new(1),
            options,
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
        for attempt in 0..=self.options.max_retries {
            let mut request = self.client.post(&self.url).json(&body);
            if let ResolvedAuth::UserPassword { user, password } = &self.auth {
                request = request.basic_auth(user, Some(password));
            }
            let response = match request.send() {
                Ok(response) => response,
                Err(error) if is_retryable_transport_error(&error) => {
                    if self.retry(method, attempt, "transport_error", None) {
                        continue;
                    }
                    bail!(
                        "RPC {method} request failed after retries ({})",
                        transport_error_kind(&error)
                    );
                }
                Err(error) => {
                    bail!(
                        "RPC {method} request failed ({})",
                        transport_error_kind(&error)
                    );
                }
            };
            let status = response.status();
            if is_retryable_status(status) {
                let retry_after = retry_after(&response);
                if self.retry(
                    method,
                    attempt,
                    &format!("http_{}", status.as_u16()),
                    retry_after,
                ) {
                    continue;
                }
                bail!(
                    "RPC {method} returned retryable HTTP {status} after {} attempts",
                    attempt + 1
                );
            }
            if !status.is_success() {
                bail!("RPC {method} returned HTTP {status}");
            }
            if response
                .content_length()
                .is_some_and(|length| length > self.options.max_response_bytes)
            {
                bail!(
                    "RPC {method} response exceeds configured {} MiB limit",
                    self.options.max_response_bytes / 1024 / 1024
                );
            }
            let mut reader = LimitedReader::new(response, self.options.max_response_bytes);
            let envelope: RpcEnvelope<T> = match serde_json::from_reader(&mut reader) {
                Ok(envelope) => envelope,
                Err(_error) => {
                    if reader.exceeded() {
                        bail!(
                            "RPC {method} response exceeds configured {} MiB limit",
                            self.options.max_response_bytes / 1024 / 1024
                        );
                    }
                    if self.retry(method, attempt, "invalid_response", None) {
                        continue;
                    }
                    bail!("decode RPC {method} response (HTTP {status}) after retries");
                }
            };
            if let Some(error) = envelope.error {
                if is_retryable_rpc_error(error.code)
                    && self.retry(method, attempt, &format!("rpc_{}", error.code), None)
                {
                    continue;
                }
                bail!("RPC {method} failed ({}): {}", error.code, error.message);
            }
            return envelope
                .result
                .with_context(|| format!("RPC {method} returned no result"));
        }
        unreachable!("RPC attempt loop always returns")
    }

    fn retry(
        &self,
        method: &str,
        attempt: u32,
        reason: &str,
        retry_after: Option<Duration>,
    ) -> bool {
        if attempt >= self.options.max_retries {
            return false;
        }
        let delay = self.retry_delay(attempt, retry_after);
        eprintln!(
            "rpc_retry method={method} retry={}/{} reason={reason} delay_ms={}",
            attempt + 1,
            self.options.max_retries,
            delay.as_millis()
        );
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        true
    }

    fn retry_delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let multiplier = 1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        let exponential = self
            .options
            .retry_initial_delay
            .checked_mul(multiplier)
            .unwrap_or(self.options.retry_max_delay)
            .min(self.options.retry_max_delay);
        retry_after
            .unwrap_or_default()
            .max(exponential)
            .min(self.options.retry_max_delay)
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

struct LimitedReader<R> {
    inner: R,
    remaining: u64,
    exceeded: bool,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            exceeded: false,
        }
    }

    fn exceeded(&self) -> bool {
        self.exceeded
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0u8; 1];
            if self.inner.read(&mut probe)? == 0 {
                return Ok(0);
            }
            self.exceeded = true;
            return Err(io::Error::other("RPC response size limit exceeded"));
        }
        let allowed = usize::try_from(self.remaining.min(buffer.len() as u64))
            .expect("allowed read length fits usize");
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn is_retryable_transport_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_body()
}

fn transport_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection"
    } else if error.is_body() {
        "response_body"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_builder() {
        "request_build"
    } else {
        "transport"
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn is_retryable_rpc_error(code: i64) -> bool {
    // Bitcoin Core uses -28 while warming up or loading chain state.
    code == -28
}

fn retry_after(response: &Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
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
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => {
            if exponent.contains(['e', 'E']) {
                bail!("BTC amount has multiple exponents: {text}");
            }
            let exponent = exponent
                .parse::<i64>()
                .with_context(|| format!("invalid BTC amount exponent: {text}"))?;
            (mantissa, exponent)
        }
        None => (text, 0),
    };
    let (whole, fractional) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.contains('.') || fractional.contains('.') {
        bail!("BTC amount has multiple decimal points: {text}");
    }
    if whole.is_empty() && fractional.is_empty() {
        bail!("BTC amount has no digits");
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("BTC amount contains a non-decimal digit: {text}");
    }

    let mut digits = String::with_capacity(whole.len() + fractional.len());
    digits.push_str(whole);
    digits.push_str(fractional);
    if digits.bytes().all(|byte| byte == b'0') {
        return Ok(0);
    }
    let first_nonzero = digits
        .bytes()
        .position(|byte| byte != b'0')
        .expect("non-zero digit checked");
    digits.drain(..first_nonzero);

    let fractional_len =
        i64::try_from(fractional.len()).context("BTC amount fractional length overflow")?;
    let zero_shift = 8i64
        .checked_add(exponent)
        .and_then(|value| value.checked_sub(fractional_len))
        .context("BTC amount exponent overflow")?;
    if zero_shift >= 0 {
        let zero_count = usize::try_from(zero_shift).context("BTC amount exponent overflow")?;
        if digits.len().saturating_add(zero_count) > 20 {
            bail!("BTC amount overflow: {text}");
        }
        digits.extend(std::iter::repeat_n('0', zero_count));
    } else {
        let remove_count =
            usize::try_from(zero_shift.unsigned_abs()).context("BTC amount exponent overflow")?;
        if remove_count > digits.len() {
            bail!("BTC amount is smaller than one satoshi: {text}");
        }
        let keep = digits.len() - remove_count;
        if digits.as_bytes()[keep..].iter().any(|byte| *byte != b'0') {
            bail!("BTC amount is smaller than one satoshi: {text}");
        }
        digits.truncate(keep);
    }

    digits
        .parse::<u64>()
        .with_context(|| format!("BTC amount overflow: {text}"))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    #[test]
    fn parses_btc_amount_exactly() {
        assert_eq!(btc_to_sats("1").unwrap(), 100_000_000);
        assert_eq!(btc_to_sats("0.00000001").unwrap(), 1);
        assert_eq!(btc_to_sats("12.34000000").unwrap(), 1_234_000_000);
        assert_eq!(btc_to_sats("0.00000600").unwrap(), 600);
        assert_eq!(btc_to_sats("6e-6").unwrap(), 600);
        assert_eq!(btc_to_sats("1E-8").unwrap(), 1);
        assert_eq!(btc_to_sats("000000000000.00000600").unwrap(), 600);
        assert_eq!(btc_to_sats("184467440737.09551615").unwrap(), u64::MAX);
    }

    #[test]
    fn rejects_sub_satoshi_amounts() {
        assert!(btc_to_sats("0.000000001").is_err());
        assert!(btc_to_sats("1e-9").is_err());
        assert!(btc_to_sats("-0.00000001").is_err());
        assert!(btc_to_sats("184467440737.09551616").is_err());
    }

    #[test]
    fn deserializes_provider_amount_without_floating_point_round_trip() {
        let fixed: BtcAmount = serde_json::from_str("0.00000600").unwrap();
        let scientific: BtcAmount = serde_json::from_str("6e-6").unwrap();
        assert_eq!(fixed.0, 600);
        assert_eq!(scientific.0, 600);
    }

    #[test]
    fn retries_retryable_http_status_then_succeeds() {
        let url = serve_responses(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
            json_response(r#"{"jsonrpc":"2.0","id":1,"result":42,"error":null}"#),
        ]);
        let client = test_client(url, 2);

        let result: u64 = client.call("test", json!([])).unwrap();

        assert_eq!(result, 42);
    }

    #[test]
    fn retries_malformed_success_response_then_succeeds() {
        let url = serve_responses(vec![
            json_response(r#"{"jsonrpc":"2.0","id":1,"result":not-json}"#),
            json_response(r#"{"jsonrpc":"2.0","id":1,"result":7,"error":null}"#),
        ]);
        let client = test_client(url, 1);

        let result: u64 = client.call("test", json!([])).unwrap();

        assert_eq!(result, 7);
    }

    #[test]
    fn transport_errors_do_not_expose_the_rpc_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let secret = "provider-key-must-not-appear";
        let client = test_client(format!("http://{address}/{secret}"), 0);

        let error = client
            .call::<u64>("test", json!([]))
            .unwrap_err()
            .to_string();

        assert!(!error.contains(secret));
        assert!(!error.contains(&address.to_string()));
    }

    #[test]
    fn rejects_a_response_above_the_memory_guard_without_retrying() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":"oversized","error":null}"#;
        let url = serve_responses(vec![json_response(body)]);
        let mut options = test_options(3);
        options.max_response_bytes = 16;
        let client = RpcClient::with_options(url, Auth::None, options).unwrap();

        let error = client
            .call::<String>("test", json!([]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("response exceeds configured"));
    }

    fn test_client(url: String, max_retries: u32) -> RpcClient {
        RpcClient::with_options(url, Auth::None, test_options(max_retries)).unwrap()
    }

    fn test_options(max_retries: u32) -> RpcOptions {
        RpcOptions {
            timeout: Duration::from_secs(2),
            max_retries,
            retry_initial_delay: Duration::ZERO,
            retry_max_delay: Duration::ZERO,
            max_response_bytes: 1024 * 1024,
        }
    }

    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn serve_responses(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        format!("http://{address}")
    }
}
