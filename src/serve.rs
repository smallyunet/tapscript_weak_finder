use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::db::{Database, RecentBlock, Status};

const MAX_INFLIGHT: usize = 32;
const MAX_HEADER_BYTES: usize = 8 * 1024;

#[derive(Debug, Serialize)]
struct PanelSnapshot {
    status: Status,
    recent_blocks: Vec<RecentBlock>,
}

pub fn run(db_path: &Path, bind: &str) -> Result<()> {
    let listener = TcpListener::bind(bind).with_context(|| format!("bind panel on {bind}"))?;
    let local = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| bind.to_owned());
    eprintln!("panel listening on http://{local}");
    serve(listener, db_path.to_path_buf())
}

fn serve(listener: TcpListener, db_path: PathBuf) -> Result<()> {
    let inflight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("panel accept error: {error}");
                continue;
            }
        };
        if inflight.load(Ordering::Relaxed) >= MAX_INFLIGHT {
            let _ = write_response(
                &stream,
                503,
                "text/plain; charset=utf-8",
                b"too many connections",
            );
            continue;
        }
        inflight.fetch_add(1, Ordering::Relaxed);
        let db_path = db_path.clone();
        let inflight = Arc::clone(&inflight);
        thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            if let Err(error) = handle_connection(stream, &db_path) {
                eprintln!("panel request error: {error:#}");
            }
            inflight.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, db_path: &Path) -> Result<()> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while header.len() < MAX_HEADER_BYTES {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            break;
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n") {
        bail!("panel request header was incomplete");
    }
    let text = String::from_utf8_lossy(&header);
    let request = text.lines().next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method != "GET" {
        return write_response(
            &stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        );
    }
    match path {
        "/" => write_response(
            &stream,
            200,
            "text/html; charset=utf-8",
            PANEL_HTML.as_bytes(),
        ),
        "/api/status" => match snapshot_json(db_path) {
            Ok(body) => write_response(&stream, 200, "application/json", body.as_bytes()),
            Err(_) if !db_path.exists() => write_response(
                &stream,
                503,
                "application/json",
                br#"{"error":"scan database is not ready"}"#,
            ),
            Err(error) => {
                eprintln!("panel status error: {error:#}");
                write_response(
                    &stream,
                    500,
                    "application/json",
                    br#"{"error":"status unavailable"}"#,
                )
            }
        },
        _ => write_response(&stream, 404, "text/plain; charset=utf-8", b"not found"),
    }
}

fn snapshot_json(db_path: &Path) -> Result<String> {
    let db = Database::open_readonly(db_path)?;
    let snapshot = PanelSnapshot {
        status: db.status()?,
        recent_blocks: db.recent_blocks(30)?,
    };
    Ok(serde_json::to_string(&snapshot)?)
}

fn write_response(
    mut stream: &TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

const PANEL_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TapScript 扫描进度</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; background: #10141a; color: #e7ecf3; }
  main { max-width: 1080px; margin: 0 auto; padding: 28px 20px 48px; }
  h1 { font-size: 1.4rem; margin: 0 0 6px; }
  p { margin: 0 0 18px; color: #b7c0ce; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }
  .card { background: #1b222d; border: 1px solid #2c3646; border-radius: 10px; padding: 12px 14px; }
  .card span { display: block; color: #93a0b5; font-size: 12px; }
  .card strong { font-size: 1.25rem; font-variant-numeric: tabular-nums; }
  table { width: 100%; border-collapse: collapse; margin-top: 22px; font-variant-numeric: tabular-nums; }
  th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #2c3646; }
  th { color: #93a0b5; font-weight: 600; font-size: 12px; }
  code { font-size: 12px; }
  .error { color: #ffb4a8; }
</style>
</head>
<body>
<main>
  <h1>TapScript 扫描进度</h1>
  <p id="note">只显示扫描进度和计数。不列出输出点、脚本或见证。</p>
  <div id="summary" class="grid"></div>
  <table>
    <thead>
      <tr>
        <th>高度</th><th>区块</th><th>交易</th><th>新建 P2TR</th><th>花费 P2TR</th><th>脚本路径</th><th>分析器命中</th>
      </tr>
    </thead>
    <tbody id="blocks"></tbody>
  </table>
</main>
<script>
const fields = [
  ["chain", "链"],
  ["start_height", "起始高度"],
  ["next_height", "下一高度"],
  ["target_height", "目标高度"],
  ["scanned_blocks", "已提交区块"],
  ["analyzed_scripts", "已分析脚本"],
  ["candidate_weak_scripts", "candidate_weak"],
  ["policy_rejected_scripts", "policy_rejected"],
  ["confirmed_weak_scripts", "confirmed_weak"],
  ["consensus_invalid_scripts", "consensus_invalid"],
  ["no_proof_found_scripts", "no_proof_found"],
  ["inconclusive_scripts", "inconclusive"],
  ["current_p2tr_utxos", "库内未花费 P2TR 数"],
  ["current_p2tr_balance_sats", "库内未花费聪"]
];
function cell(label, value) {
  return `<div class="card"><span>${label}</span><strong>${value ?? "—"}</strong></div>`;
}
async function refresh() {
  const note = document.getElementById("note");
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (response.status === 503) throw new Error("扫描数据库还没写出来");
    if (!response.ok) throw new Error("HTTP " + response.status);
    const body = await response.json();
    const status = body.status;
    document.getElementById("summary").innerHTML = fields.map(([key, label]) => cell(label, status[key])).join("");
    document.getElementById("blocks").innerHTML = (body.recent_blocks || []).map((block) =>
      `<tr><td>${block.height}</td><td><code>${block.block_hash.slice(0, 16)}…</code></td><td>${block.transactions}</td><td>${block.p2tr_created}</td><td>${block.p2tr_spent}</td><td>${block.script_paths}</td><td>${block.weak_scripts}</td></tr>`
    ).join("");
    note.className = "";
    note.textContent = "只显示扫描进度和计数。不列出输出点、脚本或见证。上次刷新 " + new Date().toLocaleTimeString();
  } catch (error) {
    note.className = "error";
    note.textContent = "暂时读不到扫描数据库：" + error.message;
  }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };

    use serde_json::Value;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::db::Database;

    #[test]
    fn panel_serves_counts_without_spendable_details() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let mut db = Database::open(&path).unwrap();
        db.prepare_scan("main", 709_632, 709_832, 709_632, 144)
            .unwrap();
        drop(db);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || serve(listener, path).unwrap());

        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let json: Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["status"]["start_height"], 709_632);
        assert_eq!(json["status"]["target_height"], 709_832);
        assert!(json["recent_blocks"].as_array().unwrap().is_empty());
        assert!(!body.contains("unspent_outpoints"));
        assert!(!body.contains("proof_witness"));
        assert!(!body.contains("vulnerable_script"));
        assert!(!body.contains("output_key"));

        let mut page = TcpStream::connect(address).unwrap();
        page.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut html = String::new();
        page.read_to_string(&mut html).unwrap();
        assert!(html.contains("TapScript 扫描进度"));
        assert!(!html.contains("unspent_outpoints"));
    }

    #[test]
    fn panel_waits_when_database_is_missing() {
        let path = std::env::temp_dir().join(format!(
            "tapscript-missing-panel-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || serve(listener, path).unwrap());

        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.contains("scan database is not ready"));
        assert!(!response.contains("unspent_outpoints"));
    }
}
