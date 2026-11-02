// Network Diagnostics — Tauri library root. Desktop runs this through
// src/main.rs; Android/iOS load this same code as a library target
// (Tauri mobile builds require a lib target — a bin-only crate fails
// Android builds with "no library targets found in package").
// All checking runs in nd-core on the user's own device; the UI only
// collects the list and renders results.

use nd_core::*;
use std::time::Duration;

#[tauri::command]
async fn check_proxies(list_text: String, target: Option<String>) -> Result<String, String> {
    let list = parse_proxy_list(&list_text);
    if list.is_empty() {
        return Err("no valid proxies found in the pasted list".to_string());
    }
    let mut opts = CheckOptions {
        target_url: target.filter(|t| !t.trim().is_empty()),
        threads: 50,
        timeout: Duration::from_secs(10),
        geo: true, // app classifies residential vs datacenter by default
        ..Default::default()
    };
    // Baseline for transparent grading: what the judge sees without a proxy.
    if let Ok((200, body)) = direct_fetch(&opts.judge_url, opts.timeout) {
        if let Some(origin) = parse_judge(&body).origin {
            opts.real_ip = Some(origin.split(',').next().unwrap_or("").trim().to_string());
        }
    }
    // Checking is blocking network I/O; keep the UI thread free.
    let results = tauri::async_runtime::spawn_blocking(move || check_all(&list, &opts))
        .await
        .map_err(|e| e.to_string())?;
    Ok(results_to_json(&results))
}

/// Pull the built-in catalog of public free lists at runtime, merge and
/// de-duplicate. Returns JSON: {total, candidates (list text), reports}.
#[tauri::command]
async fn fetch_sources() -> Result<String, String> {
    let (merged, reports) = tauri::async_runtime::spawn_blocking(move || {
        nd_core::fetch_sources(&default_sources(), Duration::from_secs(20))
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"total\":{},\"candidates\":\"{}\",\"reports\":{}}}",
        merged.len(),
        escape_json(&endpoints_to_text(&merged)),
        reports_to_json(&reports)
    ))
}

#[tauri::command]
async fn check_domain(domain: String) -> Result<String, String> {
    let health = tauri::async_runtime::spawn_blocking(move || {
        domain_health(&domain, "8.8.8.8:53", Duration::from_secs(5))
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(health.to_json())
}

/// Fetch one URL as text (the "import list from URL" feature). Uses the
/// same in-process HTTPS stack as source fetching, so it works on
/// Android too.
#[tauri::command]
async fn fetch_url_text(url: String) -> Result<String, String> {
    let url = url.trim().to_string();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("URL must start with http:// or https://".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        nd_core::fetch_url(&url, Duration::from_secs(20))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Save an export file to the device's Downloads folder (falling back
/// to Documents, then the app data dir) and return its full path.
/// Browser-style blob downloads silently do nothing inside Android's
/// WebView, so exports go through the native side where they always
/// land on disk. Text exports pass `content`; binary ones (PDF) pass
/// base64 in `content_b64`.
#[tauri::command]
fn save_export(
    app: tauri::AppHandle,
    filename: String,
    content: Option<String>,
    content_b64: Option<String>,
) -> Result<String, String> {
    use tauri::Manager;
    let bytes: Vec<u8> = if let Some(b64) = content_b64 {
        base64_decode(&b64).ok_or_else(|| "invalid base64 payload".to_string())?
    } else {
        content.unwrap_or_default().into_bytes()
    };
    let dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().document_dir())
        .or_else(|_| app.path().app_data_dir())
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let safe: String = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    let path = dir.join(if safe.is_empty() { "export.txt".to_string() } else { safe });
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

/// Minimal standard-alphabet base64 decoder (export payloads only).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut n: u32 = 0;
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                n <<= 6;
            } else {
                n = (n << 6) | val(c)?;
                let _ = i;
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            check_proxies,
            check_domain,
            fetch_sources,
            fetch_url_text,
            save_export
        ])
        .run(tauri::generate_context!())
        .expect("error while running Network Diagnostics");
}
