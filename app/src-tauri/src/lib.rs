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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![check_proxies, check_domain, fetch_sources])
        .run(tauri::generate_context!())
        .expect("error while running Network Diagnostics");
}
