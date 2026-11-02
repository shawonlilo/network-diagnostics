//! nd-check — Network Diagnostics command line.
//!
//!   nd-check check  --file proxies.txt [--target https://site.example]
//!                   [--judge http://httpbin.org/get] [--threads 50]
//!                   [--timeout 10] [--geo] [--out ./results]
//!   nd-check domain example.com [--dns 8.8.8.8:53] [--json]
//!
//! Only test proxies and systems you own or are authorized to test.

use nd_core::*;
use std::io::Read as IoRead;
use std::time::Duration;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn usage() {
    eprintln!(
        "nd-check — Network Diagnostics\n\nUSAGE:\n  nd-check check --file <list.txt|-> [options]\n  nd-check domain <example.com> [--dns host:port] [--json]\n\nCHECK OPTIONS:\n  --judge <url>     judge endpoint echoing origin+headers (default http://httpbin.org/get)\n  --target <url>    also test each working proxy against this site\n  --threads <n>     parallel checks (default 50)\n  --timeout <secs>  per-proxy timeout (default 10)\n  --geo             enrich exit IPs with country/ISP (ip-api.com)\n  --out <dir>       write results.json, working.txt, target_ok.txt here\n"
    );
}

fn cmd_check(args: &[String]) -> i32 {
    let file = match flag(args, "--file") {
        Some(f) => f,
        None => {
            usage();
            return 2;
        }
    };
    let text = if file == "-" {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            eprintln!("failed to read stdin");
            return 2;
        }
        buf
    } else {
        match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cannot read {file}: {e}");
                return 2;
            }
        }
    };
    let list = parse_proxy_list(&text);
    if list.is_empty() {
        eprintln!("no valid proxies found in input");
        return 2;
    }
    let timeout = Duration::from_secs(
        flag(args, "--timeout").and_then(|v| v.parse().ok()).unwrap_or(10),
    );
    let mut opts = CheckOptions {
        judge_url: flag(args, "--judge")
            .unwrap_or_else(|| "http://httpbin.org/get".to_string()),
        target_url: flag(args, "--target"),
        threads: flag(args, "--threads")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50),
        timeout,
        geo: has(args, "--geo"),
        ..Default::default()
    };
    // Baseline: what does the judge see without a proxy? (transparent grading)
    if let Ok((200, body)) = direct_fetch(&opts.judge_url, timeout) {
        let echo = parse_judge(&body);
        if let Some(origin) = echo.origin {
            opts.real_ip = Some(origin.split(',').next().unwrap_or("").trim().to_string());
        }
    }
    eprintln!(
        "checking {} proxies ({} threads, judge: {})...",
        list.len(),
        opts.threads,
        opts.judge_url
    );
    let started = std::time::Instant::now();
    let results = check_all(&list, &opts);
    let alive: Vec<&ProxyResult> = results.iter().filter(|r| r.alive).collect();
    let target_ok: Vec<&&ProxyResult> = alive
        .iter()
        .filter(|r| r.target_ok == Some(true))
        .collect();
    println!(
        "\n{} checked in {:.1}s — {} alive{}",
        results.len(),
        started.elapsed().as_secs_f64(),
        alive.len(),
        if opts.target_url.is_some() {
            format!(", {} pass the target test", target_ok.len())
        } else {
            String::new()
        }
    );
    for r in &alive {
        println!(
            "{:>7}ms  {:<8} {:<12} {:<24} {}",
            r.latency_ms.unwrap_or(0),
            r.protocol.clone().unwrap_or_default(),
            r.anonymity.clone().unwrap_or_default(),
            r.exit_ip.clone().unwrap_or_default(),
            r.proxy
        );
    }
    if let Some(out_dir) = flag(args, "--out") {
        let dir = std::path::Path::new(&out_dir);
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("cannot create out dir: {e}");
            return 1;
        }
        let _ = std::fs::write(dir.join("results.json"), results_to_json(&results));
        // Working proxies in full protocol form, fastest first.
        let working: Vec<String> = alive
            .iter()
            .map(|r| {
                let proto = match r.protocol.as_deref() {
                    Some("socks5") => ProxyProtocol::Socks5,
                    Some("socks4") => ProxyProtocol::Socks4,
                    _ => ProxyProtocol::Http,
                };
                format!("{}://{}", proto.as_str(), r.proxy)
            })
            .collect();
        let _ = std::fs::write(dir.join("working.txt"), working.join("\n") + "\n");
        if opts.target_url.is_some() {
            let t: Vec<String> = target_ok
                .iter()
                .map(|r| format!("{}://{}", r.protocol.clone().unwrap_or_default(), r.proxy))
                .collect();
            let _ = std::fs::write(dir.join("target_ok.txt"), t.join("\n") + "\n");
        }
        eprintln!("wrote results to {out_dir}/");
    }
    0
}

fn cmd_domain(args: &[String]) -> i32 {
    let mut domain: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dns" | "--timeout" | "--judge" | "--target" | "--threads" | "--file" | "--out" => {
                i += 2;
            }
            a if a.starts_with("--") => i += 1,
            a => {
                domain = Some(a.to_string());
                i += 1;
            }
        }
    }
    let domain = match domain {
        Some(d) => d,
        None => {
            usage();
            return 2;
        }
    };
    let resolver = flag(args, "--dns").unwrap_or_else(|| "8.8.8.8:53".to_string());
    let health = domain_health(&domain, &resolver, Duration::from_secs(5));
    if has(args, "--json") {
        println!("{}", health.to_json());
    } else {
        println!("domain:   {}", health.domain);
        println!(
            "A:        {}",
            if health.a_records.is_empty() {
                "—".to_string()
            } else {
                health.a_records.join(", ")
            }
        );
        println!(
            "MX:       {}",
            if health.mx_records.is_empty() {
                "—".to_string()
            } else {
                health.mx_records.join(", ")
            }
        );
        println!("SPF:      {}", health.spf.clone().unwrap_or_else(|| "—".to_string()));
        println!("DMARC:    {}", health.dmarc.clone().unwrap_or_else(|| "—".to_string()));
        println!("verdict:  {}", health.verdict());
        if let Some(e) = &health.error {
            println!("note:     {e}");
        }
    }
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("check") => cmd_check(&args[1..]),
        Some("domain") => cmd_domain(&args[1..]),
        _ => {
            usage();
            2
        }
    };
    std::process::exit(code);
}
