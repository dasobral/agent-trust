//! R-13d production-scale check: the committed kernel alone, E5 message flow (allocate,
//! release, persist, 7 consumes), adapter mode (a head checkpoint before each mutation).
//! Prints, per tenth of the run: events, history bytes per event, ms per request, RSS.
#[path = "authority.rs"]
#[allow(dead_code)]
mod authority;
use serde_json::{json, Value};
use std::time::Instant;

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).map(|l| l.split_whitespace().nth(1).unwrap().parse().unwrap()))
        .unwrap_or(0)
}

fn main() {
    let envelope_bytes: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let messages: usize = std::env::args().nth(2).unwrap().parse().unwrap();
    let dir = std::env::temp_dir().join(format!("r13d-scale-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("authority.sqlite");
    let mut k = authority::Authority::open(&path).unwrap();
    let mut ok = |k: &mut authority::Authority, v: Value| k.execute(v.clone()).unwrap_or_else(|e| panic!("{e}: {v}"));
    let readers: Vec<String> = (1..8).map(|i| format!("agent{i:02}")).collect();
    ok(&mut k, json!({"command":"init","group":"g","root":"root"}));
    for r in &readers {
        for right in ["read", "admit"] {
            ok(&mut k, json!({"command":"grant","actor":"root","subject":r,"right":right,"generation":0,"fresh_keys":true,"now":10}));
        }
        ok(&mut k, json!({"command":"admit","actor":"root","subject":r,"now":10}));
    }
    let mut cover = vec![json!([{"subject":"root","right":"write","generation":0}]), json!([{"subject":"root","right":"read","generation":0}])];
    for r in &readers { cover.push(json!([{"subject":r,"right":"read","generation":0}])); }
    let envelope = "ab".repeat(envelope_bytes);
    let digest = "cd".repeat(32);
    let conn = rusqlite::Connection::open(&path).unwrap();
    println!("events,bytes_per_event,ms_per_request,rss_mib");
    let (mut requests, mut seconds) = (0usize, 0f64);
    for m in 0..messages {
        let op = format!("op{m}");
        let mut reqs = vec![json!({"command":"allocate","actor":"root","op":op}), Value::Null,
                            json!({"command":"persist","op":op,"digest":digest,"envelope":envelope})];
        for r in &readers { reqs.push(json!({"command":"consume","op":op,"recipient":r,"actor":r,"now":10})); }
        for i in 0..reqs.len() {
            let t = Instant::now();
            let head = ok(&mut k, json!({"command":"checkpoint","history":"none"}));
            let req = if i == 1 {
                json!({"command":"release","actor":"root","op":op,"right":"write","epoch":head["epoch"],"branch":head["branch"],
                       "policy_revision":head["policy_revision"],"digest":digest,"cover":cover,"now":10})
            } else { reqs[i].clone() };
            ok(&mut k, req);
            requests += 1; seconds += t.elapsed().as_secs_f64();
        }
        if (m + 1) % (messages / 10) == 0 {
            let (events, bytes): (i64, i64) = conn.query_row("SELECT COUNT(*), SUM(LENGTH(event)) FROM authority_events", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            println!("{events},{:.0},{:.3},{:.1}", bytes as f64 / events as f64, seconds * 1000.0 / requests as f64, rss_kib() as f64 / 1024.0);
            requests = 0; seconds = 0.0;
        }
    }
    drop(k);
    let t = Instant::now();
    let _k = authority::Authority::open(&path).unwrap();
    let file = std::fs::metadata(&path).unwrap().len();
    println!("reopen_ms,{:.0},file_mb,{:.1}", t.elapsed().as_secs_f64() * 1000.0, file as f64 / 1e6);
    std::fs::remove_dir_all(&dir).ok();
}
