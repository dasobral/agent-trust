//! F-8 microbenchmark: the agent-trust kernel alone, driven like the E5 message flow
//! (allocate, release, persist, 7 consumes per message), root as the only writer and 7
//! admitted readers. `adapter` mode adds the C-31 `checkpoint` read before each mutation.
#[path = "authority_base.rs"]
#[allow(dead_code)]
mod authority_base;
#[path = "authority_fix.rs"]
#[allow(dead_code)]
mod authority_fix;
use serde_json::{json, Value};
use std::time::Instant;

trait Kernel {
    fn exec(&mut self, v: Value) -> Result<Value, String>;
}
impl Kernel for authority_base::Authority {
    fn exec(&mut self, v: Value) -> Result<Value, String> { self.execute(v) }
}
impl Kernel for authority_fix::Authority {
    fn exec(&mut self, v: Value) -> Result<Value, String> { self.execute(v) }
}

fn ok(k: &mut dyn Kernel, v: Value) -> Value {
    k.exec(v.clone()).unwrap_or_else(|e| panic!("{e}: {v}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let variant = args[1].as_str(); // base | fix
    let adapter = args[2] == "adapter"; // kernel | adapter
    let envelope_bytes: usize = args[3].parse().unwrap();
    let messages: usize = args[4].parse().unwrap();
    let dir = std::env::temp_dir().join(format!("f8-{}-{}", std::process::id(), variant));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("authority.sqlite");
    let mut k: Box<dyn Kernel> = match variant {
        "base" => Box::new(authority_base::Authority::open(&path).unwrap()),
        _ => Box::new(authority_fix::Authority::open(&path).unwrap()),
    };
    let k = k.as_mut();
    let readers: Vec<String> = (1..8).map(|i| format!("agent{i:02}")).collect();
    let now = 10u64;
    ok(k, json!({"command":"init","group":"g","root":"root"}));
    for r in &readers {
        for right in ["read", "admit"] {
            ok(k, json!({"command":"grant","actor":"root","subject":r,"right":right,"generation":0,"fresh_keys":true,"now":now}));
        }
        ok(k, json!({"command":"admit","actor":"root","subject":r,"now":now}));
    }
    let mut cover = vec![json!([{"subject":"root","right":"write","generation":0}]),
                         json!([{"subject":"root","right":"read","generation":0}])];
    for r in &readers { cover.push(json!([{"subject":r,"right":"read","generation":0}])); }
    let envelope = "ab".repeat(envelope_bytes);
    let digest = "cd".repeat(32);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mut window = (0usize, 0f64);
    println!("events,history_mb,ms_per_request");
    let mut events: i64 = conn.query_row("SELECT COUNT(*) FROM authority_events", [], |r| r.get(0)).unwrap();
    for m in 0..messages {
        let op = format!("op{m}");
        let mut reqs = vec![json!({"command":"allocate","actor":"root","op":op})];
        reqs.push(Value::Null); // release, built after the allocate
        reqs.push(json!({"command":"persist","op":op,"digest":digest,"envelope":envelope}));
        for r in &readers {
            reqs.push(json!({"command":"consume","op":op,"recipient":r,"actor":r,"now":now}));
        }
        for i in 0..reqs.len() {
            let t = Instant::now();
            if adapter { ok(k, json!({"command":"checkpoint","history":"none"})); }
            let req = if i == 1 {
                let c = ok(k, json!({"command":"checkpoint","history":"none"}));
                json!({"command":"release","actor":"root","op":op,"right":"write",
                       "epoch":c["epoch"],"branch":c["branch"],"policy_revision":c["policy_revision"],
                       "digest":digest,"cover":cover,"now":now})
            } else { reqs[i].clone() };
            ok(k, req);
            window.0 += 1;
            window.1 += t.elapsed().as_secs_f64() * 1000.0;
            events += 1;
        }
        if (m + 1) % 6 == 0 {
            let bytes: i64 = conn.query_row("SELECT COALESCE(SUM(LENGTH(event)),0) FROM authority_events", [], |r| r.get(0)).unwrap();
            println!("{events},{:.1},{:.2}", bytes as f64 / 1e6, window.1 / window.0 as f64);
            window = (0, 0.0);
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}
