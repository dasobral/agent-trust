use agent_trust::authority::Authority;
use agent_trust::entropy::EntropyConfig;
use agent_trust::mls::MlsLab;
use agent_trust::suite::Suite;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn usage() -> &'static str {
    "usage: agent-trust authority --state PATH\n       agent-trust mls-demo\n       agent-trust lab --dir PATH --seed N\n       agent-trust export-trace --dir PATH\n\nThe authority command is a trusted administrative local interface; it is not a network service."
}

fn fail_usage(message: &str) -> ! {
    eprintln!("{}\n{}", message, usage());
    std::process::exit(2)
}

fn run_authority(path: PathBuf) -> i32 {
    let mut authority = match Authority::open(path) {
        Ok(authority) => authority,
        Err(error) => {
            eprintln!("{}", error);
            return 1;
        }
    };

    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("failed to read stdin: {}", error);
                return 1;
            }
        };
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => match authority.execute(request) {
                Ok(value) => json!({"ok": value}),
                Err(error) => json!({"error": error}),
            },
            Err(_) => json!({"error": "malformed"}),
        };
        if serde_json::to_writer(&mut stdout, &response).is_err()
            || stdout.write_all(b"\n").is_err()
            || stdout.flush().is_err()
        {
            return 1;
        }
    }
    0
}

fn run_mls_demo() -> i32 {
    let result = (|| -> Result<Value, String> {
        let mut lab = MlsLab::new()?;
        lab.add_member("bob")?;
        lab.add_member("carol")?;
        let staged_keypackage_binding_verified = lab.verify_member_admission("bob").is_ok()
            && lab.verify_member_admission("carol").is_ok();
        let before = lab.epoch();

        lab.snapshot_member("bob", "revoked-copy")?;
        let old_wire = lab.protect("alice", b"before removal", b"epoch: old")?;
        let old_snapshot_decrypts = lab.decrypt("revoked-copy", &old_wire).is_ok();

        lab.remove_member("bob")?;
        let epoch_advanced = lab.epoch() > before;
        let successor_wire = lab.protect("alice", b"after removal", b"epoch: successor")?;
        let continuing_reader_decrypts = lab.decrypt("carol", &successor_wire).is_ok();
        let removed_reader_rejected = lab.decrypt("revoked-copy", &successor_wire).is_err();

        let summary = json!({
            "baseline_retained_reader_decrypts": old_snapshot_decrypts,
            "removed_reader_rejected": removed_reader_rejected,
            "continuing_reader_decrypts": continuing_reader_decrypts,
            "epoch_advanced": epoch_advanced,
            "full_lap_mls": false,
            "staged_keypackage_binding_verified": staged_keypackage_binding_verified,
        });
        if old_snapshot_decrypts
            && removed_reader_rejected
            && continuing_reader_decrypts
            && epoch_advanced
            && staged_keypackage_binding_verified
        {
            Ok(summary)
        } else {
            Err("mls-demo experiment outcome was not met".to_owned())
        }
    })();

    match result {
        Ok(summary) => {
            println!("{}", summary);
            0
        }
        Err(error) => {
            eprintln!("{}", error);
            1
        }
    }
}

/// Parses `lab --dir PATH --seed N`.
fn lab_args(mut args: std::env::ArgsOs) -> (PathBuf, u64) {
    let (Some(dir_flag), Some(dir), Some(seed_flag), Some(seed), None) = (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) else {
        fail_usage("lab requires --dir PATH --seed N")
    };
    if dir_flag != "--dir" || seed_flag != "--seed" {
        fail_usage("lab requires --dir PATH --seed N");
    }
    let Some(seed) = seed.to_str().and_then(|seed| seed.parse().ok()) else {
        fail_usage("lab seed must be an unsigned integer")
    };
    (dir.into(), seed)
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        fail_usage("missing command")
    };
    let status = match command.to_string_lossy().as_ref() {
        "authority" => {
            let Some(flag) = args.next() else {
                fail_usage("authority requires --state PATH")
            };
            if flag != "--state" {
                fail_usage("authority requires --state PATH");
            }
            let Some(path) = args.next() else {
                fail_usage("authority requires --state PATH")
            };
            if args.next().is_some() {
                fail_usage("unexpected authority argument");
            }
            run_authority(path.into())
        }
        "mls-demo" => {
            if args.next().is_some() {
                fail_usage("mls-demo takes no arguments");
            }
            run_mls_demo()
        }
        "lab" => {
            let (dir, seed) = lab_args(args);
            // C-42: the suite is resolved first; an unknown value processes no request.
            let suite = match Suite::from_env(|name| std::env::var(name).ok()) {
                Ok(suite) => suite,
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1)
                }
            };
            // C-40: the entropy source is resolved before any request is read; a bad or
            // unreachable source is a startup failure, never a fallback to another source.
            let entropy = match EntropyConfig::from_env().and_then(|config| config.connect()) {
                Ok(entropy) => entropy,
                Err(error) => {
                    eprintln!("entropy_unavailable: {error}");
                    std::process::exit(1)
                }
            };
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            match agent_trust::lab::run_lab_with_suite(
                &dir,
                seed,
                entropy,
                suite,
                stdin.lock(),
                stdout.lock(),
            ) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        "export-trace" => {
            let (Some(flag), Some(dir), None) = (args.next(), args.next(), args.next()) else {
                fail_usage("export-trace requires --dir PATH")
            };
            if flag != "--dir" {
                fail_usage("export-trace requires --dir PATH");
            }
            match agent_trust::lab::export_v2_trace(std::path::Path::new(&dir)) {
                Ok(trace) => {
                    println!("{}", Value::Array(trace));
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        _ => fail_usage("unknown command"),
    };
    std::process::exit(status);
}
