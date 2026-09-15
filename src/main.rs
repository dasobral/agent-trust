use agent_trust::authority::Authority;
use agent_trust::mls::MlsLab;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn usage() -> &'static str {
    "usage: agent-trust authority --state PATH\n       agent-trust mls-demo\n\nThe authority command is a trusted administrative local interface; it is not a network service."
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
        });
        if old_snapshot_decrypts && removed_reader_rejected && continuing_reader_decrypts && epoch_advanced {
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

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else { fail_usage("missing command") };
    let status = match command.to_string_lossy().as_ref() {
        "authority" => {
            let Some(flag) = args.next() else { fail_usage("authority requires --state PATH") };
            if flag != "--state" {
                fail_usage("authority requires --state PATH");
            }
            let Some(path) = args.next() else { fail_usage("authority requires --state PATH") };
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
        _ => fail_usage("unknown command"),
    };
    std::process::exit(status);
}
