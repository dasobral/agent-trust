//! `att-node`: the network services of the Agent Trust testbed.
//!
//! One binary, four roles. Every role is configured only by `ATT_*` environment
//! variables (and the `AGENT_TRUST_ENTROPY_*` variables of agent-trust for the
//! entropy source), so the same image runs under any deployment backend.
//!
//! | Role        | Wraps                                   | Trust            |
//! |-------------|-----------------------------------------|------------------|
//! | `apf`       | agent-trust `Adapter` (APF key, kernel, sequencer) | Trusted authority |
//! | `agent`     | agent-trust `ClientEndpoint` (one MLS member)       | Holds its own keys |
//! | `relay`     | Nothing: opaque store and forward, fault injection  | Untrusted network  |
//! | `qrng-mock` | A QRNG Open API server over the OS RNG              | MOCK entropy       |
//!
//! Three tools share the binary: `pki` (the deployment's post quantum and classical CAs
//! and certificates for mutual TLS), `pki-issue` (one more certificate, for negative
//! controls) and `probe` (a health check and a transport probe under mutual TLS).

mod agent;
mod apf;
mod config;
mod http;
mod qrng_mock;
mod relay;
mod tls;

fn usage() -> &'static str {
    "usage: att-node <apf|agent|relay|qrng-mock>\n\
     \x20      att-node pki --dir DIR --names a,b,c [--namespace NS]\n\
     \x20      att-node pki-issue --dir DIR --name NAME --out OUT [--classical]\n\
     \x20      att-node probe URL [--tls-dir DIR [--as NAME] [--classical-kx] [--method M] [--body JSON]]\n\
     Configuration comes from ATT_* environment variables; see docs/protocol.md."
}

fn main() {
    let role = std::env::args().nth(1).unwrap_or_default();
    let result = match role.as_str() {
        "apf" => apf::run(),
        "agent" => agent::run(),
        "relay" => relay::run(),
        "qrng-mock" => qrng_mock::run(),
        "pki" => tls::run_pki(&std::env::args().skip(2).collect::<Vec<_>>()),
        "pki-issue" => tls::run_pki_issue(&std::env::args().skip(2).collect::<Vec<_>>()),
        "probe" => http::run_probe(&std::env::args().skip(2).collect::<Vec<_>>()),
        "--version" => {
            println!("att-node {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("att-node {role}: {error}");
        std::process::exit(1);
    }
}
