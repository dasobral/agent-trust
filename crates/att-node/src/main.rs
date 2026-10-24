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

mod agent;
mod apf;
mod config;
mod http;
mod qrng_mock;
mod relay;

fn usage() -> &'static str {
    "usage: att-node <apf|agent|relay|qrng-mock>\n\
     Configuration comes from ATT_* environment variables; see docs/protocol.md."
}

fn main() {
    let role = std::env::args().nth(1).unwrap_or_default();
    let result = match role.as_str() {
        "apf" => apf::run(),
        "agent" => agent::run(),
        "relay" => relay::run(),
        "qrng-mock" => qrng_mock::run(),
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
