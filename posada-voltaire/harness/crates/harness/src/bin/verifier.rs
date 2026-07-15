//! Independent verifier (property P3).
//!
//! Reads a transcript JSON produced by the harness and recomputes the tally
//! from the PUBLIC data alone. Exits 0 on PASS, non-zero on FAIL. Knows nothing
//! about any secret; it only needs the transcript.
//!
//!   cargo run --release --bin verifier -- <transcript.json>

use std::process::exit;
use voltaire_core::tally::{verify_transcript, Transcript};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: verifier <transcript.json>");
        exit(2);
    });
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            exit(2);
        }
    };
    let transcript: Transcript = match serde_json::from_str(&data) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("malformed transcript: {e}");
            exit(2);
        }
    };

    let outcome = verify_transcript(&transcript);
    println!("election : {}", transcript.header.election);
    println!("policy   : {}", transcript.header.policy);
    println!("ballots  : {}", transcript.ballots.len());
    println!("options  : {:?}", transcript.header.options);
    if outcome.pass {
        println!("VERIFY   : PASS — {}", outcome.reason);
        exit(0);
    } else {
        println!("VERIFY   : FAIL — {}", outcome.reason);
        exit(1);
    }
}
