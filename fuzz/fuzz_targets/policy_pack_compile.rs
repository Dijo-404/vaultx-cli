//! Fuzz target: policy pack parser + compiler (plan §43).
//!
//! Feeds arbitrary bytes through `parse_pack_yaml` (typed schema decode +
//! full validation invariants), then lowers any accepted pack through
//! `compile` into the broker constraint set. Compilation is where pack
//! invariants are preserved rather than merely checked, so both stages
//! belong under fuzzing. Panics/hangs/UB are the finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultx_policy_packs::{compile, parse_pack_yaml};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(pack) = parse_pack_yaml(text) else {
        return;
    };
    if let Ok(compiled) = compile(&pack) {
        // The policy-document projection of a compiled pack must also be
        // panic-free for any accepted pack.
        if let Ok(principal) = vaultx_policy::Principal::parse("agent:fuzz") {
            let _ = compiled.to_policy_document(&principal);
        }
    }
});
