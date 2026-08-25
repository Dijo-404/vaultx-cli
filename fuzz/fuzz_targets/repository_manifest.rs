//! Fuzz target: manifest decoder (plan §43).
//!
//! Exercises JSON deserialization of the full manifest model — typed ID
//! validation, internally tagged entry kinds, provider refs — for
//! arbitrary bytes. Panics/hangs/UB are the finding; Err is fine.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultx_repository::{Manifest, ManifestEntry};

fuzz_target!(|data: &[u8]| {
    let manifest: Manifest = match serde_json::from_slice(data) {
        Ok(manifest) => manifest,
        Err(_) => return,
    };
    // Re-encode must never panic either.
    let _ = serde_json::to_vec(&manifest);
    // Walk every decoded entry kind once so each variant's fields were
    // actually constructed from attacker bytes.
    for entry in manifest.entries.values() {
        let _ = matches!(
            entry,
            ManifestEntry::Config { .. }
                | ManifestEntry::Secret { .. }
                | ManifestEntry::Brokered { .. }
                | ManifestEntry::Dynamic { .. }
        );
    }
});
