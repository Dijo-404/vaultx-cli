//! Fuzz target: diff/merge engine (plan §43).
//!
//! Input is a JSON triple `[base, ours, theirs]` of manifests. Decoding
//! all three then running `compute_diff` and `three_way_merge` covers
//! every diff classification branch and merge conflict path with
//! attacker-controlled manifests. Panics/hangs/UB are the finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultx_repository::{
    compute_diff, render_diff, three_way_merge, three_way_merge_with_strategy, MergeStrategy,
    Manifest,
};

fuzz_target!(|data: &[u8]| {
    let (base, ours, theirs): (Manifest, Manifest, Manifest) = match serde_json::from_slice(data) {
        Ok(triple) => triple,
        Err(_) => return,
    };
    let diff = compute_diff(&base, &ours);
    // Rendering is metadata-only output but must not panic on any diff.
    let _ = render_diff(&diff);
    let _ = three_way_merge(&base, &ours, &theirs);
    let _ = three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Ours);
    let _ = three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Theirs);
});
