//! Fuzz target: repository object envelope decoder (plan §43).
//!
//! Exercises `ObjectEnvelope` canonical-JSON decoding plus the typed
//! payload decode path. Any input is legal here; Ok/Err are ignored and
//! a panic, hang, or memory error is the finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultx_repository::object::{ObjectEnvelope, ObjectType};

fuzz_target!(|data: &[u8]| {
    let envelope: ObjectEnvelope = match serde_json::from_slice(data) {
        Ok(envelope) => envelope,
        Err(_) => return,
    };
    // Payload decode as an unstructured value exercises the hex payload
    // round trip for arbitrary object categories.
    let _ = envelope.decode_payload::<serde_json::Value>();
    let _ = serde_json::to_vec(&envelope);
    // Touch the category discriminant so enum decoding is fully consumed.
    let _ = matches!(envelope.object_type, ObjectType::Manifest);
});
