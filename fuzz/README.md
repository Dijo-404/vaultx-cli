# vaultx-fuzz

libFuzzer targets for the vaultx parsers (plan §43). This package is
**excluded from the main workspace** (`[workspace] exclude = ["fuzz"]` in
the root `Cargo.toml`) because it builds against `libfuzzer-sys`, which
requires nightly toolchain flags at link time.

The committed `corpus/<target>/` directories are **seed corpora**: small,
hand-crafted *valid* inputs checked in so every target starts from
well-formed parser states instead of random garbage. They also double as
the "fuzz smoke corpus" referenced by plan §41 — see
`.github/workflows/fuzz-smoke.yml`.

## Running

Requires a nightly toolchain and `cargo-fuzz`:

```sh
rustup install nightly
cargo +nightly install cargo-fuzz   # or: taiki-e/install-action@cargo-fuzz in CI

cd fuzz
cargo +nightly fuzz run repository_object_envelope -- -max_total_time=60
```

Run from this directory (`fuzz/`). Any crash input lands in
`fuzz/crashes/` (or `artifact-*/` under CI); reproduce with
`cargo +nightly fuzz run <target> <crash-file>`.

## Targets

| Target | Crate | Entry point exercised |
| --- | --- | --- |
| `repository_object_envelope` | `vaultx-repository` | canonical envelope JSON decode (`ObjectEnvelope`) + typed payload hex decode |
| `repository_manifest` | `vaultx-repository` | manifest JSON decode (typed IDs, tagged entry kinds, provider refs) |
| `repository_diff_merge` | `vaultx-repository` | `[base, ours, theirs]` triple → `compute_diff`, `render_diff`, `three_way_merge[_with_strategy]` |
| `policy_document_yaml` | `vaultx-policy` | `parse_policy_yaml` (serde YAML + semantic validation) |
| `policy_pack_compile` | `vaultx-policy-packs` | `parse_pack_yaml` → `compile` → `to_policy_document` |
| `broker_protocol` | `vaultx-broker` | `BrokerRequest` / `BrokerResponse` JSON wire decode |
| `url_canonicalize` | `vaultx-http` | `CanonicalUrl::parse` (egress security boundary) |
| `http_controls` | `vaultx-http` | `filter_request_headers` + response sanitization (`redact_headers`, `enforce_content_type`, `redact_json_fields`) |

Target bodies ignore `Ok`/`Err`: parse and validation rejections are
expected outcomes for arbitrary bytes. The finding condition is a panic,
hang, or memory error.

## Notes

* Seeds are **committed**; libFuzzer grows them in-memory during runs but
  does not rewrite the checked-in files unless you pass `-artifact_prefix`
  / corpus output dirs deliberately.
* `http_controls` clamps header counts/values and body size purely to keep
  worst-case runtime inside fuzzer time budgets; it does not weaken what
  the parsers see.
