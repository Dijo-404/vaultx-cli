//! Append-only JSONL implementation of [`AppendStore`] plus JSONL export.
//!
//! # Concurrency model (v1)
//!
//! Like the repository, this store assumes **single-process,
//! single-writer access**. An internal mutex serializes writes within the
//! process (poisoning is recovered from because all authoritative state
//! lives on disk); concurrent writers in separate processes are
//! unsupported. Concurrent readers are always safe.
//!
//! # Crash semantics
//!
//! Each append serializes one compact JSON object and writes body and
//! terminating `\n` in a **single** `write_all`, then calls
//! [`File::sync_data`] so the record reaches stable storage before
//! success is reported. A crash can therefore leave either nothing or a
//! truncated final line — never two records spliced onto one physical
//! line.
//!
//! Readers never silently skip damage of any kind. Every read path
//! ([`JsonlAppendStore::append`], `latest_hash`, `verify_chain`,
//! `query`) surfaces a partial or malformed line as
//! [`AuditError::CorruptRecord`] naming its 1-based line number —
//! including a final segment whose JSON would otherwise parse but lacks
//! its terminating newline, which is treated as evidence of a crashed
//! write rather than accepted as a record. The chain is fail-closed —
//! appending is refused while any record is unreadable, so operator
//! intervention precedes further writes.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use crate::error::AuditError;
use crate::event::{generate_audit_event_id, AuditDecision, AuditEvent, NewAuditEvent};
use crate::store::{AppendStore, AuditFilter};

/// Local append-only audit store backed by one JSON Lines file.
#[derive(Debug)]
pub struct JsonlAppendStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl JsonlAppendStore {
    /// Creates a handle to a JSONL store at `path`.
    ///
    /// The file itself is created lazily by the first append; the parent
    /// directory must already exist.
    #[must_use]
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    fn lock_writes(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn load_events(&self) -> Result<Vec<AuditEvent>, AuditError> {
        let Some(file) = open_store_file(&self.path)? else {
            return Ok(Vec::new());
        };
        let mut events = Vec::new();
        walk_records(file, |number, body| {
            events.push(parse_event_line(body, number)?);
            Ok(true)
        })?;
        Ok(events)
    }
}

fn open_store_file(path: &std::path::Path) -> Result<Option<File>, AuditError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Walks physical records of a JSONL file, invoking `visit(number, body)`
/// with 1-based line numbers and newline-stripped bodies; returning
/// `Ok(false)` from `visit` stops the walk (filter short-circuit).
///
/// A final segment without its terminating `\n` is rejected outright —
/// even when its JSON would parse — because an unterminated tail is
/// evidence of a crashed write, not a record.
fn walk_records<F>(file: File, mut visit: F) -> Result<(), AuditError>
where
    F: FnMut(usize, &str) -> Result<bool, AuditError>,
{
    let mut reader = BufReader::new(file);
    let mut raw = String::new();
    let mut number = 0;
    loop {
        raw.clear();
        if reader.read_line(&mut raw)? == 0 {
            return Ok(());
        }
        number += 1;
        let Some(body) = raw.strip_suffix('\n') else {
            return Err(AuditError::CorruptRecord {
                line: number,
                reason: "final record is missing its terminating newline".to_owned(),
            });
        };
        if !visit(number, body)? {
            return Ok(());
        }
    }
}

fn parse_event_line(line: &str, number: usize) -> Result<AuditEvent, AuditError> {
    serde_json::from_str(line).map_err(|e| AuditError::CorruptRecord {
        line: number,
        reason: e.to_string(),
    })
}

fn serialize_line(event: &AuditEvent) -> Result<String, AuditError> {
    serde_json::to_string(event).map_err(|e| AuditError::Serialization(e.to_string()))
}

fn matches_filter(filter: &AuditFilter, event: &AuditEvent) -> bool {
    let decision_matches = match filter.decision_allow {
        None => true,
        Some(true) => matches!(event.decision, AuditDecision::Allow),
        Some(false) => matches!(event.decision, AuditDecision::Deny { .. }),
    };
    filter
        .actor
        .as_ref()
        .is_none_or(|actor| *actor == event.actor)
        && filter
            .project
            .as_ref()
            .is_none_or(|project| *project == event.project)
        && filter.action.is_none_or(|action| action == event.action)
        && decision_matches
        && filter
            .credential
            .as_ref()
            .is_none_or(|credential| event.credential.as_ref() == Some(credential))
        && filter
            .correlation_id
            .as_ref()
            .is_none_or(|correlation| *correlation == event.correlation_id)
}

impl AppendStore for JsonlAppendStore {
    fn append(&self, event: NewAuditEvent) -> Result<AuditEvent, AuditError> {
        let _guard = self.lock_writes();
        // Fail closed: refuse to extend a chain whose tail cannot be read.
        let events = self.load_events()?;
        let sequence = events.last().map_or(0, |last| last.sequence + 1);
        let prev_hash = match events.last() {
            Some(last) => Some(last.hash()?),
            None => None,
        };
        let stored = AuditEvent {
            id: generate_audit_event_id()?,
            correlation_id: event.correlation_id,
            sequence,
            prev_hash,
            actor: event.actor,
            project: event.project,
            environment: event.environment,
            action: event.action,
            decision: event.decision,
            credential: event.credential,
            destination: event.destination,
            capability: event.capability,
            policy_ids: event.policy_ids,
            metadata: event.metadata,
        };
        // Write-boundary validation: an oversized denial reason built by
        // bypassing the validated constructor must not persist into an
        // unreadable store.
        stored.decision.validate()?;
        let mut record = serialize_line(&stored)?;
        record.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        // Single write: body and terminator share one call so a crash
        // can never splice two records onto one physical line.
        file.write_all(record.as_bytes())?;
        file.flush()?;
        // Durability: the record reaches stable storage before success
        // is reported to the caller.
        file.sync_data()?;
        Ok(stored)
    }

    fn latest_hash(&self) -> Result<Option<String>, AuditError> {
        let _guard = self.lock_writes();
        match self.load_events()?.last() {
            Some(last) => Ok(Some(last.hash()?)),
            None => Ok(None),
        }
    }

    fn verify_chain(&self) -> Result<(), AuditError> {
        let events = self.load_events()?;
        let mut expected_prev: Option<String> = None;
        for (index, event) in events.iter().enumerate() {
            if event.sequence != index as u64 {
                return Err(AuditError::ChainBroken {
                    at_sequence: event.sequence,
                    reason: format!("expected contiguous sequence {index}"),
                });
            }
            if event.prev_hash != expected_prev {
                // Attribute the break to the earliest implicated event:
                // with no predecessor the offending event is this one
                // (genesis/link rewrite); otherwise either the
                // predecessor's content no longer hashes to the digest
                // recorded about it, or this event's own link was
                // rewritten — report the earlier of the two.
                let at_sequence = index
                    .checked_sub(1)
                    .map_or(event.sequence, |prev| events[prev].sequence);
                return Err(AuditError::ChainBroken {
                    at_sequence,
                    reason: "recomputed hash does not match the recorded linkage".to_owned(),
                });
            }
            expected_prev = Some(event.hash()?);
        }
        Ok(())
    }

    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AuditError> {
        let limit = filter.limit.unwrap_or(usize::MAX);
        let mut matched = Vec::new();
        if limit == 0 {
            return Ok(matched);
        }
        let Some(file) = open_store_file(&self.path)? else {
            return Ok(matched);
        };
        walk_records(file, |number, body| {
            let event = parse_event_line(body, number)?;
            if matches_filter(filter, &event) {
                matched.push(event);
                if matched.len() >= limit {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        Ok(matched)
    }
}

/// Writes filtered events from `store` to `writer`, one compact JSON
/// object per line — byte-identical to the corresponding
/// [`JsonlAppendStore`] records.
///
/// # Errors
/// Returns [`AuditError`] when querying the store or writing to `writer`
/// fails.
pub fn export_jsonl<S>(
    store: &S,
    filter: &AuditFilter,
    writer: &mut impl Write,
) -> Result<(), AuditError>
where
    S: AppendStore + ?Sized,
{
    for event in store.query(filter)? {
        writeln!(writer, "{}", serialize_line(&event)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{
        AuditAction, CapabilityName, CorrelationId, SafeAuditMetadata, SafeDestinationSummary,
    };
    use crate::store::{NoopRemoteIngest, RemoteIngest};
    use vaultx_policy::Principal;
    use vaultx_types::{CredentialRef, EnvironmentId, PolicyId, ProjectId};

    fn temp_store(name: &str) -> (tempfile::TempDir, JsonlAppendStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = JsonlAppendStore::open(dir.path().join(name));
        (dir, store)
    }

    fn sample_new_event() -> NewAuditEvent {
        NewAuditEvent {
            correlation_id: CorrelationId::generate().expect("generated"),
            actor: Principal::parse("agent:alice").expect("valid principal"),
            project: ProjectId::parse("proj_core").expect("valid project"),
            environment: None,
            action: AuditAction::HttpRequest,
            decision: AuditDecision::Allow,
            credential: None,
            destination: None,
            capability: None,
            policy_ids: Vec::new(),
            metadata: SafeAuditMetadata::default(),
        }
    }

    fn read_lines(store: &JsonlAppendStore) -> Vec<String> {
        std::fs::read_to_string(&store.path)
            .expect("store readable")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn fresh_store_is_empty_and_valid() {
        let (_dir, store) = temp_store("audit.jsonl");
        assert_eq!(store.latest_hash().unwrap(), None);
        store.verify_chain().unwrap();
        assert!(store.query(&AuditFilter::default()).unwrap().is_empty());
    }

    #[test]
    fn genesis_event_carries_none_prev_hash_and_generated_identity() {
        let (_dir, store) = temp_store("audit.jsonl");
        let genesis = store.append(sample_new_event()).unwrap();
        assert_eq!(genesis.sequence, 0);
        assert_eq!(genesis.prev_hash, None);
        assert!(genesis.id.as_str().starts_with("aud_"));
        assert_eq!(store.latest_hash().unwrap(), Some(genesis.hash().unwrap()));
        let loaded = store.query(&AuditFilter::default()).unwrap();
        assert_eq!(loaded, vec![genesis]);
    }

    #[test]
    fn chaining_links_successive_events() {
        let (_dir, store) = temp_store("audit.jsonl");
        let first = store.append(sample_new_event()).unwrap();
        let second = store
            .append(NewAuditEvent {
                action: AuditAction::SecretSet,
                ..sample_new_event()
            })
            .unwrap();

        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(second.prev_hash, Some(first.hash().unwrap()));
        assert_ne!(first.hash().unwrap(), second.hash().unwrap());
        assert_eq!(store.latest_hash().unwrap(), Some(second.hash().unwrap()));
        store.verify_chain().unwrap();
    }

    #[test]
    fn append_query_round_trip_with_all_filter_dimensions() {
        let (_dir, store) = temp_store("audit.jsonl");

        let alice = Principal::parse("agent:alice").unwrap();
        let bob = Principal::parse("agent:bob").unwrap();
        let core = ProjectId::parse("proj_core").unwrap();
        let web = ProjectId::parse("proj_web").unwrap();
        let prod = EnvironmentId::parse("env_prod").unwrap();
        let token = CredentialRef::parse("deploy_token").unwrap();
        let policy = PolicyId::parse("pol_least_privilege").unwrap();
        let shared_correlation = CorrelationId::parse("shared-trace").unwrap();

        let events = [
            NewAuditEvent {
                correlation_id: shared_correlation.clone(),
                actor: alice.clone(),
                project: core.clone(),
                environment: Some(prod.clone()),
                action: AuditAction::HttpRequest,
                decision: AuditDecision::Allow,
                credential: Some(token.clone()),
                destination: Some(
                    SafeDestinationSummary::new("api.github.com", 443, "/user/repos").unwrap(),
                ),
                capability: Some(CapabilityName::parse("github.pull_request.create").unwrap()),
                policy_ids: vec![policy],
                metadata: SafeAuditMetadata::from_pairs([("http.method", "GET")]).unwrap(),
            },
            NewAuditEvent {
                correlation_id: shared_correlation.clone(),
                actor: bob.clone(),
                project: core.clone(),
                action: AuditAction::HttpRequest,
                decision: AuditDecision::Deny {
                    reason: "path not allowed".to_owned(),
                },
                ..sample_new_event()
            },
            NewAuditEvent {
                actor: alice.clone(),
                project: web,
                action: AuditAction::SecretRotate,
                ..sample_new_event()
            },
            NewAuditEvent {
                actor: bob.clone(),
                project: core.clone(),
                action: AuditAction::PolicyUpdated,
                decision: AuditDecision::Allow,
                ..sample_new_event()
            },
        ];
        let mut stored = Vec::new();
        for event in events {
            stored.push(store.append(event).unwrap());
        }

        let default_all = store.query(&AuditFilter::default()).unwrap();
        assert_eq!(default_all.len(), 4);
        assert_eq!(default_all, stored);

        // actor
        let alice_only = store
            .query(&AuditFilter {
                actor: Some(alice.clone()),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(alice_only, vec![stored[0].clone(), stored[2].clone()]);

        // project
        let web_only = store
            .query(&AuditFilter {
                project: Some(ProjectId::parse("proj_web").unwrap()),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(web_only.len(), 1);
        assert_eq!(web_only[0].sequence, 2);

        // action
        let secret_rotations = store
            .query(&AuditFilter {
                action: Some(AuditAction::SecretRotate),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(secret_rotations.len(), 1);

        // decision_allow both ways
        let denies = store
            .query(&AuditFilter {
                decision_allow: Some(false),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].sequence, 1);
        let allows = store
            .query(&AuditFilter {
                decision_allow: Some(true),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(allows.len(), 3);

        // credential
        let credentialed = store
            .query(&AuditFilter {
                credential: Some(token),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(credentialed.len(), 1);
        assert_eq!(credentialed[0].sequence, 0);

        // correlation id
        let correlated = store
            .query(&AuditFilter {
                correlation_id: Some(shared_correlation),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(correlated, vec![stored[0].clone(), stored[1].clone()]);

        // combined dimensions narrow further
        let combined = store
            .query(&AuditFilter {
                actor: Some(alice.clone()),
                project: Some(core.clone()),
                decision_allow: Some(true),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(combined, vec![stored[0].clone()]);

        // limit truncates matches
        let limited = store
            .query(&AuditFilter {
                limit: Some(2),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(limited, vec![stored[0].clone(), stored[1].clone()]);
        assert!(store
            .query(&AuditFilter {
                limit: Some(0),
                ..AuditFilter::default()
            })
            .unwrap()
            .is_empty());

        // no match yields empty result
        assert!(store
            .query(&AuditFilter {
                actor: Some(Principal::parse("agent:nobody").unwrap()),
                ..AuditFilter::default()
            })
            .unwrap()
            .is_empty());
    }

    #[test]
    fn verify_chain_reports_earliest_offending_sequence_for_tampered_content() {
        let (_dir, store) = temp_store("audit.jsonl");
        for index in 0..3 {
            store
                .append(NewAuditEvent {
                    metadata: SafeAuditMetadata::from_pairs([(
                        "marker",
                        if index == 1 { "alpha" } else { "clean" },
                    )])
                    .unwrap(),
                    ..sample_new_event()
                })
                .unwrap();
        }
        store.verify_chain().unwrap();

        // Tamper with the middle event's metadata by rewriting the file.
        let mut lines = read_lines(&store);
        assert_eq!(lines.len(), 3);
        lines[1] = lines[1].replace("\"alpha\"", "\"beta\"");
        std::fs::write(&store.path, lines.join("\n") + "\n").unwrap();

        // The tampered event itself is blamed (its recomputed hash no
        // longer matches the digest its successor recorded), not the
        // successor where the mismatch is observed.
        let err = store.verify_chain().unwrap_err();
        match err {
            AuditError::ChainBroken { at_sequence, .. } => assert_eq!(at_sequence, 1),
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_partial_last_line_fails_closed_everywhere() {
        let (_dir, store) = temp_store("audit.jsonl");
        store.append(sample_new_event()).unwrap();

        // Simulate a crashed write: truncated trailing record, no newline.
        let mut file = OpenOptions::new().append(true).open(&store.path).unwrap();
        file.write_all(br#"{"id":"aud_broken"#).unwrap();
        drop(file);

        for outcome in [
            store.verify_chain().expect_err("verify fails"),
            store.latest_hash().expect_err("latest_hash fails"),
            store
                .query(&AuditFilter::default())
                .expect_err("query fails"),
            store.append(sample_new_event()).expect_err("append fails"),
        ] {
            assert!(
                matches!(outcome, AuditError::CorruptRecord { line: 2, .. }),
                "expected CorruptRecord at line 2, got {outcome:?}"
            );
        }
    }

    #[test]
    fn corrupt_mid_file_line_reports_its_line_number() {
        let (_dir, store) = temp_store("audit.jsonl");
        for _ in 0..3 {
            store.append(sample_new_event()).unwrap();
        }
        let mut lines = read_lines(&store);
        lines[1] = String::from("not-json");
        std::fs::write(&store.path, lines.join("\n") + "\n").unwrap();

        for err in [
            store.verify_chain().unwrap_err(),
            store.query(&AuditFilter::default()).unwrap_err(),
        ] {
            assert!(
                matches!(err, AuditError::CorruptRecord { line: 2, .. }),
                "expected CorruptRecord at line 2, got {err:?}"
            );
        }
    }

    #[test]
    fn verify_chain_detects_genesis_linkage_violation() {
        let (_dir, store) = temp_store("audit.jsonl");
        store.append(sample_new_event()).unwrap();

        let mut lines = read_lines(&store);
        lines[0] = lines[0].replace("\"prev_hash\":null", "\"prev_hash\":\"deadbeef\"");
        std::fs::write(&store.path, lines.join("\n") + "\n").unwrap();

        // With no predecessor, the offending event itself is reported.
        assert!(matches!(
            store.verify_chain().unwrap_err(),
            AuditError::ChainBroken { at_sequence: 0, .. }
        ));
    }

    #[test]
    fn unterminated_final_record_fails_closed_even_when_json_is_valid() {
        let (_dir, store) = temp_store("audit.jsonl");
        store.append(sample_new_event()).unwrap();
        store.append(sample_new_event()).unwrap();

        // Drop only the final newline: every remaining byte is valid
        // JSONL, simulating a death between body and terminator.
        let body = std::fs::read_to_string(&store.path).unwrap();
        let trimmed = body.trim_end_matches('\n');
        std::fs::write(&store.path, trimmed).unwrap();

        for outcome in [
            store.verify_chain().expect_err("verify fails"),
            store.latest_hash().expect_err("latest_hash fails"),
            store
                .query(&AuditFilter::default())
                .expect_err("query fails"),
            store.append(sample_new_event()).expect_err("append fails"),
        ] {
            assert!(
                matches!(outcome, AuditError::CorruptRecord { line: 2, .. }),
                "expected CorruptRecord at line 2, got {outcome:?}"
            );
        }
    }

    #[test]
    fn oversized_deny_reason_is_refused_at_write_boundary() {
        let (_dir, store) = temp_store("audit.jsonl");
        store.append(sample_new_event()).unwrap();

        // A literal Deny bypassing the validated constructor must not be
        // persisted: the write path re-validates before serializing.
        let decision = AuditDecision::Deny {
            reason: "x".repeat(AuditDecision::MAX_DENY_REASON_BYTES + 1),
        };
        let err = store
            .append(NewAuditEvent {
                decision,
                ..sample_new_event()
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::InvalidMetadata { .. }));

        // The store stays healthy: nothing was written.
        store.verify_chain().unwrap();
        assert_eq!(store.query(&AuditFilter::default()).unwrap().len(), 1);
    }

    #[test]
    fn export_jsonl_output_equals_filtered_source_lines() {
        let (_dir, store) = temp_store("audit.jsonl");
        let web = ProjectId::parse("proj_web").unwrap();
        let core = ProjectId::parse("proj_core").unwrap();
        for project in [&core, &web, &core, &web] {
            store
                .append(NewAuditEvent {
                    project: project.clone(),
                    ..sample_new_event()
                })
                .unwrap();
        }

        let mut exported = Vec::new();
        export_jsonl(
            &store,
            &AuditFilter {
                project: Some(web),
                ..AuditFilter::default()
            },
            &mut exported,
        )
        .unwrap();

        let exported_text = String::from_utf8(exported).unwrap();
        let expected_lines: Vec<String> = read_lines(&store)
            .into_iter()
            .filter(|line| line.contains("\"project\":\"proj_web\""))
            .collect();
        let exported_lines: Vec<String> = exported_text.lines().map(str::to_owned).collect();
        assert_eq!(exported_lines, expected_lines);
        assert_eq!(exported_lines.len(), 2);

        // Unfiltered export reproduces the whole file byte-for-byte per line.
        let mut everything = Vec::new();
        export_jsonl(&store, &AuditFilter::default(), &mut everything).unwrap();
        let all_lines: Vec<String> = String::from_utf8(everything)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(all_lines, read_lines(&store));
    }

    #[test]
    fn noop_remote_ingest_accepts_batches() {
        let (_dir, store) = temp_store("audit.jsonl");
        let event = store.append(sample_new_event()).unwrap();
        let ingest = NoopRemoteIngest;
        ingest.ingest_batch(vec![event]).unwrap();
    }

    #[test]
    fn structural_redaction_canary() {
        let (_dir, store) = temp_store("audit.jsonl");
        const CANARY: &str = "CANARY_SECRET_9f8";

        // (1) Sensitive keys are rejected before anything is written.
        let mut metadata = SafeAuditMetadata::default();
        assert!(metadata
            .try_insert("Authorization", &format!("Bearer {CANARY}"))
            .is_err());

        // (2) An event built ONLY through public APIs carries no field
        // shaped like an auth header / bearer token / cookie.
        metadata.try_insert("http.method", "GET").unwrap();
        let event = store
            .append(NewAuditEvent {
                metadata,
                destination: Some(
                    SafeDestinationSummary::new("api.github.com", 443, "/user/repos").unwrap(),
                ),
                ..sample_new_event()
            })
            .unwrap();
        let line = serde_json::to_string(&event).unwrap();
        assert!(!line.contains(CANARY));
        assert!(!line.contains("\"authorization\""));
        assert!(!line.contains("\"proxy-authorization\""));
        assert!(!line.contains("\"cookie\""));
        assert!(!line.contains("\"session-token\""));

        // Raw file bytes back the assertion up end-to-end.
        let raw = std::fs::read_to_string(&store.path).unwrap();
        assert!(!raw.contains(CANARY));

        // (3) Destinations exclude the query component by construction:
        // only host/port/path fields exist on the wire.
        let destination_json = serde_json::to_value(event.destination.unwrap()).unwrap();
        let mut keys: Vec<_> = destination_json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["host", "path", "port"]);
        assert!(!raw.contains('?'));
    }
}
