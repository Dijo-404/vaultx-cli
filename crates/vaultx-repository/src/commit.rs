//! Signed commits and content-derived commit IDs.
//!
//! # Signing contract
//!
//! The signed payload is the canonical JSON of a commit's semantic fields
//! (`format`, `parents`, `manifest`, `author`, `message`) — i.e. everything
//! except the [`signature`](Commit::signature) field itself. Mutable
//! storage metadata is not part of the commit type at all, so nothing
//! outside those five fields can ever influence a signature.
//!
//! # Commit ID derivation
//!
//! A [`CommitId`] is derived from the canonical bytes of the *stored*
//! commit object — the [`ObjectEnvelope`] wrapping this commit's full
//! canonical JSON, signature included. Including the signature is
//! deliberate: any tampering with any field — or with the signature —
//! changes both the [`ObjectId`] of the backing object and the
//! [`CommitId`], so an ID can never be made to point at modified content.
//!
//! Because the envelope's content hash **is** the commit ID's digest, the
//! two identifiers are bijective (`obj_<hex>` ⇄ `cmt_<hex>`); refs store
//! `CommitId`s and resolve directly to object-store entries without an
//! indirection table. See [`commit_object_id`] / [`Commit::commit_id`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vaultx_crypto::signature::{
    verify as verify_signature, SignatureBytes, SigningKeyPair, VerifyingPublicKey,
};
use vaultx_types::{CommitId, IdentityRef, ObjectId};

use crate::error::RepoError;
use crate::object::{ObjectEnvelope, ObjectType};

/// Version of the commit format written by this crate.
pub const COMMIT_FORMAT_VERSION: u16 = 1;

/// The exact bytes covered by a commit's Ed25519 signature: canonical JSON
/// of every [`Commit`] field except `signature`, serialized in declaration
/// order.
///
/// Kept private so callers cannot accidentally sign a divergent projection;
/// use [`Commit::sign_payload`].
#[derive(Serialize)]
struct SignableCommit<'a> {
    format: u16,
    parents: &'a [CommitId],
    manifest: &'a ObjectId,
    author: &'a IdentityRef,
    message: &'a str,
}

impl SignableCommit<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>, RepoError> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// An immutable, signed snapshot of manifest state pointing into the object
/// store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// Commit format version; currently always
    /// [`COMMIT_FORMAT_VERSION`] (=1).
    pub format: u16,
    /// Parent commits (empty for a root commit; multiple entries mark a
    /// merge). Order is significant for canonical encoding.
    pub parents: Vec<CommitId>,
    /// Object store ID of this commit's manifest.
    pub manifest: ObjectId,
    /// Who authored the change.
    pub author: IdentityRef,
    /// Free-form human-readable description. Never carries secret values.
    pub message: String,
    /// Detached Ed25519 signature over the signable core.
    pub signature: SignatureBytes,
}

impl Commit {
    /// Assembles an *unsigned* commit at the current format version.
    ///
    /// Use [`Commit::sign_with`] to produce a verifiable commit.
    #[must_use]
    pub fn new(
        parents: Vec<CommitId>,
        manifest: ObjectId,
        author: IdentityRef,
        message: impl Into<String>,
    ) -> Self {
        Self {
            format: COMMIT_FORMAT_VERSION,
            parents,
            manifest,
            author,
            message: message.into(),
            signature: SignatureBytes(Vec::new()),
        }
    }

    /// Canonical bytes of the signable core (commit without its signature).
    ///
    /// # Errors
    /// Propagates serialization failures as [`RepoError::Json`].
    pub fn sign_payload(&self) -> Result<Vec<u8>, RepoError> {
        let core = SignableCommit {
            format: self.format,
            parents: &self.parents,
            manifest: &self.manifest,
            author: &self.author,
            message: &self.message,
        };
        core.canonical_bytes()
    }
    /// Returns this commit with `signature` set by signing the signable
    /// core with `keypair`.
    ///
    /// # Errors
    /// Propagates payload-encoding failures as [`RepoError::Json`].
    pub fn sign_with(mut self, keypair: &SigningKeyPair) -> Result<Self, RepoError> {
        let payload = self.sign_payload()?;
        self.signature = keypair.sign(&payload);
        Ok(self)
    }

    /// Verifies this commit's signature against `public_key`.
    ///
    /// # Errors
    /// [`RepoError::SignatureInvalid`] when verification fails or the
    /// payload cannot be re-encoded.
    pub fn verify(&self, public_key: &VerifyingPublicKey) -> Result<(), RepoError> {
        let payload = self.sign_payload()?;
        verify_signature(public_key, &payload, &self.signature)
            .map_err(|_| RepoError::SignatureInvalid)
    }

    /// Content ID derived from the canonical bytes of this commit's stored
    /// object form (envelope-wrapped, signature included).
    ///
    /// # Errors
    /// Propagates serialization failures; ID-construction cannot fail for
    /// hex digests.
    pub fn commit_id(&self) -> Result<CommitId, RepoError> {
        let mut hasher = Sha256::new();
        hasher.update(storage_bytes(self)?);
        CommitId::parse(&format!(
            "{}{}",
            CommitId::PREFIX,
            hex::encode(hasher.finalize())
        ))
        .map_err(Into::into)
    }
}

/// The [`ObjectId`] under which `commit`'s envelope is content-addressed.
///
/// Shares its digest with [`Commit::commit_id`] — only the prefix differs
/// — which is what lets refs holding a [`CommitId`] resolve straight to an
/// object-store lookup.
///
/// # Errors
/// Propagates serialization failures.
pub fn commit_object_id(commit: &Commit) -> Result<ObjectId, RepoError> {
    let mut hasher = Sha256::new();
    hasher.update(storage_bytes(commit)?);
    Ok(ObjectId::parse(&format!(
        "{}{}",
        ObjectId::PREFIX,
        hex::encode(hasher.finalize())
    ))?)
}

/// The single source of truth for wrapping a commit into its typed storage
/// envelope. Both ID derivation ([`storage_bytes`]) and persistence
/// (history/repo layers) go through here, so stored bytes and hashed bytes
/// are identical by construction rather than by convention.
///
/// # Errors
/// Propagates serialization failures.
pub(crate) fn commit_envelope(commit: &Commit) -> Result<ObjectEnvelope, RepoError> {
    Ok(ObjectEnvelope::new(
        ObjectType::Commit,
        serde_json::to_vec(commit)?,
    ))
}

fn storage_bytes(commit: &Commit) -> Result<Vec<u8>, RepoError> {
    commit_envelope(commit)?.canonical_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultx_crypto::signature::VerifyingPublicKey as PubKey;

    fn fixture() -> Commit {
        Commit {
            format: COMMIT_FORMAT_VERSION,
            parents: vec![CommitId::parse("cmt_root").unwrap()],
            manifest: ObjectId::parse("obj_manifest").unwrap(),
            author: IdentityRef::parse("user:alice").unwrap(),
            message: "add DB_HOST".to_owned(),
            signature: SignatureBytes(vec![7; 64]),
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let pair = SigningKeyPair::generate();
        let public = PubKey::from_signing(&pair);
        let unsigned = Commit::new(
            Vec::new(),
            ObjectId::parse("obj_m").unwrap(),
            IdentityRef::parse("user:bob").unwrap(),
            "root commit",
        );
        let signed = unsigned.sign_with(&pair).unwrap();
        assert!(signed.verify(&public).is_ok());

        // Same signer, different key must fail.
        let stranger = SigningKeyPair::generate();
        assert!(matches!(
            signed.verify(&PubKey::from_signing(&stranger)),
            Err(RepoError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let pair = SigningKeyPair::generate();
        let public = PubKey::from_signing(&pair);
        let mut signed = Commit::new(
            Vec::new(),
            ObjectId::parse("obj_m").unwrap(),
            IdentityRef::parse("user:bob").unwrap(),
            "original",
        )
        .sign_with(&pair)
        .unwrap();

        signed.message = "tampered".to_owned();
        assert!(
            matches!(signed.verify(&public), Err(RepoError::SignatureInvalid)),
            "modified message must invalidate the signature"
        );
    }

    #[test]
    fn tampering_any_field_changes_commit_id() {
        let pair = SigningKeyPair::generate();
        let base = Commit {
            parents: vec![CommitId::parse("cmt_p1").unwrap()],
            ..fixture()
        }
        .sign_with(&pair)
        .unwrap();
        let base_id = base.commit_id().unwrap();

        let mut variant = base.clone();
        variant.parents.push(CommitId::parse("cmt_p2").unwrap());
        assert_ne!(variant.commit_id().unwrap(), base_id);

        let mut variant = base.clone();
        variant.manifest = ObjectId::parse("obj_other").unwrap();
        assert_ne!(variant.commit_id().unwrap(), base_id);

        let mut variant = base.clone();
        variant.author = IdentityRef::parse("user:mallory").unwrap();
        assert_ne!(variant.commit_id().unwrap(), base_id);

        let mut variant = base.clone();
        variant.message = "different".to_owned();
        assert_ne!(variant.commit_id().unwrap(), base_id);

        let mut variant = base.clone();
        variant.signature = SignatureBytes(vec![9; 64]);
        assert_ne!(variant.commit_id().unwrap(), base_id);

        // And flipping even one byte of the signature invalidates it.
        assert!(variant.verify(&PubKey::from_signing(&pair)).is_err());
    }

    #[test]
    fn sign_payload_excludes_signature_field() {
        let pair = SigningKeyPair::generate();
        let signed = fixture().sign_with(&pair).unwrap();

        let payload = String::from_utf8(signed.sign_payload().unwrap()).unwrap();
        assert!(!payload.contains("signature"), "payload was {payload}");
        for needle in [
            "\"format\":1",
            "\"parents\"",
            "\"manifest\"",
            "\"author\"",
            "\"message\"",
        ] {
            assert!(
                payload.contains(needle),
                "payload missing {needle}: {payload}"
            );
        }

        // Payload order follows declaration order.
        let fmt_pos = payload.find("\"format\"").unwrap();
        let msg_pos = payload.find("\"message\"").unwrap();
        assert!(fmt_pos < msg_pos);
    }

    #[test]
    fn commit_id_is_stable_across_serialization_round_trip() {
        let pair = SigningKeyPair::generate();
        let original = fixture().sign_with(&pair).unwrap();
        let id_before = original.commit_id().unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let restored: Commit = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, original);
        assert_eq!(restored.commit_id().unwrap(), id_before);
        assert!(id_before.as_str().starts_with("cmt_"));
        assert_eq!(id_before.as_str().len(), 4 + 64);
    }

    #[test]
    fn commit_id_and_object_id_share_the_same_digest() {
        let pair = SigningKeyPair::generate();
        let commit = fixture().sign_with(&pair).unwrap();

        let cid = commit.commit_id().unwrap();
        let oid = commit_object_id(&commit).unwrap();

        // Bijective prefixes over one shared digest: refs resolve directly
        // to object-store entries.
        assert_eq!(&cid.as_str()[4..], &oid.as_str()[4..]);
        assert_eq!(
            ObjectId::parse(&format!("obj_{}", &cid.as_str()[4..])).unwrap(),
            oid
        );
        assert_eq!(
            CommitId::parse(&format!("cmt_{}", &oid.as_str()[4..])).unwrap(),
            cid
        );
    }

    #[test]
    fn root_commit_has_no_parents_and_still_verifies() {
        let pair = SigningKeyPair::generate();
        let public = PubKey::from_signing(&pair);
        let root = Commit::new(
            Vec::new(),
            ObjectId::parse("obj_first").unwrap(),
            IdentityRef::parse("ci-bot").unwrap(),
            "",
        )
        .sign_with(&pair)
        .unwrap();
        assert!(root.parents.is_empty());
        assert!(root.verify(&public).is_ok());
    }

    #[test]
    fn merge_style_multi_parent_commits_are_deterministic() {
        let pair = SigningKeyPair::generate();
        let parents_a = vec![
            CommitId::parse("cmt_a").unwrap(),
            CommitId::parse("cmt_b").unwrap(),
        ];
        let parents_b = vec![
            CommitId::parse("cmt_b").unwrap(),
            CommitId::parse("cmt_a").unwrap(),
        ];
        let mk = |parents: Vec<CommitId>| {
            Commit::new(
                parents,
                ObjectId::parse("obj_m").unwrap(),
                IdentityRef::parse("user:x").unwrap(),
                "merge",
            )
            .sign_with(&pair)
            .unwrap()
        };
        // Parent ORDER matters for canonical bytes: swapped lists differ.
        assert_ne!(
            mk(parents_a.clone()).commit_id().unwrap(),
            mk(parents_b).commit_id().unwrap()
        );
        // Identical input yields identical ID twice.
        assert_eq!(
            mk(parents_a.clone()).commit_id().unwrap(),
            mk(parents_a).commit_id().unwrap()
        );
    }
}
