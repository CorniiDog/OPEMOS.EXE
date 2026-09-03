//! Inactive, private verifier capability for authenticated Core generation
//! snapshots. This module has no production verifier, process, keyring,
//! endpoint, transport, cache, activation, command, or UI wiring.

use crate::{
    core_contracts::reject_duplicate_contract_keys,
    core_generation_contracts::{
        DISCOVERY_MAX_BYTES, MANIFEST_MAX_BYTES, MAX_SIGNATURE_BYTES, OPENPGP_HASH_ALGORITHM_IDS,
    },
};
#[cfg(test)]
use crate::{
    core_generation_bootstrap::{
        expected_generation_authority, parse_bootstrap_policy, MAX_KEYRING_BYTES,
    },
    core_generation_contracts::{
        validate_discovery_bytes, validate_manifest_bytes, validate_openpgp_status, validate_pair,
        OpenPgpValidSignature, MAX_OPENPGP_STATUS_BYTES,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const MAX_EVIDENCE_BYTES: usize = 64 * 1024;

const EVIDENCE_KIND: &str = "opemos-userspace-lock-verifier-evidence";
const VERIFICATION_PROFILE: &str = "openpgp-detached-validsig-v1";
const KEYRING_FILENAME: &str = "opemos-userspace-lock-generations.gpg";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VerifierEvidenceRecord {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) verification_profile: String,
    pub(crate) policy_sha256: String,
    pub(crate) keyring_filename: String,
    pub(crate) keyring_sha256: String,
    pub(crate) primary_signing_fingerprint: String,
    pub(crate) documents: [VerifierEvidenceDocument; 2],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VerifierEvidenceDocument {
    pub(crate) role: String,
    pub(crate) payload_sha256: String,
    pub(crate) payload_size: u64,
    pub(crate) signature_sha256: String,
    pub(crate) signature_size: u64,
    pub(crate) signing_fingerprint: String,
    pub(crate) primary_signing_fingerprint: String,
    pub(crate) hash_algorithm_id: u32,
}

/// Opaque evidence produced only after this module binds its exact
/// policy/keyring snapshot and authenticated document bytes. There is
/// intentionally no public constructor or Deserialize implementation: caller
/// assertions and wire documents are never accepted as proof.
pub(crate) struct SnapshotBoundAuthenticationEvidence {
    record: VerifierEvidenceRecord,
    _seal: CapabilitySeal,
}

struct CapabilitySeal;

impl SnapshotBoundAuthenticationEvidence {
    pub(crate) fn record(&self) -> &VerifierEvidenceRecord {
        &self.record
    }
}

pub(crate) struct RequestPlanInputs<'a> {
    pub(crate) policy_payload: &'a [u8],
    pub(crate) discovery_payload: &'a [u8],
    pub(crate) discovery_signature: &'a [u8],
    pub(crate) manifest_payload: &'a [u8],
    pub(crate) manifest_signature: &'a [u8],
}

/// Parse a canonical audit record for diagnostics. This never returns or
/// recreates the verifier-owned capability required by request planning.
pub(crate) fn parse_verifier_evidence_record(
    payload: &[u8],
) -> Result<VerifierEvidenceRecord, String> {
    let record: VerifierEvidenceRecord =
        parse_canonical(payload, MAX_EVIDENCE_BYTES, "Core verifier evidence")?;
    validate_evidence_record(&record)?;
    Ok(record)
}

fn parse_canonical<T: DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    label: &str,
) -> Result<T, String> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(format!("{label} is empty or exceeds its size limit."));
    }
    reject_duplicate_contract_keys(bytes, label)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| format!("{label} is malformed."))?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("Could not canonicalize {label}: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!("{label} is not canonical JSON."));
    }
    serde_json::from_value(value).map_err(|_| format!("{label} is invalid."))
}

fn validate_evidence_record(record: &VerifierEvidenceRecord) -> Result<(), String> {
    if record.schema_version != 1
        || record.kind != EVIDENCE_KIND
        || record.status != "authenticated"
        || record.verification_profile != VERIFICATION_PROFILE
        || !lower_sha256(&record.policy_sha256)
        || record.keyring_filename != KEYRING_FILENAME
        || !lower_sha256(&record.keyring_sha256)
        || !upper_fingerprint(&record.primary_signing_fingerprint)
    {
        return Err("Verifier evidence identity is invalid.".into());
    }
    for (index, role) in ["discovery", "generation-manifest"].iter().enumerate() {
        let document = &record.documents[index];
        let maximum = if index == 0 {
            DISCOVERY_MAX_BYTES as u64
        } else {
            MANIFEST_MAX_BYTES as u64
        };
        if document.role != *role
            || !lower_sha256(&document.payload_sha256)
            || !(1..=maximum).contains(&document.payload_size)
            || !lower_sha256(&document.signature_sha256)
            || !(1..=MAX_SIGNATURE_BYTES).contains(&document.signature_size)
            || !upper_fingerprint(&document.signing_fingerprint)
            || document.primary_signing_fingerprint != record.primary_signing_fingerprint
            || !OPENPGP_HASH_ALGORITHM_IDS.contains(&document.hash_algorithm_id)
        {
            return Err("Verifier evidence document identity is invalid.".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_evidence_capability(
    evidence: &SnapshotBoundAuthenticationEvidence,
    inputs: &RequestPlanInputs<'_>,
) -> Result<(), String> {
    if evidence.record.policy_sha256 != sha256(inputs.policy_payload) {
        return Err("Verifier evidence belongs to another bootstrap policy.".into());
    }
    for (stored, (role, payload, signature)) in evidence.record.documents.iter().zip([
        (
            "discovery",
            inputs.discovery_payload,
            inputs.discovery_signature,
        ),
        (
            "generation-manifest",
            inputs.manifest_payload,
            inputs.manifest_signature,
        ),
    ]) {
        if stored.role != role
            || stored.payload_size != payload.len() as u64
            || stored.payload_sha256 != sha256(payload)
            || stored.signature_size != signature.len() as u64
            || stored.signature_sha256 != sha256(signature)
        {
            return Err("Verifier evidence belongs to different snapshots.".into());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) struct DetachedVerifierOutput {
    pub(crate) exit_status: i32,
    pub(crate) status: Vec<u8>,
}

#[cfg(test)]
pub(crate) fn verify_generation_snapshots<F>(
    inputs: &RequestPlanInputs<'_>,
    keyring_payload: &[u8],
    mut verify_detached: F,
) -> Result<SnapshotBoundAuthenticationEvidence, String>
where
    F: FnMut(&[u8], &[u8], &[u8], &str) -> Result<DetachedVerifierOutput, String>,
{
    let policy = parse_bootstrap_policy(inputs.policy_payload)?;
    let expected_authority = expected_generation_authority(&policy, inputs.policy_payload)?;
    let authority = &policy.authority;
    if keyring_payload.is_empty()
        || keyring_payload.len() > MAX_KEYRING_BYTES
        || sha256(keyring_payload) != authority.keyring_sha256
    {
        return Err("Verifier inputs differ from installed bootstrap authority.".into());
    }
    if inputs.discovery_payload.is_empty()
        || inputs.discovery_payload.len() > DISCOVERY_MAX_BYTES
        || inputs.manifest_payload.is_empty()
        || inputs.manifest_payload.len() > MANIFEST_MAX_BYTES
        || !(1..=MAX_SIGNATURE_BYTES as usize).contains(&inputs.discovery_signature.len())
        || !(1..=MAX_SIGNATURE_BYTES as usize).contains(&inputs.manifest_signature.len())
    {
        return Err("Document or detached signature snapshot is empty or excessive.".into());
    }

    let discovery_verified = verifier_result(
        &mut verify_detached,
        inputs.discovery_payload,
        inputs.discovery_signature,
        keyring_payload,
        &authority.primary_signing_fingerprint,
        "discovery",
    )?;
    let discovery = validate_discovery_bytes(inputs.discovery_payload)?;
    if discovery.authority != expected_authority {
        return Err("Verifier inputs differ from installed bootstrap authority.".into());
    }
    if discovery.generation.signature_size != inputs.manifest_signature.len() as u64
        || discovery.generation.signature_sha256 != sha256(inputs.manifest_signature)
    {
        return Err("Manifest signature differs from authenticated discovery.".into());
    }
    let manifest_verified = verifier_result(
        &mut verify_detached,
        inputs.manifest_payload,
        inputs.manifest_signature,
        keyring_payload,
        &authority.primary_signing_fingerprint,
        "generation-manifest",
    )?;
    let manifest = validate_manifest_bytes(inputs.manifest_payload)?;
    validate_pair(&discovery, &manifest)?;
    if !authority
        .allowed_hash_algorithm_ids
        .contains(&discovery_verified.hash_algorithm_id)
        || !authority
            .allowed_hash_algorithm_ids
            .contains(&manifest_verified.hash_algorithm_id)
    {
        return Err("Detached signature hash algorithm is not authorized.".into());
    }
    let record = VerifierEvidenceRecord {
        schema_version: 1,
        kind: EVIDENCE_KIND.into(),
        status: "authenticated".into(),
        verification_profile: VERIFICATION_PROFILE.into(),
        policy_sha256: sha256(inputs.policy_payload),
        keyring_filename: authority.keyring_filename.clone(),
        keyring_sha256: authority.keyring_sha256.clone(),
        primary_signing_fingerprint: authority.primary_signing_fingerprint.clone(),
        documents: [
            document_record(
                "discovery",
                inputs.discovery_payload,
                inputs.discovery_signature,
                &discovery_verified,
            ),
            document_record(
                "generation-manifest",
                inputs.manifest_payload,
                inputs.manifest_signature,
                &manifest_verified,
            ),
        ],
    };
    validate_evidence_record(&record)?;
    if canonical_bytes(&record)?.len() > MAX_EVIDENCE_BYTES {
        return Err("Verifier evidence is excessive.".into());
    }
    Ok(SnapshotBoundAuthenticationEvidence {
        record,
        _seal: CapabilitySeal,
    })
}

#[cfg(test)]
fn verifier_result<F>(
    verifier: &mut F,
    payload: &[u8],
    signature: &[u8],
    keyring: &[u8],
    primary: &str,
    role: &str,
) -> Result<OpenPgpValidSignature, String>
where
    F: FnMut(&[u8], &[u8], &[u8], &str) -> Result<DetachedVerifierOutput, String>,
{
    let output = verifier(payload, signature, keyring, role)
        .map_err(|_| "Detached signature verifier failed.".to_string())?;
    if output.exit_status != 0
        || output.status.is_empty()
        || output.status.len() > MAX_OPENPGP_STATUS_BYTES
    {
        return Err("Detached signature verifier did not report bounded success.".into());
    }
    validate_openpgp_status(&output.status, primary)
}

#[cfg(test)]
fn document_record(
    role: &str,
    payload: &[u8],
    signature: &[u8],
    verified: &OpenPgpValidSignature,
) -> VerifierEvidenceDocument {
    VerifierEvidenceDocument {
        role: role.into(),
        payload_sha256: sha256(payload),
        payload_size: payload.len() as u64,
        signature_sha256: sha256(signature),
        signature_size: signature.len() as u64,
        signing_fingerprint: verified.signing_fingerprint.clone(),
        primary_signing_fingerprint: verified.primary_fingerprint.clone(),
        hash_algorithm_id: verified.hash_algorithm_id,
    }
}

#[cfg(test)]
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("Could not encode verifier evidence: {error}"))?;
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("Could not encode verifier evidence: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn upper_fingerprint(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}
