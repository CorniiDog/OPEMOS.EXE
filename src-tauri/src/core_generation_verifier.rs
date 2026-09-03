//! Inactive, private verifier capability for authenticated Core generation
//! snapshots. This module has no production verifier, process, keyring,
//! endpoint, transport, cache, activation, command, or UI wiring.

use crate::{
    core_contracts::reject_duplicate_contract_keys,
    core_generation_bootstrap::BootstrapPolicy,
    core_generation_contracts::{
        GenerationAuthority, GenerationDiscovery, GenerationManifest, OpenPgpValidSignature,
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
        MAX_OPENPGP_STATUS_BYTES,
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
pub(crate) struct AuthenticatedGeneration {
    policy_payload: Vec<u8>,
    _keyring_payload: Vec<u8>,
    discovery_payload: Vec<u8>,
    discovery_signature: Vec<u8>,
    manifest_payload: Vec<u8>,
    manifest_signature: Vec<u8>,
    policy: BootstrapPolicy,
    authority: GenerationAuthority,
    discovery: GenerationDiscovery,
    manifest: GenerationManifest,
    _discovery_status: OpenPgpValidSignature,
    _manifest_status: OpenPgpValidSignature,
    record: VerifierEvidenceRecord,
    _seal: CapabilitySeal,
}

struct CapabilitySeal;

/// Compatibility name retained while request-plan callers migrate to the
/// richer authenticated generation capability. It remains non-deserializable.
pub(crate) type SnapshotBoundAuthenticationEvidence = AuthenticatedGeneration;

impl AuthenticatedGeneration {
    pub(crate) fn record(&self) -> &VerifierEvidenceRecord {
        &self.record
    }

    pub(crate) fn request_plan_inputs(&self) -> RequestPlanInputs<'_> {
        RequestPlanInputs {
            policy_payload: &self.policy_payload,
            discovery_payload: &self.discovery_payload,
            discovery_signature: &self.discovery_signature,
            manifest_payload: &self.manifest_payload,
            manifest_signature: &self.manifest_signature,
        }
    }

    pub(crate) fn policy(&self) -> &BootstrapPolicy {
        &self.policy
    }

    pub(crate) fn authority(&self) -> &GenerationAuthority {
        &self.authority
    }

    pub(crate) fn discovery(&self) -> &GenerationDiscovery {
        &self.discovery
    }

    pub(crate) fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }

    #[cfg(test)]
    pub(crate) fn canonical_evidence_bytes(&self) -> Result<Vec<u8>, String> {
        canonical_bytes(&self.record)
    }
}

pub(crate) struct PendingAuthenticatedDiscovery {
    policy_payload: Vec<u8>,
    keyring_payload: Vec<u8>,
    discovery_payload: Vec<u8>,
    discovery_signature: Vec<u8>,
    policy: BootstrapPolicy,
    authority: GenerationAuthority,
    discovery: GenerationDiscovery,
    discovery_status: OpenPgpValidSignature,
    _seal: CapabilitySeal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestRequestIdentity {
    filename: String,
    size: u64,
    sha256: String,
    signature_filename: String,
    signature_size: u64,
    signature_sha256: String,
}

impl PendingAuthenticatedDiscovery {
    pub(crate) fn manifest_request(&self) -> ManifestRequestIdentity {
        ManifestRequestIdentity {
            filename: self.discovery.generation.manifest_filename.clone(),
            size: self.discovery.generation.manifest_size,
            sha256: self.discovery.generation.manifest_sha256.clone(),
            signature_filename: self.discovery.generation.signature_filename.clone(),
            signature_size: self.discovery.generation.signature_size,
            signature_sha256: self.discovery.generation.signature_sha256.clone(),
        }
    }
}

impl ManifestRequestIdentity {
    pub(crate) fn filename(&self) -> &str {
        &self.filename
    }
    pub(crate) fn size(&self) -> u64 {
        self.size
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
    pub(crate) fn signature_filename(&self) -> &str {
        &self.signature_filename
    }
    pub(crate) fn signature_size(&self) -> u64 {
        self.signature_size
    }
    pub(crate) fn signature_sha256(&self) -> &str {
        &self.signature_sha256
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
pub(crate) fn authenticate_discovery_snapshot<F, C>(
    policy_payload: &[u8],
    keyring_payload: &[u8],
    discovery_payload: &[u8],
    discovery_signature: &[u8],
    cancelled: &C,
    mut verify_detached: F,
) -> Result<PendingAuthenticatedDiscovery, String>
where
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    let policy = parse_bootstrap_policy(policy_payload)?;
    let authority = expected_generation_authority(&policy, policy_payload)?;
    if keyring_payload.is_empty()
        || keyring_payload.len() > MAX_KEYRING_BYTES
        || sha256(keyring_payload) != policy.authority.keyring_sha256
    {
        return Err("Verifier inputs differ from installed bootstrap authority.".into());
    }
    if discovery_payload.is_empty()
        || discovery_payload.len() > DISCOVERY_MAX_BYTES
        || !(1..=MAX_SIGNATURE_BYTES as usize).contains(&discovery_signature.len())
    {
        return Err("Discovery or detached signature snapshot is empty or excessive.".into());
    }
    let discovery_status = verifier_result(
        &mut verify_detached,
        discovery_payload,
        discovery_signature,
        keyring_payload,
        &policy.authority.primary_signing_fingerprint,
        "discovery",
        cancelled,
    )?;
    if !policy
        .authority
        .allowed_hash_algorithm_ids
        .contains(&discovery_status.hash_algorithm_id)
    {
        return Err("Detached signature hash algorithm is not authorized.".into());
    }
    let discovery = validate_discovery_bytes(discovery_payload)?;
    if discovery.authority != authority {
        return Err("Verifier inputs differ from installed bootstrap authority.".into());
    }
    Ok(PendingAuthenticatedDiscovery {
        policy_payload: policy_payload.to_vec(),
        keyring_payload: keyring_payload.to_vec(),
        discovery_payload: discovery_payload.to_vec(),
        discovery_signature: discovery_signature.to_vec(),
        policy,
        authority,
        discovery,
        discovery_status,
        _seal: CapabilitySeal,
    })
}

#[cfg(test)]
pub(crate) fn authenticate_manifest_snapshot<F, C>(
    pending: PendingAuthenticatedDiscovery,
    manifest_payload: &[u8],
    manifest_signature: &[u8],
    cancelled: &C,
    mut verify_detached: F,
) -> Result<AuthenticatedGeneration, String>
where
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    if manifest_payload.is_empty()
        || manifest_payload.len() > MANIFEST_MAX_BYTES
        || !(1..=MAX_SIGNATURE_BYTES as usize).contains(&manifest_signature.len())
        || pending.discovery.generation.manifest_size != manifest_payload.len() as u64
        || pending.discovery.generation.manifest_sha256 != sha256(manifest_payload)
        || pending.discovery.generation.signature_size != manifest_signature.len() as u64
        || pending.discovery.generation.signature_sha256 != sha256(manifest_signature)
    {
        return Err("Manifest snapshots differ from authenticated discovery.".into());
    }
    let manifest_status = verifier_result(
        &mut verify_detached,
        manifest_payload,
        manifest_signature,
        &pending.keyring_payload,
        &pending.policy.authority.primary_signing_fingerprint,
        "generation-manifest",
        cancelled,
    )?;
    if !pending
        .policy
        .authority
        .allowed_hash_algorithm_ids
        .contains(&manifest_status.hash_algorithm_id)
    {
        return Err("Detached signature hash algorithm is not authorized.".into());
    }
    let manifest = validate_manifest_bytes(manifest_payload)?;
    validate_pair(&pending.discovery, &manifest)?;
    let record = VerifierEvidenceRecord {
        schema_version: 1,
        kind: EVIDENCE_KIND.into(),
        status: "authenticated".into(),
        verification_profile: VERIFICATION_PROFILE.into(),
        policy_sha256: sha256(&pending.policy_payload),
        keyring_filename: pending.policy.authority.keyring_filename.clone(),
        keyring_sha256: pending.policy.authority.keyring_sha256.clone(),
        primary_signing_fingerprint: pending.policy.authority.primary_signing_fingerprint.clone(),
        documents: [
            document_record(
                "discovery",
                &pending.discovery_payload,
                &pending.discovery_signature,
                &pending.discovery_status,
            ),
            document_record(
                "generation-manifest",
                manifest_payload,
                manifest_signature,
                &manifest_status,
            ),
        ],
    };
    validate_evidence_record(&record)?;
    if canonical_bytes(&record)?.len() > MAX_EVIDENCE_BYTES {
        return Err("Verifier evidence is excessive.".into());
    }
    Ok(AuthenticatedGeneration {
        policy_payload: pending.policy_payload,
        _keyring_payload: pending.keyring_payload,
        discovery_payload: pending.discovery_payload,
        discovery_signature: pending.discovery_signature,
        manifest_payload: manifest_payload.to_vec(),
        manifest_signature: manifest_signature.to_vec(),
        policy: pending.policy,
        authority: pending.authority,
        discovery: pending.discovery,
        manifest,
        _discovery_status: pending.discovery_status,
        _manifest_status: manifest_status,
        record,
        _seal: CapabilitySeal,
    })
}

#[cfg(test)]
pub(crate) struct DetachedVerifierOutput {
    pub(crate) exit_status: i32,
    pub(crate) status: Vec<u8>,
}

#[cfg(test)]
pub(crate) fn verify_generation_snapshots<F, C>(
    inputs: &RequestPlanInputs<'_>,
    keyring_payload: &[u8],
    cancelled: &C,
    mut verify_detached: F,
) -> Result<SnapshotBoundAuthenticationEvidence, String>
where
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    let pending = authenticate_discovery_snapshot(
        inputs.policy_payload,
        keyring_payload,
        inputs.discovery_payload,
        inputs.discovery_signature,
        cancelled,
        &mut verify_detached,
    )?;
    authenticate_manifest_snapshot(
        pending,
        inputs.manifest_payload,
        inputs.manifest_signature,
        cancelled,
        &mut verify_detached,
    )
}

#[cfg(test)]
fn verifier_result<F, C>(
    verifier: &mut F,
    payload: &[u8],
    signature: &[u8],
    keyring: &[u8],
    primary: &str,
    role: &str,
    cancelled: &C,
) -> Result<OpenPgpValidSignature, String>
where
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    if cancelled() {
        return Err("Detached signature verification was cancelled.".into());
    }
    let output = verifier(payload, signature, keyring, role, cancelled)
        .map_err(|_| "Detached signature verifier failed.".to_string())?;
    if cancelled() {
        return Err("Detached signature verification was cancelled.".into());
    }
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
