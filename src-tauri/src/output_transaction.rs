//! Inactive descriptor-bound output transaction.
//!
//! The transaction reserves exact source/output identities, stages an image and
//! its adjacent manifest with durable per-file receipts, and publishes the
//! image before the manifest. Recovery may advance only fully receipted exact
//! bytes. Ambiguous or mismatched residue is preserved for a future explicit
//! maintenance UI; production export is intentionally not wired to this yet.

use super::*;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};

const RECORD_LIMIT: u64 = 8 * 1024;
const RECEIPT_LIMIT: u64 = 8 * 1024;
const COPY_CHUNK: usize = 64 * 1024;
const RECOVERY_REQUIRED: &str = "OUTPUT_RESERVATION_RECOVERY_REQUIRED";
const RECORD_MALFORMED: &str = "OUTPUT_RESERVATION_RECORD_MALFORMED";
const RECORD_OVERSIZED: &str = "OUTPUT_RESERVATION_RECORD_OVERSIZED";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl FileIdentity {
    fn of(value: &fs::Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            size: value.len(),
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
            mtime: value.mtime(),
            mtime_ns: value.mtime_nsec(),
            ctime: value.ctime(),
            ctime_ns: value.ctime_nsec(),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OutputRecord {
    schema_version: u32,
    operation_id: String,
    phase: OutputPhase,
    source_identity: FileIdentity,
    source_sha256: String,
    lock_identity: FileIdentity,
    parent_identity: FileIdentity,
    output_basename: String,
    manifest_basename: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum OutputPhase {
    Reserved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicationFileKind {
    Image,
    Manifest,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PublicationReceipt {
    schema_version: u32,
    operation_id: String,
    phase: PublicationPhase,
    kind: PublicationFileKind,
    reservation_sha256: String,
    previous_receipt_sha256: Option<String>,
    parent_identity: FileIdentity,
    stage_basename: String,
    final_basename: String,
    file_identity: FileIdentity,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicationPhase {
    ImageStaged,
    ManifestStaged,
    ImagePublished,
    ManifestPublished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationRecovery {
    Reserved,
    ImageStaged,
    ReadyToPublish,
    ImagePublished,
    Complete,
}

#[derive(Debug)]
struct PublicationNames {
    image_stage: CString,
    manifest_stage: CString,
    image_receipt: CString,
    manifest_receipt: CString,
}

#[derive(Debug)]
struct ArtifactCapability {
    file: File,
    identity: FileIdentity,
    sha256: String,
    stage: CString,
    final_name: CString,
    kind: PublicationFileKind,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AdjacentOutputManifest<'a> {
    schema_version: u32,
    image_sha256: &'a str,
    image_size: u64,
    source_sha256: &'a str,
}

#[derive(Debug)]
struct PinnedDirectory {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
}

impl PinnedDirectory {
    fn open(path: &Path, private: bool) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| format!("Could not open directory safely: {e}"))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        validate_directory(&metadata, private)?;
        let result = Self {
            file,
            path: path.to_path_buf(),
            identity: FileIdentity::of(&metadata),
        };
        result.verify(private)?;
        Ok(result)
    }

    fn verify(&self, private: bool) -> Result<(), String> {
        let fd = self.file.metadata().map_err(|e| e.to_string())?;
        let path = fs::symlink_metadata(&self.path)
            .map_err(|e| format!("Pinned directory disappeared: {e}"))?;
        validate_directory(&fd, private)?;
        validate_directory(&path, private)?;
        if !same_directory_identity(&FileIdentity::of(&fd), &self.identity)
            || !same_directory_identity(&FileIdentity::of(&path), &self.identity)
        {
            return Err("PINNED_DIRECTORY_CHANGED".into());
        }
        Ok(())
    }

    fn openat(&self, name: &CStr, flags: i32, mode: u32) -> Result<File, io::Error> {
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn rebind(&self, name: &CStr, expected: &FileIdentity, error: &str) -> Result<(), String> {
        let reopened = self
            .openat(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|_| error.to_string())?;
        let metadata = reopened.metadata().map_err(|_| error.to_string())?;
        if FileIdentity::of(&metadata) != *expected {
            return Err(error.into());
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LockCapability {
    root: PinnedDirectory,
    file: File,
    basename: CString,
    identity: FileIdentity,
}

impl LockCapability {
    fn acquire(root_path: &Path, key: &[u8]) -> Result<Self, String> {
        let root = PinnedDirectory::open(root_path, true)?;
        let basename = strict_basename(&format!("reservation-{:x}.lock", Sha256::digest(key)))?;
        let file = root
            .openat(
                &basename,
                libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
                0o600,
            )
            .map_err(|e| format!("Could not open reservation lock: {e}"))?;
        let mut metadata = file.metadata().map_err(|e| e.to_string())?;
        validate_owned_empty_regular(&metadata, "LOCK_METADATA_UNSAFE")?;
        if metadata.mode() & 0o7777 != 0o600 {
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err("LOCK_MODE_REPAIR_FAILED".into());
            }
            metadata = file.metadata().map_err(|e| e.to_string())?;
        }
        validate_lock(&metadata)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                Err("RESERVATION_ALREADY_HELD".into())
            } else {
                Err("RESERVATION_LOCK_FAILED".into())
            };
        }
        let result = Self {
            root,
            file,
            basename,
            identity: FileIdentity::of(&metadata),
        };
        result.verify()?;
        Ok(result)
    }

    fn verify(&self) -> Result<(), String> {
        self.root.verify(true)?;
        let fd = self.file.metadata().map_err(|e| e.to_string())?;
        let path = self
            .root
            .openat(&self.basename, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|_| "RESERVATION_LOCK_CHANGED".to_string())?;
        let path = path.metadata().map_err(|e| e.to_string())?;
        validate_lock(&fd)?;
        validate_lock(&path)?;
        if FileIdentity::of(&fd) != self.identity || FileIdentity::of(&path) != self.identity {
            return Err("RESERVATION_LOCK_CHANGED".into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct SourceReservation {
    lock: LockCapability,
    parent: PinnedDirectory,
    basename: CString,
    source: File,
    identity: FileIdentity,
    sha256: String,
}

impl SourceReservation {
    pub(crate) fn acquire(root: &Path, source_path: &Path) -> Result<Self, String> {
        let (parent_path, basename) = split_path(source_path)?;
        let parent = PinnedDirectory::open(&parent_path, false)?;
        let source = parent
            .openat(&basename, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|e| format!("Could not open selected source: {e}"))?;
        let metadata = source.metadata().map_err(|e| e.to_string())?;
        validate_source(&metadata)?;
        let identity = FileIdentity::of(&metadata);
        let sha256 = hash_fd(&source, metadata.len())?;
        let mut key = b"source\0".to_vec();
        key.extend_from_slice(&parent.identity.device.to_le_bytes());
        key.extend_from_slice(&parent.identity.inode.to_le_bytes());
        key.extend_from_slice(basename.as_bytes());
        let result = Self {
            lock: LockCapability::acquire(root, &key)?,
            parent,
            basename,
            source,
            identity,
            sha256,
        };
        result.verify()?;
        Ok(result)
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        self.lock.verify()?;
        self.parent.verify(false)?;
        let fd = self.source.metadata().map_err(|e| e.to_string())?;
        let path = self
            .parent
            .openat(&self.basename, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|_| "SOURCE_RESERVATION_CHANGED".to_string())?;
        let path_metadata = path.metadata().map_err(|e| e.to_string())?;
        validate_source(&fd)?;
        validate_source(&path_metadata)?;
        if FileIdentity::of(&fd) != self.identity
            || FileIdentity::of(&path_metadata) != self.identity
            || hash_fd(&self.source, self.identity.size)? != self.sha256
            || hash_fd(&path, self.identity.size)? != self.sha256
        {
            return Err("SOURCE_RESERVATION_CHANGED".into());
        }
        self.parent
            .rebind(&self.basename, &self.identity, "SOURCE_RESERVATION_CHANGED")?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct OutputReservation {
    lock: LockCapability,
    parent: PinnedDirectory,
    output: CString,
    manifest: CString,
    record: CString,
    operation_id: String,
    source_identity: FileIdentity,
    source_sha256: String,
    record_parent_identity: FileIdentity,
}

impl OutputReservation {
    pub(crate) fn acquire(
        root: &Path,
        source: &SourceReservation,
        output_path: &Path,
    ) -> Result<Self, String> {
        source.verify()?;
        let (parent_path, output) = split_path(output_path)?;
        let parent = PinnedDirectory::open(&parent_path, false)?;
        let manifest = strict_basename(&format!(
            "{}.manifest.json",
            output.to_str().map_err(|_| "OUTPUT_BASENAME_UTF8")?
        ))?;
        ensure_absent(&parent, &output, "OUTPUT")?;
        ensure_absent(&parent, &manifest, "MANIFEST")?;
        let lock = LockCapability::acquire(root, &output_lock_key(&parent, &output))?;
        let stem = lock
            .basename
            .to_str()
            .map_err(|_| "LOCK_BASENAME_UTF8")?
            .strip_suffix(".lock")
            .ok_or("LOCK_BASENAME_INVALID")?;
        let record = strict_basename(&format!("{stem}.record"))?;
        inspect_record(&lock.root, &record)?;
        let operation_id = new_operation_id(&source.sha256, &parent.identity, output.as_bytes())?;
        let record_parent_identity = parent.identity;
        let mut result = Self {
            lock,
            parent,
            output,
            manifest,
            record,
            operation_id,
            source_identity: source.identity,
            source_sha256: source.sha256.clone(),
            record_parent_identity,
        };
        result.create_record()?;
        result.verify()?;
        Ok(result)
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        self.lock.verify()?;
        self.parent.verify(false)?;
        ensure_absent(&self.parent, &self.output, "OUTPUT")?;
        ensure_absent(&self.parent, &self.manifest, "MANIFEST")?;
        if read_record(&self.lock.root, &self.record)? != self.value() {
            return Err("OUTPUT_RESERVATION_RECORD_CHANGED".into());
        }
        Ok(())
    }

    fn value(&self) -> OutputRecord {
        OutputRecord {
            schema_version: 2,
            operation_id: self.operation_id.clone(),
            phase: OutputPhase::Reserved,
            source_identity: self.source_identity,
            source_sha256: self.source_sha256.clone(),
            lock_identity: self.lock.identity,
            parent_identity: self.record_parent_identity,
            output_basename: self.output.to_string_lossy().into_owned(),
            manifest_basename: self.manifest.to_string_lossy().into_owned(),
        }
    }

    fn create_record(&mut self) -> Result<(), String> {
        self.lock.verify()?;
        let mut bytes = serde_json::to_vec(&self.value()).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let mut file = self
            .lock
            .root
            .openat(
                &self.record,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
            .map_err(|e| format!("Could not create durable reservation: {e}"))?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err("RECORD_MODE_REPAIR_FAILED".into());
        }
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        let identity = FileIdentity::of(&file.metadata().map_err(|e| e.to_string())?);
        self.lock
            .root
            .rebind(&self.record, &identity, "OUTPUT_RESERVATION_RECORD_CHANGED")?;
        self.lock.root.file.sync_all().map_err(|e| e.to_string())?;
        self.lock
            .root
            .rebind(&self.record, &identity, "OUTPUT_RESERVATION_RECORD_CHANGED")?;
        self.lock.verify()
    }

    fn names(&self) -> Result<PublicationNames, String> {
        Ok(PublicationNames {
            image_stage: strict_basename(&format!(".opemos-{}.image.stage", self.operation_id))?,
            manifest_stage: strict_basename(&format!(
                ".opemos-{}.manifest.stage",
                self.operation_id
            ))?,
            image_receipt: strict_basename(&format!(
                "publication-{}.01-image-staged.receipt",
                self.operation_id
            ))?,
            manifest_receipt: strict_basename(&format!(
                "publication-{}.02-manifest-staged.receipt",
                self.operation_id
            ))?,
        })
    }

    fn published_receipt(&self, index: u8, label: &str) -> Result<CString, String> {
        strict_basename(&format!(
            "publication-{}.{index:02}-{label}.receipt",
            self.operation_id
        ))
    }

    fn reservation_sha256(&self) -> Result<String, String> {
        canonical_sha256(&self.value())
    }

    fn reopen(root: &Path, source: &SourceReservation, output_path: &Path) -> Result<Self, String> {
        source.verify()?;
        let (parent_path, output) = split_path(output_path)?;
        let parent = PinnedDirectory::open(&parent_path, false)?;
        let manifest = strict_basename(&format!(
            "{}.manifest.json",
            output.to_str().map_err(|_| "OUTPUT_BASENAME_UTF8")?
        ))?;
        let lock = LockCapability::acquire(root, &output_lock_key(&parent, &output))?;
        let stem = lock
            .basename
            .to_str()
            .map_err(|_| "LOCK_BASENAME_UTF8")?
            .strip_suffix(".lock")
            .ok_or("LOCK_BASENAME_INVALID")?;
        let record = strict_basename(&format!("{stem}.record"))?;
        let value = read_record(&lock.root, &record)?;
        if value.source_identity != source.identity
            || value.source_sha256 != source.sha256
            || value.lock_identity != lock.identity
            || !same_directory_identity(&value.parent_identity, &parent.identity)
            || value.output_basename != output.to_string_lossy()
            || value.manifest_basename != manifest.to_string_lossy()
        {
            return Err(format!(
                "{RECOVERY_REQUIRED}: reservation identity mismatch"
            ));
        }
        let result = Self {
            lock,
            parent,
            output,
            manifest,
            record,
            operation_id: value.operation_id,
            source_identity: source.identity,
            source_sha256: source.sha256.clone(),
            record_parent_identity: value.parent_identity,
        };
        result.verify_guards(source)?;
        Ok(result)
    }

    fn verify_guards(&self, source: &SourceReservation) -> Result<(), String> {
        source.verify()?;
        self.lock.verify()?;
        self.parent.verify(false)?;
        if read_record(&self.lock.root, &self.record)? != self.value() {
            return Err("OUTPUT_RESERVATION_RECORD_CHANGED".into());
        }
        Ok(())
    }

    fn publish_bytes_with_hook(
        &self,
        source: &SourceReservation,
        image: &[u8],
        mut hook: impl FnMut(&'static str) -> Result<(), String>,
    ) -> Result<PublicationRecovery, String> {
        self.verify_guards(source)?;
        if image.is_empty() {
            return Err("OUTPUT_IMAGE_EMPTY".into());
        }
        let image_sha256 = bytes_sha256(image);
        let manifest = canonical_json(&AdjacentOutputManifest {
            schema_version: 1,
            image_sha256: &image_sha256,
            image_size: image.len() as u64,
            source_sha256: &self.source_sha256,
        })?;
        let names = self.names()?;
        let reservation_sha256 = self.reservation_sha256()?;
        let image_capability = self.ensure_staged(
            source,
            PublicationFileKind::Image,
            image,
            &names.image_stage,
            &self.output,
            &names.image_receipt,
            None,
            &reservation_sha256,
            &mut hook,
        )?;
        let image_receipt_sha = receipt_sha256(&self.lock.root, &names.image_receipt)?;
        let manifest_capability = self.ensure_staged(
            source,
            PublicationFileKind::Manifest,
            &manifest,
            &names.manifest_stage,
            &self.manifest,
            &names.manifest_receipt,
            Some(&image_receipt_sha),
            &reservation_sha256,
            &mut hook,
        )?;
        let manifest_receipt_sha = receipt_sha256(&self.lock.root, &names.manifest_receipt)?;
        let image_published = self.published_receipt(3, "image-published")?;
        self.publish_artifact(
            source,
            image_capability,
            &image_published,
            PublicationPhase::ImagePublished,
            &manifest_receipt_sha,
            &reservation_sha256,
            "image",
            &mut hook,
        )?;
        let image_published_sha = receipt_sha256(&self.lock.root, &image_published)?;
        let manifest_published = self.published_receipt(4, "manifest-published")?;
        self.publish_artifact(
            source,
            manifest_capability,
            &manifest_published,
            PublicationPhase::ManifestPublished,
            &image_published_sha,
            &reservation_sha256,
            "manifest",
            &mut hook,
        )?;
        self.verify_guards(source)?;
        self.verify_image_predecessor(&reservation_sha256)?;
        let manifest_published_receipt = read_receipt(&self.lock.root, &manifest_published)?;
        validate_receipt_chain(
            &manifest_published_receipt,
            PublicationFileKind::Manifest,
            PublicationPhase::ManifestPublished,
            &self.operation_id,
            &reservation_sha256,
            Some(&image_published_sha),
            &self.parent.identity,
            &names.manifest_stage,
            &self.manifest,
        )?;
        self.verify_published_artifact(&manifest_published_receipt, &self.manifest)?;
        self.verify_guards(source)?;
        self.verify_complete_pair(image, &manifest)
            .map(|()| PublicationRecovery::Complete)
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_staged(
        &self,
        source: &SourceReservation,
        kind: PublicationFileKind,
        bytes: &[u8],
        stage: &CString,
        final_name: &CString,
        receipt_name: &CString,
        previous_receipt_sha256: Option<&str>,
        reservation_sha256: &str,
        hook: &mut impl FnMut(&'static str) -> Result<(), String>,
    ) -> Result<ArtifactCapability, String> {
        if let Some(receipt) = receipt_if_present(&self.lock.root, receipt_name)? {
            validate_receipt_chain(
                &receipt,
                kind,
                PublicationPhase::from_staged_kind(kind),
                &self.operation_id,
                reservation_sha256,
                previous_receipt_sha256,
                &self.parent.identity,
                stage,
                final_name,
            )?;
            return self.open_exact_artifact(stage, final_name, &receipt, bytes);
        }
        ensure_absent(&self.parent, stage, "STAGE")?;
        ensure_absent(&self.parent, final_name, "FINAL")?;
        self.verify_guards(source)?;
        let mut file = self
            .parent
            .openat(
                stage,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
                0o600,
            )
            .map_err(map_stage_create_error)?;
        let cleanup = |file: &File| cleanup_unreceipted(&self.parent, stage, file);
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            cleanup(&file)?;
            return Err("OUTPUT_STAGE_MODE_FAILED".into());
        }
        if let Err(error) = hook(match kind {
            PublicationFileKind::Image => "image-stage-created",
            PublicationFileKind::Manifest => "manifest-stage-created",
        }) {
            cleanup(&file)?;
            return Err(error);
        }
        for chunk in bytes.chunks(COPY_CHUNK) {
            if let Err(error) = file.write_all(chunk) {
                cleanup(&file)?;
                return Err(map_write_error(error));
            }
            if let Err(error) = hook(match kind {
                PublicationFileKind::Image => "image-stage-written",
                PublicationFileKind::Manifest => "manifest-stage-written",
            }) {
                cleanup(&file)?;
                return Err(error);
            }
        }
        if let Err(error) = file.sync_all() {
            cleanup(&file)?;
            return Err(map_write_error(error));
        }
        if let Err(error) = hook(match kind {
            PublicationFileKind::Image => "image-stage-synced",
            PublicationFileKind::Manifest => "manifest-stage-synced",
        }) {
            cleanup(&file)?;
            return Err(error);
        }
        self.verify_guards(source)?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        validate_artifact(&metadata)?;
        let identity = FileIdentity::of(&metadata);
        self.parent
            .rebind(stage, &identity, "OUTPUT_STAGE_CHANGED")?;
        let sha256 = hash_fd(&file, identity.size)?;
        if identity.size != bytes.len() as u64 || sha256 != bytes_sha256(bytes) {
            return Err("OUTPUT_STAGE_CHANGED".into());
        }
        let receipt = PublicationReceipt {
            schema_version: 1,
            operation_id: self.operation_id.clone(),
            phase: PublicationPhase::from_staged_kind(kind),
            kind,
            reservation_sha256: reservation_sha256.to_string(),
            previous_receipt_sha256: previous_receipt_sha256.map(str::to_string),
            parent_identity: self.parent.identity,
            stage_basename: stage.to_string_lossy().into_owned(),
            final_basename: final_name.to_string_lossy().into_owned(),
            file_identity: identity,
            sha256: sha256.clone(),
        };
        create_receipt(&self.lock.root, receipt_name, &receipt)?;
        hook(match kind {
            PublicationFileKind::Image => "image-receipt-synced",
            PublicationFileKind::Manifest => "manifest-receipt-synced",
        })?;
        self.verify_guards(source)?;
        Ok(ArtifactCapability {
            file,
            identity,
            sha256,
            stage: stage.clone(),
            final_name: final_name.clone(),
            kind,
        })
    }

    fn open_exact_artifact(
        &self,
        stage: &CString,
        final_name: &CString,
        receipt: &PublicationReceipt,
        expected: &[u8],
    ) -> Result<ArtifactCapability, String> {
        let stage_result = self
            .parent
            .openat(stage, libc::O_RDWR | libc::O_NONBLOCK, 0);
        let final_result = self
            .parent
            .openat(final_name, libc::O_RDONLY | libc::O_NONBLOCK, 0);
        let (file, observed_name) = match (stage_result, final_result) {
            (Ok(_), Ok(_)) => {
                return Err(format!("{RECOVERY_REQUIRED}: artifact collision"));
            }
            (Ok(file), Err(error)) if error.kind() == io::ErrorKind::NotFound => (file, stage),
            (Err(error), Ok(file)) if error.kind() == io::ErrorKind::NotFound => (file, final_name),
            (Err(stage_error), Err(final_error))
                if stage_error.kind() == io::ErrorKind::NotFound
                    && final_error.kind() == io::ErrorKind::NotFound =>
            {
                return Err(format!("{RECOVERY_REQUIRED}: receipted artifact missing"));
            }
            _ => return Err(format!("{RECOVERY_REQUIRED}: unsafe staged artifact")),
        };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        validate_artifact(&metadata)?;
        let identity = FileIdentity::of(&metadata);
        if !same_artifact_identity(&identity, &receipt.file_identity)
            || identity.size != expected.len() as u64
            || receipt.sha256 != bytes_sha256(expected)
            || hash_fd(&file, identity.size)? != receipt.sha256
        {
            return Err(format!("{RECOVERY_REQUIRED}: artifact mismatch"));
        }
        self.parent
            .rebind(observed_name, &identity, "OUTPUT_ARTIFACT_CHANGED")?;
        Ok(ArtifactCapability {
            file,
            identity,
            sha256: receipt.sha256.clone(),
            stage: stage.clone(),
            final_name: final_name.clone(),
            kind: receipt.kind,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_artifact(
        &self,
        source: &SourceReservation,
        mut artifact: ArtifactCapability,
        published_receipt_name: &CString,
        phase: PublicationPhase,
        previous_receipt_sha256: &str,
        reservation_sha256: &str,
        label: &'static str,
        hook: &mut impl FnMut(&'static str) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(receipt) = receipt_if_present(&self.lock.root, published_receipt_name)? {
            validate_receipt_chain(
                &receipt,
                artifact.kind,
                phase,
                &self.operation_id,
                reservation_sha256,
                Some(previous_receipt_sha256),
                &self.parent.identity,
                &artifact.stage,
                &artifact.final_name,
            )?;
            self.verify_published_artifact(&receipt, &artifact.final_name)?;
            return Ok(());
        }
        self.verify_guards(source)?;
        let stage_exists = self
            .parent
            .openat(&artifact.stage, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .is_ok();
        let final_exists = self
            .parent
            .openat(&artifact.final_name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .is_ok();
        if stage_exists && final_exists {
            return Err(format!("{RECOVERY_REQUIRED}: publication collision"));
        }
        if stage_exists {
            self.parent.rebind(
                &artifact.stage,
                &artifact.identity,
                "OUTPUT_ARTIFACT_CHANGED",
            )?;
            hook(if label == "image" {
                "before-image-rename"
            } else {
                "before-manifest-rename"
            })?;
            self.verify_guards(source)?;
            if label == "manifest" {
                self.verify_image_predecessor(reservation_sha256)?;
            }
            rename_noreplace(&self.parent, &artifact.stage, &artifact.final_name)?;
            let _deferred_cancellation = hook(if label == "image" {
                "image-renamed"
            } else {
                "manifest-renamed"
            });
        } else if !final_exists {
            return Err(format!("{RECOVERY_REQUIRED}: publication artifact missing"));
        }
        artifact.file.sync_all().map_err(map_write_error)?;
        self.parent.file.sync_all().map_err(map_write_error)?;
        let _deferred_cancellation = hook(if label == "image" {
            "image-parent-synced"
        } else {
            "manifest-parent-synced"
        });
        self.verify_guards(source)?;
        let final_file = self
            .parent
            .openat(&artifact.final_name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|_| "OUTPUT_FINAL_CHANGED".to_string())?;
        let final_metadata = final_file.metadata().map_err(|e| e.to_string())?;
        validate_artifact(&final_metadata).map_err(|_| "OUTPUT_FINAL_CHANGED".to_string())?;
        let final_identity = FileIdentity::of(&final_metadata);
        if !same_artifact_identity(&final_identity, &artifact.identity)
            || hash_fd(&final_file, final_identity.size)? != artifact.sha256
        {
            return Err("OUTPUT_FINAL_CHANGED".into());
        }
        self.parent.rebind(
            &artifact.final_name,
            &final_identity,
            "OUTPUT_FINAL_CHANGED",
        )?;
        artifact.identity = final_identity;
        let receipt = PublicationReceipt {
            schema_version: 1,
            operation_id: self.operation_id.clone(),
            phase,
            kind: artifact.kind,
            reservation_sha256: reservation_sha256.to_string(),
            previous_receipt_sha256: Some(previous_receipt_sha256.to_string()),
            parent_identity: self.parent.identity,
            stage_basename: artifact.stage.to_string_lossy().into_owned(),
            final_basename: artifact.final_name.to_string_lossy().into_owned(),
            file_identity: final_identity,
            sha256: artifact.sha256,
        };
        create_receipt(&self.lock.root, published_receipt_name, &receipt)?;
        let _deferred_cancellation = hook(if label == "image" {
            "image-published-receipt-synced"
        } else {
            "manifest-published-receipt-synced"
        });
        Ok(())
    }

    fn verify_published_artifact(
        &self,
        receipt: &PublicationReceipt,
        final_name: &CString,
    ) -> Result<(), String> {
        let file = self
            .parent
            .openat(final_name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|_| format!("{RECOVERY_REQUIRED}: published artifact missing"))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        validate_artifact(&metadata)?;
        let identity = FileIdentity::of(&metadata);
        if identity != receipt.file_identity || hash_fd(&file, identity.size)? != receipt.sha256 {
            return Err(format!("{RECOVERY_REQUIRED}: published artifact mismatch"));
        }
        self.parent
            .rebind(final_name, &identity, "OUTPUT_FINAL_CHANGED")
    }

    fn verify_image_predecessor(&self, reservation_sha256: &str) -> Result<(), String> {
        let names = self.names()?;
        let image_staged_sha = receipt_sha256(&self.lock.root, &names.image_receipt)?;
        let manifest_staged = read_receipt(&self.lock.root, &names.manifest_receipt)?;
        validate_receipt_chain(
            &manifest_staged,
            PublicationFileKind::Manifest,
            PublicationPhase::ManifestStaged,
            &self.operation_id,
            reservation_sha256,
            Some(&image_staged_sha),
            &self.parent.identity,
            &names.manifest_stage,
            &self.manifest,
        )?;
        let manifest_staged_sha = canonical_sha256(&manifest_staged)?;
        let image_published_name = self.published_receipt(3, "image-published")?;
        let image_published = read_receipt(&self.lock.root, &image_published_name)?;
        validate_receipt_chain(
            &image_published,
            PublicationFileKind::Image,
            PublicationPhase::ImagePublished,
            &self.operation_id,
            reservation_sha256,
            Some(&manifest_staged_sha),
            &self.parent.identity,
            &names.image_stage,
            &self.output,
        )?;
        self.verify_published_artifact(&image_published, &self.output)
    }

    fn verify_complete_pair(&self, image: &[u8], manifest: &[u8]) -> Result<(), String> {
        self.verify_complete_pair_with_hook(image, manifest, || {})
    }

    fn verify_complete_pair_with_hook(
        &self,
        image: &[u8],
        manifest: &[u8],
        between_hashes: impl FnOnce(),
    ) -> Result<(), String> {
        let mut observed = Vec::with_capacity(2);
        let mut between_hashes = Some(between_hashes);
        for (index, (name, expected)) in [(&self.output, image), (&self.manifest, manifest)]
            .into_iter()
            .enumerate()
        {
            let file = self
                .parent
                .openat(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
                .map_err(|_| "OUTPUT_PAIR_INCOMPLETE".to_string())?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            validate_artifact(&metadata)?;
            let identity = FileIdentity::of(&metadata);
            if identity.size != expected.len() as u64
                || hash_fd(&file, identity.size)? != bytes_sha256(expected)
            {
                return Err("OUTPUT_PAIR_MISMATCH".into());
            }
            observed.push((name, file, identity));
            if index == 0 {
                if let Some(hook) = between_hashes.take() {
                    hook();
                }
            }
        }
        for (name, file, identity) in observed {
            if FileIdentity::of(&file.metadata().map_err(|e| e.to_string())?) != identity {
                return Err("OUTPUT_PAIR_CHANGED".into());
            }
            self.parent.rebind(name, &identity, "OUTPUT_PAIR_CHANGED")?;
        }
        Ok(())
    }
}

impl PublicationPhase {
    fn from_staged_kind(kind: PublicationFileKind) -> Self {
        match kind {
            PublicationFileKind::Image => Self::ImageStaged,
            PublicationFileKind::Manifest => Self::ManifestStaged,
        }
    }
}

fn output_lock_key(parent: &PinnedDirectory, output: &CStr) -> Vec<u8> {
    let mut key = b"output\0".to_vec();
    key.extend_from_slice(&parent.identity.device.to_le_bytes());
    key.extend_from_slice(&parent.identity.inode.to_le_bytes());
    key.extend_from_slice(output.to_bytes());
    key
}

fn new_operation_id(
    source_sha256: &str,
    parent: &FileIdentity,
    output: &[u8],
) -> Result<String, String> {
    let mut entropy = [0_u8; 32];
    let mut random = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")
        .map_err(|error| format!("OUTPUT_RANDOMNESS_UNAVAILABLE: {error}"))?;
    random
        .read_exact(&mut entropy)
        .map_err(|error| format!("OUTPUT_RANDOMNESS_UNAVAILABLE: {error}"))?;
    let mut digest = Sha256::new();
    digest.update(b"opemos-output-operation-v1\0");
    digest.update(entropy);
    digest.update(source_sha256.as_bytes());
    digest.update(parent.device.to_le_bytes());
    digest.update(parent.inode.to_le_bytes());
    digest.update(output);
    Ok(format!("{:x}", digest.finalize()))
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, String> {
    Ok(bytes_sha256(&canonical_json(value)?))
}

fn bytes_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_receipt(
    root: &PinnedDirectory,
    name: &CStr,
    receipt: &PublicationReceipt,
) -> Result<(), String> {
    root.verify(true)?;
    let bytes = canonical_json(receipt)?;
    if bytes.len() as u64 > RECEIPT_LIMIT {
        return Err("OUTPUT_RECEIPT_OVERSIZED".into());
    }
    let mut file = root
        .openat(
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                "OUTPUT_RECEIPT_COLLISION".to_string()
            } else {
                map_write_error(error)
            }
        })?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err("OUTPUT_RECEIPT_MODE_FAILED".into());
    }
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(map_write_error)?;
    let identity = FileIdentity::of(&file.metadata().map_err(|e| e.to_string())?);
    root.rebind(name, &identity, "OUTPUT_RECEIPT_CHANGED")?;
    root.file.sync_all().map_err(map_write_error)?;
    root.rebind(name, &identity, "OUTPUT_RECEIPT_CHANGED")?;
    root.verify(true)
}

fn read_receipt(root: &PinnedDirectory, name: &CStr) -> Result<PublicationReceipt, String> {
    let mut file = root
        .openat(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
        .map_err(|_| "OUTPUT_RECEIPT_MISSING".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "OUTPUT_RECEIPT_MALFORMED".to_string())?;
    validate_record(&metadata).map_err(|_| "OUTPUT_RECEIPT_MALFORMED".to_string())?;
    if metadata.len() > RECEIPT_LIMIT {
        return Err("OUTPUT_RECEIPT_OVERSIZED".into());
    }
    let identity = FileIdentity::of(&metadata);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(RECEIPT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "OUTPUT_RECEIPT_MALFORMED".to_string())?;
    if bytes.len() as u64 > RECEIPT_LIMIT {
        return Err("OUTPUT_RECEIPT_OVERSIZED".into());
    }
    if FileIdentity::of(
        &file
            .metadata()
            .map_err(|_| "OUTPUT_RECEIPT_MALFORMED".to_string())?,
    ) != identity
    {
        return Err("OUTPUT_RECEIPT_MALFORMED".into());
    }
    root.rebind(name, &identity, "OUTPUT_RECEIPT_MALFORMED")?;
    let value: PublicationReceipt =
        serde_json::from_slice(&bytes).map_err(|_| "OUTPUT_RECEIPT_MALFORMED".to_string())?;
    if canonical_json(&value)? != bytes
        || value.schema_version != 1
        || !is_sha256(&value.operation_id)
        || !is_sha256(&value.reservation_sha256)
        || value
            .previous_receipt_sha256
            .as_deref()
            .is_some_and(|hash| !is_sha256(hash))
        || !is_sha256(&value.sha256)
        || strict_basename(&value.stage_basename).is_err()
        || strict_basename(&value.final_basename).is_err()
    {
        return Err("OUTPUT_RECEIPT_MALFORMED".into());
    }
    Ok(value)
}

fn receipt_if_present(
    root: &PinnedDirectory,
    name: &CStr,
) -> Result<Option<PublicationReceipt>, String> {
    match root.openat(name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("OUTPUT_RECEIPT_MALFORMED".into()),
        Ok(_) => read_receipt(root, name).map(Some),
    }
}

fn receipt_sha256(root: &PinnedDirectory, name: &CStr) -> Result<String, String> {
    canonical_sha256(&read_receipt(root, name)?)
}

#[allow(clippy::too_many_arguments)]
fn validate_receipt_chain(
    receipt: &PublicationReceipt,
    kind: PublicationFileKind,
    phase: PublicationPhase,
    operation_id: &str,
    reservation_sha256: &str,
    previous_receipt_sha256: Option<&str>,
    parent: &FileIdentity,
    stage: &CStr,
    final_name: &CStr,
) -> Result<(), String> {
    if receipt.kind != kind
        || receipt.phase != phase
        || receipt.operation_id != operation_id
        || receipt.reservation_sha256 != reservation_sha256
        || receipt.previous_receipt_sha256.as_deref() != previous_receipt_sha256
        || !same_directory_identity(&receipt.parent_identity, parent)
        || receipt.stage_basename.as_bytes() != stage.to_bytes()
        || receipt.final_basename.as_bytes() != final_name.to_bytes()
    {
        return Err(format!("{RECOVERY_REQUIRED}: receipt chain mismatch"));
    }
    Ok(())
}

fn same_artifact_identity(left: &FileIdentity, right: &FileIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.size == right.size
        && left.mode == right.mode
        && left.uid == right.uid
        && left.gid == right.gid
}

fn validate_artifact(value: &fs::Metadata) -> Result<(), String> {
    if !value.file_type().is_file()
        || value.nlink() != 1
        || value.uid() != unsafe { libc::geteuid() }
        || value.mode() & 0o7777 != 0o600
        || value.len() == 0
    {
        return Err("OUTPUT_ARTIFACT_METADATA_UNSAFE".into());
    }
    Ok(())
}

fn cleanup_unreceipted(parent: &PinnedDirectory, name: &CStr, file: &File) -> Result<(), String> {
    parent.verify(false)?;
    let identity = FileIdentity::of(&file.metadata().map_err(|e| e.to_string())?);
    parent.rebind(name, &identity, "OUTPUT_STAGE_CHANGED")?;
    let result = unsafe { libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err("OUTPUT_STAGE_CLEANUP_FAILED".into());
    }
    parent.file.sync_all().map_err(map_write_error)
}

fn rename_noreplace(
    parent: &PinnedDirectory,
    source: &CStr,
    destination: &CStr,
) -> Result<(), String> {
    parent.verify(false)?;
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            parent.file.as_raw_fd(),
            source.as_ptr(),
            parent.file.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.file.as_raw_fd(),
            source.as_ptr(),
            parent.file.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as i32
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result = -1;
    if result != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::AlreadyExists {
            Err("OUTPUT_PUBLICATION_COLLISION".into())
        } else {
            Err(format!("OUTPUT_ATOMIC_NOREPLACE_UNAVAILABLE: {error}"))
        };
    }
    parent.verify(false)
}

fn map_stage_create_error(error: io::Error) -> String {
    if error.kind() == io::ErrorKind::AlreadyExists {
        "OUTPUT_STAGE_COLLISION".into()
    } else {
        map_write_error(error)
    }
}

fn map_write_error(error: io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::ENOSPC) => "OUTPUT_STORAGE_EXHAUSTED".into(),
        Some(libc::EDQUOT) => "OUTPUT_STORAGE_QUOTA_EXHAUSTED".into(),
        _ => format!("OUTPUT_IO_FAILED: {error}"),
    }
}

fn inspect_record(root: &PinnedDirectory, record: &CStr) -> Result<(), String> {
    match root.openat(record, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(format!("{RECOVERY_REQUIRED}: unsafe record")),
        Ok(_) => match read_record(root, record) {
            Ok(_) => Err(format!("{RECOVERY_REQUIRED}: durable record exists")),
            Err(error) => Err(error),
        },
    }
}

fn read_record(root: &PinnedDirectory, record: &CStr) -> Result<OutputRecord, String> {
    read_record_with_hook(root, record, || {})
}

fn read_record_with_hook(
    root: &PinnedDirectory,
    record: &CStr,
    after_read: impl FnOnce(),
) -> Result<OutputRecord, String> {
    let mut file = root
        .openat(record, libc::O_RDONLY | libc::O_NONBLOCK, 0)
        .map_err(|_| RECORD_MALFORMED.to_string())?;
    let metadata = file.metadata().map_err(|_| RECORD_MALFORMED.to_string())?;
    validate_record(&metadata)?;
    if metadata.len() > RECORD_LIMIT {
        return Err(RECORD_OVERSIZED.into());
    }
    let identity = FileIdentity::of(&metadata);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(RECORD_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RECORD_MALFORMED.to_string())?;
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err(RECORD_OVERSIZED.into());
    }
    after_read();
    if FileIdentity::of(&file.metadata().map_err(|_| RECORD_MALFORMED.to_string())?) != identity {
        return Err(RECORD_MALFORMED.into());
    }
    root.rebind(record, &identity, RECORD_MALFORMED)?;
    let value: OutputRecord =
        serde_json::from_slice(&bytes).map_err(|_| RECORD_MALFORMED.to_string())?;
    let mut canonical = serde_json::to_vec(&value).map_err(|_| RECORD_MALFORMED.to_string())?;
    canonical.push(b'\n');
    if bytes != canonical
        || value.schema_version != 2
        || !is_sha256(&value.operation_id)
        || !is_sha256(&value.source_sha256)
        || strict_basename(&value.output_basename).is_err()
        || strict_basename(&value.manifest_basename).is_err()
    {
        return Err(RECORD_MALFORMED.into());
    }
    Ok(value)
}

fn split_path(path: &Path) -> Result<(PathBuf, CString), String> {
    let parent = fs::canonicalize(path.parent().ok_or("PATH_PARENT_MISSING")?)
        .map_err(|e| format!("Could not resolve parent: {e}"))?;
    Ok((
        parent,
        strict_os_basename(path.file_name().ok_or("PATH_BASENAME_MISSING")?)?,
    ))
}

fn strict_basename(value: &str) -> Result<CString, String> {
    strict_os_basename(OsStr::new(value))
}
fn strict_os_basename(value: &OsStr) -> Result<CString, String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
    {
        return Err("UNSAFE_BASENAME".into());
    }
    CString::new(bytes).map_err(|_| "UNSAFE_BASENAME".into())
}

fn ensure_absent(parent: &PinnedDirectory, name: &CStr, label: &str) -> Result<(), String> {
    match parent.openat(name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(file) if file.metadata().is_ok_and(|m| m.file_type().is_file()) => {
            Err(format!("OUTPUT_RESERVATION_{label}_EXISTS"))
        }
        Ok(_) => Err(format!("OUTPUT_RESERVATION_{label}_UNSAFE")),
        Err(_) => Err(format!("OUTPUT_RESERVATION_{label}_UNSAFE")),
    }
}

fn validate_directory(value: &fs::Metadata, private: bool) -> Result<(), String> {
    if !value.file_type().is_dir()
        || value.file_type().is_symlink()
        || value.uid() != unsafe { libc::geteuid() }
        || (private && value.mode() & 0o7777 != 0o700)
    {
        return Err("DIRECTORY_METADATA_UNSAFE".into());
    }
    Ok(())
}

fn same_directory_identity(left: &FileIdentity, right: &FileIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.mode == right.mode
        && left.uid == right.uid
        && left.gid == right.gid
}
fn validate_lock(value: &fs::Metadata) -> Result<(), String> {
    if !value.file_type().is_file()
        || value.nlink() != 1
        || value.uid() != unsafe { libc::geteuid() }
        || value.mode() & 0o7777 != 0o600
        || value.len() != 0
    {
        return Err("LOCK_METADATA_UNSAFE".into());
    }
    Ok(())
}
fn validate_owned_empty_regular(value: &fs::Metadata, error: &str) -> Result<(), String> {
    if !value.file_type().is_file()
        || value.nlink() != 1
        || value.uid() != unsafe { libc::geteuid() }
        || value.len() != 0
    {
        return Err(error.into());
    }
    Ok(())
}
fn validate_source(value: &fs::Metadata) -> Result<(), String> {
    if !value.file_type().is_file() || value.nlink() != 1 || value.len() == 0 {
        return Err("SOURCE_METADATA_UNSAFE".into());
    }
    Ok(())
}
fn validate_record(value: &fs::Metadata) -> Result<(), String> {
    if !value.file_type().is_file()
        || value.nlink() != 1
        || value.uid() != unsafe { libc::geteuid() }
        || value.mode() & 0o7777 != 0o600
    {
        return Err(RECORD_MALFORMED.into());
    }
    Ok(())
}

fn hash_fd(file: &File, length: u64) -> Result<String, String> {
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while offset < length {
        let wanted = (length - offset).min(buffer.len() as u64) as usize;
        let count = unsafe {
            libc::pread(
                file.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                wanted,
                offset as libc::off_t,
            )
        };
        if count <= 0 {
            return Err("SOURCE_READ_INCOMPLETE".into());
        }
        hash.update(&buffer[..count as usize]);
        offset += count as u64;
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "steamos-reservation-foundation-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            let root = path.join("private");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(path.join("source-a.img"), b"source-a").unwrap();
            fs::write(path.join("source-b.img"), b"source-b").unwrap();
            Self(path)
        }
        fn root(&self) -> PathBuf {
            self.0.join("private")
        }
        fn source(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn output(&self) -> PathBuf {
            self.0.join("result.img")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn source_lock_is_exclusive_and_source_content_is_bound() {
        let fixture = Fixture::new("source");
        let source = fixture.source("source-a.img");
        let reservation = SourceReservation::acquire(&fixture.root(), &source).unwrap();
        assert_eq!(
            SourceReservation::acquire(&fixture.root(), &source).unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        fs::write(&source, b"changed!").unwrap();
        assert_eq!(
            reservation.verify().unwrap_err(),
            "SOURCE_RESERVATION_CHANGED"
        );

        let fixture = Fixture::new("source-path-replacement");
        let source = fixture.source("source-a.img");
        let reservation = SourceReservation::acquire(&fixture.root(), &source).unwrap();
        fs::rename(&source, fixture.0.join("original.img")).unwrap();
        fs::write(&source, b"foreign!").unwrap();
        assert_eq!(
            reservation.verify().unwrap_err(),
            "SOURCE_RESERVATION_CHANGED"
        );
    }

    #[test]
    fn root_lock_parent_and_source_replacement_fail_closed() {
        let fixture = Fixture::new("replacement");
        let root = fixture.root();
        let source = fixture.source("source-a.img");
        let reservation = SourceReservation::acquire(&root, &source).unwrap();
        let lock_path = root.join(reservation.lock.basename.to_str().unwrap());
        fs::rename(&lock_path, root.join("old.lock")).unwrap();
        let replacement = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        drop(replacement);
        assert!(reservation.verify().unwrap_err().contains("LOCK_CHANGED"));

        let fixture = Fixture::new("root-replacement");
        let root = fixture.root();
        let reservation =
            SourceReservation::acquire(&root, &fixture.source("source-a.img")).unwrap();
        let old = fixture.0.join("old-root");
        fs::rename(&root, &old).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            reservation.verify().unwrap_err(),
            "PINNED_DIRECTORY_CHANGED"
        );

        let fixture = Fixture::new("parent-replacement");
        let source = fixture.source("source-a.img");
        let reservation = SourceReservation::acquire(&fixture.root(), &source).unwrap();
        let moved = fixture.0.with_extension("moved");
        fs::rename(&fixture.0, &moved).unwrap();
        fs::create_dir(&fixture.0).unwrap();
        assert!(reservation.verify().is_err());
        fs::remove_dir(&fixture.0).unwrap();
        fs::rename(&moved, &fixture.0).unwrap();
    }

    #[test]
    fn output_binds_parent_and_strict_basenames_exclusively() {
        let fixture = Fixture::new("output");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let output =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        assert!(output.verify().is_ok());
        assert_eq!(
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        assert!(strict_basename("../escape").is_err());
    }

    #[test]
    fn cancellation_preserves_durable_state_and_requires_recovery() {
        let fixture = Fixture::new("cancel");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        drop(reservation);
        let error =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap_err();
        assert!(error.starts_with(RECOVERY_REQUIRED));
    }

    #[test]
    fn malformed_and_oversized_records_are_preserved() {
        for (label, bytes, expected) in [
            ("malformed", b"{}\n".to_vec(), RECORD_MALFORMED),
            (
                "oversized",
                vec![b'x'; RECORD_LIMIT as usize + 1],
                RECORD_OVERSIZED,
            ),
        ] {
            let fixture = Fixture::new(label);
            let source =
                SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img"))
                    .unwrap();
            let reservation =
                OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
            let record = fixture.root().join(reservation.record.to_str().unwrap());
            drop(reservation);
            fs::write(&record, bytes).unwrap();
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                    .unwrap_err(),
                expected
            );
            assert!(record.exists());
        }
    }

    #[test]
    fn record_growth_during_read_fails_closed() {
        let fixture = Fixture::new("record-growth");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let record_path = fixture.root().join(reservation.record.to_str().unwrap());
        let error = read_record_with_hook(&reservation.lock.root, &reservation.record, || {
            OpenOptions::new()
                .append(true)
                .open(&record_path)
                .unwrap()
                .write_all(b"x")
                .unwrap();
        })
        .unwrap_err();
        assert_eq!(error, RECORD_MALFORMED);
    }

    #[test]
    fn fifo_source_record_and_output_fail_without_blocking() {
        let fixture = Fixture::new("fifo-source");
        let source = fixture.source("fifo.img");
        make_fifo(&source);
        assert_eq!(
            SourceReservation::acquire(&fixture.root(), &source).unwrap_err(),
            "SOURCE_METADATA_UNSAFE"
        );

        let fixture = Fixture::new("fifo-output");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        make_fifo(&fixture.output());
        assert_eq!(
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap_err(),
            "OUTPUT_RESERVATION_OUTPUT_UNSAFE"
        );

        let fixture = Fixture::new("fifo-record");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let record = fixture.root().join(reservation.record.to_str().unwrap());
        drop(reservation);
        fs::remove_file(&record).unwrap();
        make_fifo(&record);
        assert_eq!(
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap_err(),
            RECORD_MALFORMED
        );
    }

    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn output_parent_and_destination_replacement_are_detected() {
        let fixture = Fixture::new("output-parent");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        fs::write(fixture.output(), b"foreign").unwrap();
        assert_eq!(
            reservation.verify().unwrap_err(),
            "OUTPUT_RESERVATION_OUTPUT_EXISTS"
        );
        assert_eq!(fs::read(fixture.output()).unwrap(), b"foreign");

        let fixture = Fixture::new("output-parent-replaced");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let destination = fixture.0.join("destination");
        fs::create_dir(&destination).unwrap();
        let output = destination.join("result.img");
        let reservation = OutputReservation::acquire(&fixture.root(), &source, &output).unwrap();
        let moved = fixture.0.join("destination-moved");
        fs::rename(&destination, &moved).unwrap();
        fs::create_dir(&destination).unwrap();
        assert_eq!(
            reservation.verify().unwrap_err(),
            "PINNED_DIRECTORY_CHANGED"
        );
    }

    #[test]
    fn publication_is_image_first_manifest_last_and_manifest_is_closed() {
        let fixture = Fixture::new("publication-order");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let manifest = fixture.output().with_extension("img.manifest.json");
        let mut saw_image_only = false;
        let state = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "before-manifest-rename" {
                    assert_eq!(fs::read(fixture.output()).unwrap(), b"finished-image");
                    assert!(!manifest.exists());
                    saw_image_only = true;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(state, PublicationRecovery::Complete);
        assert!(saw_image_only);
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        assert_eq!(document["schemaVersion"], 1);
        assert_eq!(document["imageSize"], 14);
        assert_eq!(document.as_object().unwrap().len(), 4);
        assert!(!fs::read_to_string(manifest)
            .unwrap()
            .contains(fixture.0.to_string_lossy().as_ref()));
    }

    #[test]
    fn final_pair_rechecks_image_after_manifest_hash() {
        let fixture = Fixture::new("final-pair-race");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        reservation
            .publish_bytes_with_hook(&source, b"finished-image", |_| Ok(()))
            .unwrap();
        let manifest_path = fixture.output().with_extension("img.manifest.json");
        let manifest = fs::read(&manifest_path).unwrap();
        let error = reservation
            .verify_complete_pair_with_hook(b"finished-image", &manifest, || {
                fs::write(fixture.output(), b"tampered-image").unwrap();
            })
            .unwrap_err();
        assert_eq!(error, "OUTPUT_PAIR_CHANGED");
        assert_eq!(fs::read(manifest_path).unwrap(), manifest);
    }

    #[test]
    fn cancellable_staging_cleans_exact_unreceipted_file_and_retries() {
        for phase in [
            "image-stage-created",
            "image-stage-written",
            "image-stage-synced",
        ] {
            let fixture = Fixture::new(phase);
            let source =
                SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img"))
                    .unwrap();
            let reservation =
                OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
            let error = reservation
                .publish_bytes_with_hook(&source, b"finished-image", |observed| {
                    if observed == phase {
                        Err("CANCELLED".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(error, "CANCELLED");
            assert!(!reservation
                .parent
                .path
                .join(
                    reservation
                        .names()
                        .unwrap()
                        .image_stage
                        .to_string_lossy()
                        .as_ref()
                )
                .exists());
            assert_eq!(
                reservation
                    .publish_bytes_with_hook(&source, b"finished-image", |_| Ok(()))
                    .unwrap(),
                PublicationRecovery::Complete
            );
        }
    }

    #[test]
    fn receipted_crash_boundaries_resume_to_exact_complete_pair() {
        for phase in [
            "image-receipt-synced",
            "manifest-receipt-synced",
            "image-renamed",
            "image-parent-synced",
            "image-published-receipt-synced",
            "manifest-renamed",
            "manifest-parent-synced",
            "manifest-published-receipt-synced",
        ] {
            let fixture = Fixture::new(phase);
            let source_path = fixture.source("source-a.img");
            let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
            let reservation =
                OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
            let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ =
                    reservation.publish_bytes_with_hook(&source, b"finished-image", |observed| {
                        if observed == phase {
                            panic!("synthetic crash at {phase}");
                        }
                        Ok(())
                    });
            }));
            assert!(crashed.is_err(), "phase {phase} did not crash");
            drop(reservation);
            drop(source);
            let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
            let recovered =
                OutputReservation::reopen(&fixture.root(), &source, &fixture.output()).unwrap();
            assert_eq!(
                recovered
                    .publish_bytes_with_hook(&source, b"finished-image", |_| Ok(()))
                    .unwrap(),
                PublicationRecovery::Complete,
                "phase {phase} did not recover"
            );
            assert_eq!(fs::read(fixture.output()).unwrap(), b"finished-image");
            assert!(fixture
                .output()
                .with_extension("img.manifest.json")
                .is_file());
        }
    }

    #[test]
    fn unreceipted_crash_is_ambiguous_and_preserved() {
        let fixture = Fixture::new("unreceipted-crash");
        let source_path = fixture.source("source-a.img");
        let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let stage = reservation.names().unwrap().image_stage;
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reservation.publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "image-stage-written" {
                    panic!("synthetic crash before receipt");
                }
                Ok(())
            });
        }));
        assert!(crashed.is_err());
        drop(reservation);
        drop(source);
        let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
        let recovered =
            OutputReservation::reopen(&fixture.root(), &source, &fixture.output()).unwrap();
        let error = recovered
            .publish_bytes_with_hook(&source, b"finished-image", |_| Ok(()))
            .unwrap_err();
        assert!(error.contains("STAGE_EXISTS"));
        assert!(fixture.0.join(stage.to_string_lossy().as_ref()).exists());
        assert!(!fixture.output().exists());
    }

    #[test]
    fn collision_and_replacement_never_overwrite_or_publish_manifest() {
        let fixture = Fixture::new("publication-collision");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "before-image-rename" {
                    fs::write(fixture.output(), b"foreign").unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, "OUTPUT_PUBLICATION_COLLISION");
        assert_eq!(fs::read(fixture.output()).unwrap(), b"foreign");
        assert!(!fixture
            .output()
            .with_extension("img.manifest.json")
            .exists());

        let fixture = Fixture::new("source-replaced-during-publication");
        let source_path = fixture.source("source-a.img");
        let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "before-image-rename" {
                    fs::rename(&source_path, fixture.source("old-source.img")).unwrap();
                    fs::write(&source_path, b"foreign!").unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, "SOURCE_RESERVATION_CHANGED");
        assert!(!fixture.output().exists());

        let fixture = Fixture::new("parent-replaced-during-publication");
        let destination = fixture.0.join("destination");
        fs::create_dir(&destination).unwrap();
        let output_path = destination.join("result.img");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &output_path).unwrap();
        let moved = fixture.0.join("destination-replaced");
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "before-image-rename" {
                    fs::rename(&destination, &moved).unwrap();
                    fs::create_dir(&destination).unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, "PINNED_DIRECTORY_CHANGED");
        assert!(!output_path.exists());
        assert!(!moved.join("result.img").exists());
    }

    #[test]
    fn post_rename_replacement_is_rejected_before_manifest_visibility() {
        let fixture = Fixture::new("post-rename-replacement");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let original = fixture.0.join("published-original.img");
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "image-parent-synced" {
                    fs::rename(fixture.output(), &original).unwrap();
                    fs::write(fixture.output(), b"foreign").unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, "OUTPUT_FINAL_CHANGED");
        assert_eq!(fs::read(fixture.output()).unwrap(), b"foreign");
        assert_eq!(fs::read(original).unwrap(), b"finished-image");
        assert!(!fixture
            .output()
            .with_extension("img.manifest.json")
            .exists());
    }

    #[test]
    fn lock_replacement_during_staging_blocks_publication() {
        let fixture = Fixture::new("publication-lock-replacement");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let lock_path = fixture
            .root()
            .join(reservation.lock.basename.to_string_lossy().as_ref());
        let old_lock = fixture.root().join("replaced-output.lock");
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "before-image-rename" {
                    fs::rename(&lock_path, &old_lock).unwrap();
                    OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(&lock_path)
                        .unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, "RESERVATION_LOCK_CHANGED");
        assert!(!fixture.output().exists());
        assert!(!fixture
            .output()
            .with_extension("img.manifest.json")
            .exists());
    }

    #[test]
    fn durable_record_rejects_recreated_lock_inode_on_reopen() {
        let fixture = Fixture::new("durable-lock-binding");
        let source_path = fixture.source("source-a.img");
        let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let lock_path = fixture
            .root()
            .join(reservation.lock.basename.to_string_lossy().as_ref());
        drop(reservation);
        drop(source);
        fs::rename(&lock_path, fixture.root().join("old-output.lock")).unwrap();
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
        let error =
            OutputReservation::reopen(&fixture.root(), &source, &fixture.output()).unwrap_err();
        assert!(error.contains("identity mismatch"));
        assert!(!fixture.output().exists());
    }

    #[test]
    fn image_replacement_after_receipt_never_exposes_manifest() {
        let fixture = Fixture::new("image-replaced-before-manifest");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let original = fixture.0.join("receipted-image.img");
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "image-published-receipt-synced" {
                    fs::rename(fixture.output(), &original).unwrap();
                    fs::write(fixture.output(), b"foreign").unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert!(error.contains("ARTIFACT_METADATA_UNSAFE") || error.contains("mismatch"));
        assert_eq!(fs::read(fixture.output()).unwrap(), b"foreign");
        assert_eq!(fs::read(original).unwrap(), b"finished-image");
        assert!(!fixture
            .output()
            .with_extension("img.manifest.json")
            .exists());
    }

    #[test]
    fn stale_or_tampered_receipt_is_preserved_fail_closed() {
        let fixture = Fixture::new("tampered-receipt");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let error = reservation
            .publish_bytes_with_hook(&source, b"finished-image", |phase| {
                if phase == "image-receipt-synced" {
                    Err("CANCELLED".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error, "CANCELLED");
        let receipt = fixture.root().join(
            reservation
                .names()
                .unwrap()
                .image_receipt
                .to_string_lossy()
                .as_ref(),
        );
        fs::write(&receipt, b"{}\n").unwrap();
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            reservation
                .publish_bytes_with_hook(&source, b"finished-image", |_| Ok(()))
                .unwrap_err(),
            "OUTPUT_RECEIPT_MALFORMED"
        );
        assert!(receipt.exists());
        assert!(!fixture.output().exists());
    }

    #[test]
    fn stale_record_cannot_be_replayed_for_another_source_and_ids_are_random() {
        let fixture = Fixture::new("stale-source");
        let source_a =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source_a, &fixture.output()).unwrap();
        let first_id = reservation.operation_id.clone();
        drop(reservation);
        drop(source_a);
        let source_b =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-b.img")).unwrap();
        assert!(
            OutputReservation::reopen(&fixture.root(), &source_b, &fixture.output())
                .unwrap_err()
                .contains("identity mismatch")
        );

        let other = Fixture::new("random-id");
        let other_source =
            SourceReservation::acquire(&other.root(), &other.source("source-a.img")).unwrap();
        let other_reservation =
            OutputReservation::acquire(&other.root(), &other_source, &other.output()).unwrap();
        assert_ne!(first_id, other_reservation.operation_id);
        assert!(is_sha256(&other_reservation.operation_id));
    }

    #[test]
    fn storage_errors_have_stable_bounded_codes() {
        assert_eq!(
            map_write_error(io::Error::from_raw_os_error(libc::ENOSPC)),
            "OUTPUT_STORAGE_EXHAUSTED"
        );
        assert_eq!(
            map_write_error(io::Error::from_raw_os_error(libc::EDQUOT)),
            "OUTPUT_STORAGE_QUOTA_EXHAUSTED"
        );
    }

    #[test]
    fn cross_process_source_and_output_contention() {
        let fixture = Fixture::new("process");
        let executable = std::env::current_exe().unwrap();
        let ready = fixture.0.join("worker-ready");
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "output_transaction::tests::reservation_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("RESERVATION_TEST_ROOT", fixture.root())
            .env("RESERVATION_TEST_SOURCE", fixture.source("source-a.img"))
            .env("RESERVATION_TEST_OUTPUT", fixture.output())
            .env("RESERVATION_TEST_READY", &ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.is_file(), "reservation worker did not become ready");
        assert_eq!(
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img"))
                .unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        let other =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-b.img")).unwrap();
        assert_eq!(
            OutputReservation::acquire(&fixture.root(), &other, &fixture.output()).unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn restrictive_umask_cannot_poison_new_lock_or_record_modes() {
        let fixture = Fixture::new("umask");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "output_transaction::tests::reservation_worker",
                "--ignored",
            ])
            .env("RESERVATION_TEST_ROOT", fixture.root())
            .env("RESERVATION_TEST_SOURCE", fixture.source("source-a.img"))
            .env("RESERVATION_TEST_OUTPUT", fixture.output())
            .env("RESERVATION_TEST_READY", fixture.0.join("umask-ready"))
            .env("RESERVATION_TEST_UMASK", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    #[ignore = "subprocess helper for reservation contention"]
    fn reservation_worker() {
        let root = PathBuf::from(std::env::var_os("RESERVATION_TEST_ROOT").unwrap());
        let source_path = PathBuf::from(std::env::var_os("RESERVATION_TEST_SOURCE").unwrap());
        let output = PathBuf::from(std::env::var_os("RESERVATION_TEST_OUTPUT").unwrap());
        let ready = PathBuf::from(std::env::var_os("RESERVATION_TEST_READY").unwrap());
        let restrictive = std::env::var_os("RESERVATION_TEST_UMASK").is_some();
        if restrictive {
            unsafe { libc::umask(0o777) };
        }
        let source = SourceReservation::acquire(&root, &source_path).unwrap();
        let output_reservation = OutputReservation::acquire(&root, &source, &output).unwrap();
        assert_eq!(source.lock.file.metadata().unwrap().mode() & 0o7777, 0o600);
        assert_eq!(
            output_reservation.lock.file.metadata().unwrap().mode() & 0o7777,
            0o600
        );
        let record = output_reservation
            .lock
            .root
            .openat(&output_reservation.record, libc::O_RDONLY, 0)
            .unwrap();
        assert_eq!(record.metadata().unwrap().mode() & 0o7777, 0o600);
        if restrictive {
            unsafe { libc::umask(0o022) };
        }
        fs::write(ready, b"ready\n").unwrap();
        if restrictive {
            return;
        }
        let mut byte = [0_u8; 1];
        let _ = io::stdin().read(&mut byte);
    }
}
