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
const LOCK_RETRY_LIMIT: Duration = Duration::from_millis(250);

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

#[derive(Debug)]
struct ReceiptSnapshot {
    name: CString,
    identity: FileIdentity,
    value: PublicationReceipt,
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
        // A concurrent fork may briefly inherit this close-on-exec descriptor
        // before exec closes it. Bound that platform window without ever
        // turning a real conflicting reservation into an unbounded wait.
        let deadline = Instant::now() + LOCK_RETRY_LIMIT;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err("RESERVATION_LOCK_FAILED".into());
            }
            if Instant::now() >= deadline {
                return Err("RESERVATION_ALREADY_HELD".into());
            }
            thread::sleep(Duration::from_millis(2));
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
    inode_lock: LockCapability,
    parent: PinnedDirectory,
    basename: CString,
    source: File,
    identity: FileIdentity,
    sha256: String,
}

impl SourceReservation {
    pub(crate) fn acquire(root: &Path, source_path: &Path) -> Result<Self, String> {
        Self::acquire_cancellable(root, source_path, || false)
    }

    pub(crate) fn acquire_cancellable(
        root: &Path,
        source_path: &Path,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<Self, String> {
        check_source_cancellation(&mut cancelled)?;
        let (parent_path, basename) = split_path(source_path)?;
        let parent = PinnedDirectory::open(&parent_path, false)?;
        let source = parent
            .openat(&basename, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .map_err(|e| format!("Could not open selected source: {e}"))?;
        let metadata = source.metadata().map_err(|e| e.to_string())?;
        validate_source(&metadata)?;
        let identity = FileIdentity::of(&metadata);
        let mut key = b"source\0".to_vec();
        key.extend_from_slice(&parent.identity.device.to_le_bytes());
        key.extend_from_slice(&parent.identity.inode.to_le_bytes());
        key.extend_from_slice(basename.as_bytes());
        // Fixed order: source pathname, source inode, then output (by caller).
        // Both source locks remain held through consumption. A rename may
        // invalidate the path guard but must not make the same inode available
        // to another reservation. Failed acquisition drops earlier guards.
        let lock = LockCapability::acquire(root, &key)?;
        let mut inode_key = b"source-inode\0".to_vec();
        inode_key.extend_from_slice(&identity.device.to_le_bytes());
        inode_key.extend_from_slice(&identity.inode.to_le_bytes());
        let inode_lock = LockCapability::acquire(root, &inode_key)?;
        let sha256 = hash_fd_cancellable(&source, metadata.len(), &mut cancelled)?;
        let result = Self {
            lock,
            inode_lock,
            parent,
            basename,
            source,
            identity,
            sha256,
        };
        result.verify_cancellable(cancelled)?;
        Ok(result)
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        self.verify_cancellable(|| false)
    }

    pub(crate) fn verify_cancellable(
        &self,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<(), String> {
        check_source_cancellation(&mut cancelled)?;
        self.lock.verify()?;
        self.inode_lock.verify()?;
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
            || hash_fd_cancellable(&self.source, self.identity.size, &mut cancelled)? != self.sha256
            || hash_fd_cancellable(&path, self.identity.size, &mut cancelled)? != self.sha256
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
    manifest_lock: LockCapability,
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
        // Reject split lock namespaces before creating any output lock/record.
        let requested_root = PinnedDirectory::open(root, true)?;
        require_source_lock_root(source, &requested_root)?;
        let (parent_path, output) = split_path(output_path)?;
        let parent = PinnedDirectory::open(&parent_path, false)?;
        let manifest = strict_basename(&format!(
            "{}.manifest.json",
            output.to_str().map_err(|_| "OUTPUT_BASENAME_UTF8")?
        ))?;
        ensure_absent(&parent, &output, "OUTPUT")?;
        ensure_absent(&parent, &manifest, "MANIFEST")?;
        let lock = LockCapability::acquire(root, &output_lock_key(&parent, &output))?;
        // The image basename is a strict prefix of its manifest basename, so
        // image then manifest is a consistent lexical order for both paths.
        // Use one namespace: another image must not reserve this manifest.
        let manifest_lock = LockCapability::acquire(root, &output_lock_key(&parent, &manifest))?;
        require_source_lock_root(source, &lock.root)?;
        require_source_lock_root(source, &manifest_lock.root)?;
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
            manifest_lock,
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
        self.manifest_lock.verify()?;
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
        self.manifest_lock.verify()?;
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
        self.lock.verify()?;
        self.manifest_lock.verify()
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
        // Reject split lock namespaces before creating any output lock/record.
        let requested_root = PinnedDirectory::open(root, true)?;
        require_source_lock_root(source, &requested_root)?;
        let (parent_path, output) = split_path(output_path)?;
        let parent = PinnedDirectory::open(&parent_path, false)?;
        let manifest = strict_basename(&format!(
            "{}.manifest.json",
            output.to_str().map_err(|_| "OUTPUT_BASENAME_UTF8")?
        ))?;
        let lock = LockCapability::acquire(root, &output_lock_key(&parent, &output))?;
        // The image basename is a strict prefix of its manifest basename, so
        // image then manifest is a consistent lexical order for both paths.
        // Use one namespace: another image must not reserve this manifest.
        let manifest_lock = LockCapability::acquire(root, &output_lock_key(&parent, &manifest))?;
        require_source_lock_root(source, &lock.root)?;
        require_source_lock_root(source, &manifest_lock.root)?;
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
            manifest_lock,
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
        require_source_lock_root(source, &self.lock.root)?;
        require_source_lock_root(source, &self.manifest_lock.root)?;
        // A valid guard for another file cannot stand in for the exact source
        // recorded by this reservation, even when both files have equal bytes.
        if source.identity != self.source_identity || source.sha256 != self.source_sha256 {
            return Err("OUTPUT_SOURCE_RESERVATION_MISMATCH".into());
        }
        source.verify()?;
        self.lock.verify()?;
        self.manifest_lock.verify()?;
        self.parent.verify(false)?;
        if read_record(&self.lock.root, &self.record)? != self.value() {
            return Err("OUTPUT_RESERVATION_RECORD_CHANGED".into());
        }
        Ok(())
    }

    fn publish_bytes_cancellable(
        &self,
        source: &SourceReservation,
        image: &[u8],
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PublicationRecovery, String> {
        check_output_cancellation(&mut cancelled)?;
        self.publish_bytes_with_hook(source, image, |_| check_output_cancellation(&mut cancelled))
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
        self.verify_committed_pair(source, image, &manifest)
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
            if let Err(error) = write_staged_bytes(&mut file, chunk, kind) {
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
        if let Err(error) = sync_staged_file(&file, kind) {
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
        sync_published_file(&artifact.file, artifact.kind, false).map_err(map_write_error)?;
        sync_published_file(&self.parent.file, artifact.kind, true).map_err(map_write_error)?;
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

    fn verify_committed_pair(
        &self,
        source: &SourceReservation,
        image: &[u8],
        manifest: &[u8],
    ) -> Result<(), String> {
        self.verify_committed_pair_with_hook(source, image, manifest, || {})
    }

    fn verify_committed_pair_with_hook(
        &self,
        source: &SourceReservation,
        image: &[u8],
        manifest: &[u8],
        after_predecessor: impl FnOnce(),
    ) -> Result<(), String> {
        self.verify_guards(source)?;
        let reservation_sha256 = self.reservation_sha256()?;
        let mut receipt_chain = self.verify_image_predecessor(&reservation_sha256)?;
        validate_staged_receipt_bytes(&receipt_chain[0].value, image)?;
        validate_staged_receipt_bytes(&receipt_chain[1].value, manifest)?;
        let image_published_sha = receipt_chain
            .last()
            .ok_or("OUTPUT_RECEIPT_MISSING")?
            .sha256
            .clone();
        after_predecessor();
        let manifest_published = self.published_receipt(4, "manifest-published")?;
        let receipt = read_receipt_snapshot(&self.lock.root, &manifest_published)?;
        validate_receipt_chain(
            &receipt.value,
            PublicationFileKind::Manifest,
            PublicationPhase::ManifestPublished,
            &self.operation_id,
            &reservation_sha256,
            Some(&image_published_sha),
            &self.parent.identity,
            &self.names()?.manifest_stage,
            &self.manifest,
        )?;
        validate_staged_published_pair(&receipt_chain[1].value, &receipt.value)?;
        self.verify_published_artifact(&receipt.value, &self.manifest)?;
        receipt_chain.push(receipt);
        // Existing readable receipt bytes may survive a failed sync in the
        // same boot. Re-establish durability for the exact validated chain
        // before accepting a recovered transaction, including completed pairs.
        for receipt in &receipt_chain {
            persist_receipt_snapshot(&self.lock.root, receipt)?;
        }
        // Revalidate the slow source/lock/record guards before the output pair.
        // The pair check must remain the final acceptance operation so a
        // concurrent output mutation cannot hide behind the source rehash.
        self.verify_guards(source)?;
        for receipt in &receipt_chain {
            self.lock
                .root
                .rebind(&receipt.name, &receipt.identity, "OUTPUT_RECEIPT_CHANGED")?;
        }
        self.verify_complete_pair(image, manifest)
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

    fn verify_image_predecessor(
        &self,
        reservation_sha256: &str,
    ) -> Result<Vec<ReceiptSnapshot>, String> {
        let names = self.names()?;
        let image_staged = read_receipt_snapshot(&self.lock.root, &names.image_receipt)?;
        validate_receipt_chain(
            &image_staged.value,
            PublicationFileKind::Image,
            PublicationPhase::ImageStaged,
            &self.operation_id,
            reservation_sha256,
            None,
            &self.parent.identity,
            &names.image_stage,
            &self.output,
        )?;
        let image_staged_sha = image_staged.sha256.clone();
        let manifest_staged = read_receipt_snapshot(&self.lock.root, &names.manifest_receipt)?;
        validate_receipt_chain(
            &manifest_staged.value,
            PublicationFileKind::Manifest,
            PublicationPhase::ManifestStaged,
            &self.operation_id,
            reservation_sha256,
            Some(&image_staged_sha),
            &self.parent.identity,
            &names.manifest_stage,
            &self.manifest,
        )?;
        let manifest_staged_sha = manifest_staged.sha256.clone();
        let image_published_name = self.published_receipt(3, "image-published")?;
        let image_published = read_receipt_snapshot(&self.lock.root, &image_published_name)?;
        validate_receipt_chain(
            &image_published.value,
            PublicationFileKind::Image,
            PublicationPhase::ImagePublished,
            &self.operation_id,
            reservation_sha256,
            Some(&manifest_staged_sha),
            &self.parent.identity,
            &names.image_stage,
            &self.output,
        )?;
        validate_staged_published_pair(&image_staged.value, &image_published.value)?;
        self.verify_published_artifact(&image_published.value, &self.output)?;
        Ok(vec![image_staged, manifest_staged, image_published])
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

// Local lock-directory binding only; this does not select an installed trust
// root or activate the still-inactive output transaction.
fn require_source_lock_root(
    source: &SourceReservation,
    root: &PinnedDirectory,
) -> Result<(), String> {
    if !same_directory_identity(&source.lock.root.identity, &root.identity)
        || !same_directory_identity(&source.inode_lock.root.identity, &root.identity)
    {
        return Err("OUTPUT_SOURCE_LOCK_ROOT_MISMATCH".into());
    }
    Ok(())
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
    #[cfg(test)]
    if let Some(fault) = staging_io_faults::take(
        receipt.kind,
        staging_io_faults::Operation::ReceiptCreate(receipt.phase),
    ) {
        staging_io_faults::observe(0);
        return Err(map_write_error(io::Error::from_raw_os_error(fault.errno)));
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
    write_receipt_bytes(&mut file, &bytes, receipt)
        .and_then(|_| sync_receipt_file(&file, receipt, false))
        .map_err(map_write_error)?;
    let identity = FileIdentity::of(&file.metadata().map_err(|e| e.to_string())?);
    root.rebind(name, &identity, "OUTPUT_RECEIPT_CHANGED")?;
    sync_receipt_file(&root.file, receipt, true).map_err(map_write_error)?;
    root.rebind(name, &identity, "OUTPUT_RECEIPT_CHANGED")?;
    root.verify(true)
}

fn persist_receipt_snapshot(
    root: &PinnedDirectory,
    snapshot: &ReceiptSnapshot,
) -> Result<(), String> {
    root.verify(true)?;
    let file = root
        .openat(&snapshot.name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
        .map_err(|_| "OUTPUT_RECEIPT_CHANGED".to_string())?;
    let verify = || -> Result<(), String> {
        if FileIdentity::of(&file.metadata().map_err(|e| e.to_string())?) != snapshot.identity
            || hash_fd(&file, snapshot.identity.size)? != snapshot.sha256
        {
            return Err("OUTPUT_RECEIPT_CHANGED".into());
        }
        root.rebind(&snapshot.name, &snapshot.identity, "OUTPUT_RECEIPT_CHANGED")
    };
    verify()?;
    sync_receipt_file(&file, &snapshot.value, false).map_err(map_write_error)?;
    sync_receipt_file(&root.file, &snapshot.value, true).map_err(map_write_error)?;
    verify()?;
    root.verify(true)
}

fn read_receipt(root: &PinnedDirectory, name: &CStr) -> Result<PublicationReceipt, String> {
    Ok(read_receipt_snapshot(root, name)?.value)
}

fn read_receipt_snapshot(root: &PinnedDirectory, name: &CStr) -> Result<ReceiptSnapshot, String> {
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
    Ok(ReceiptSnapshot {
        name: name.to_owned(),
        identity,
        sha256: bytes_sha256(&bytes),
        value,
    })
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

fn validate_staged_receipt_bytes(
    staged: &PublicationReceipt,
    expected: &[u8],
) -> Result<(), String> {
    if staged.file_identity.size != expected.len() as u64 || staged.sha256 != bytes_sha256(expected)
    {
        return Err(format!(
            "{RECOVERY_REQUIRED}: staged receipt payload mismatch"
        ));
    }
    Ok(())
}

fn validate_staged_published_pair(
    staged: &PublicationReceipt,
    published: &PublicationReceipt,
) -> Result<(), String> {
    if staged.kind != published.kind
        || staged.sha256 != published.sha256
        || !same_artifact_identity(&staged.file_identity, &published.file_identity)
    {
        return Err(format!(
            "{RECOVERY_REQUIRED}: staged and published receipt mismatch"
        ));
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

// These small adapters preserve the real write/sync error paths. Faults are
// compiled only in tests, scoped to the current thread, and never configured
// through runtime environment, host settings, or publication inputs.
fn write_staged_bytes(file: &mut File, bytes: &[u8], _kind: PublicationFileKind) -> io::Result<()> {
    #[cfg(test)]
    if let Some(fault) = staging_io_faults::take(_kind, staging_io_faults::Operation::Write) {
        file.write_all(&bytes[..fault.prefix.min(bytes.len())])?;
        staging_io_faults::observe(file.metadata()?.len());
        return Err(io::Error::from_raw_os_error(fault.errno));
    }
    file.write_all(bytes)
}

fn sync_staged_file(file: &File, _kind: PublicationFileKind) -> io::Result<()> {
    #[cfg(test)]
    if let Some(fault) = staging_io_faults::take(_kind, staging_io_faults::Operation::Sync) {
        staging_io_faults::observe(file.metadata()?.len());
        return Err(io::Error::from_raw_os_error(fault.errno));
    }
    file.sync_all()
}

fn write_receipt_bytes(
    file: &mut File,
    bytes: &[u8],
    _receipt: &PublicationReceipt,
) -> io::Result<()> {
    #[cfg(test)]
    if let Some(fault) = staging_io_faults::take(
        _receipt.kind,
        staging_io_faults::Operation::ReceiptWrite(_receipt.phase),
    ) {
        file.write_all(&bytes[..fault.prefix.min(bytes.len())])?;
        staging_io_faults::observe(file.metadata()?.len());
        return Err(io::Error::from_raw_os_error(fault.errno));
    }
    file.write_all(bytes)
}

fn sync_receipt_file(file: &File, _receipt: &PublicationReceipt, _parent: bool) -> io::Result<()> {
    #[cfg(test)]
    {
        let operation = if _parent {
            staging_io_faults::Operation::ReceiptParentSync(_receipt.phase)
        } else {
            staging_io_faults::Operation::ReceiptSync(_receipt.phase)
        };
        if let Some(fault) = staging_io_faults::take(_receipt.kind, operation) {
            staging_io_faults::observe(file.metadata()?.len());
            return Err(io::Error::from_raw_os_error(fault.errno));
        }
    }
    file.sync_all()
}

fn sync_published_file(file: &File, _kind: PublicationFileKind, _parent: bool) -> io::Result<()> {
    #[cfg(test)]
    {
        let operation = if _parent {
            staging_io_faults::Operation::OutputParentSync
        } else {
            staging_io_faults::Operation::ArtifactSync
        };
        if let Some(fault) = staging_io_faults::take(_kind, operation) {
            staging_io_faults::observe(file.metadata()?.len());
            return Err(io::Error::from_raw_os_error(fault.errno));
        }
    }
    file.sync_all()
}

#[cfg(test)]
mod staging_io_faults {
    use super::{PublicationFileKind, PublicationPhase};
    use std::cell::RefCell;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Operation {
        Write,
        Sync,
        ReceiptCreate(PublicationPhase),
        ReceiptWrite(PublicationPhase),
        ReceiptSync(PublicationPhase),
        ReceiptParentSync(PublicationPhase),
        ArtifactSync,
        OutputParentSync,
    }

    pub(super) struct Fault {
        pub(super) kind: PublicationFileKind,
        pub(super) operation: Operation,
        pub(super) errno: i32,
        pub(super) prefix: usize,
        pub(super) skip: usize,
    }

    thread_local! {
        static STATE: RefCell<(Option<Fault>, Option<u64>)> = const { RefCell::new((None, None)) };
    }

    pub(super) struct Guard;

    impl Guard {
        pub(super) fn arm(fault: Fault) -> Self {
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                assert!(state.0.is_none(), "nested staging fault injection");
                *state = (Some(fault), None);
            });
            Self
        }

        pub(super) fn observed_size(&self) -> Option<u64> {
            STATE.with(|state| state.borrow().1)
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            STATE.with(|state| *state.borrow_mut() = (None, None));
        }
    }

    pub(super) fn take(kind: PublicationFileKind, operation: Operation) -> Option<Fault> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let fault = state.0.as_mut()?;
            if fault.kind != kind || fault.operation != operation {
                return None;
            }
            if fault.skip > 0 {
                fault.skip -= 1;
                return None;
            }
            state.0.take()
        })
    }

    pub(super) fn observe(size: u64) {
        STATE.with(|state| state.borrow_mut().1 = Some(size));
    }
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

fn check_source_cancellation(cancelled: &mut impl FnMut() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("SOURCE_RESERVATION_CANCELLED".into())
    } else {
        Ok(())
    }
}

fn check_output_cancellation(cancelled: &mut impl FnMut() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("OUTPUT_PUBLICATION_CANCELLED".into())
    } else {
        Ok(())
    }
}

fn hash_fd(file: &File, length: u64) -> Result<String, String> {
    hash_fd_cancellable(file, length, &mut || false)
}

fn hash_fd_cancellable(
    file: &File,
    length: u64,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while offset < length {
        check_source_cancellation(cancelled)?;
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
    check_source_cancellation(cancelled)?;
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    const TEST_IMAGE: &[u8] = b"finished-image";

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

    fn expected_manifest(source_sha256: &str) -> Vec<u8> {
        let image_sha256 = bytes_sha256(TEST_IMAGE);
        canonical_json(&AdjacentOutputManifest {
            schema_version: 1,
            image_sha256: &image_sha256,
            image_size: TEST_IMAGE.len() as u64,
            source_sha256,
        })
        .unwrap()
    }

    fn overwrite_receipt(root: &Path, name: &CStr, receipt: &PublicationReceipt) {
        fs::write(
            root.join(name.to_string_lossy().as_ref()),
            canonical_json(receipt).unwrap(),
        )
        .unwrap();
    }

    struct WorkerGuard(Option<std::process::Child>);

    impl WorkerGuard {
        fn new(child: std::process::Child) -> Self {
            Self(Some(child))
        }

        fn child_mut(&mut self) -> &mut std::process::Child {
            self.0.as_mut().expect("publication worker already reaped")
        }
    }

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
                let _ = child.wait();
            }
        }
    }

    fn wait_for_worker(worker: &mut WorkerGuard, phase: &str) {
        let stdout = worker
            .child_mut()
            .stdout
            .take()
            .expect("publication worker stdout was not captured");
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("publication worker output was not UTF-8 text");
                if line.starts_with("PUBLICATION_READY:") {
                    let _ = sender.send(line);
                    return;
                }
            }
        });
        let marker = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("publication worker did not reach its crash boundary");
        reader.join().expect("publication worker reader failed");
        assert_eq!(marker, format!("PUBLICATION_READY:{phase}"));
        assert!(worker.child_mut().try_wait().unwrap().is_none());
    }

    fn kill_worker(worker: &mut WorkerGuard) {
        let child_id = worker.child_mut().id();
        assert_eq!(unsafe { libc::kill(child_id as i32, libc::SIGKILL) }, 0);
        let status = worker.child_mut().wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        worker.0.take();
    }

    fn publication_worker_authority(fixture: &Fixture) -> (PathBuf, String) {
        let mut entropy = [0_u8; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut entropy)
            .unwrap();
        let nonce = bytes_sha256(&entropy);
        let path = fixture.0.join(".publication-worker-authority");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(nonce.as_bytes()).unwrap();
        file.sync_all().unwrap();
        (path, nonce)
    }

    fn assert_residue_is_bounded(fixture: &Fixture) {
        let root_entries = fs::read_dir(fixture.root())
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        // Four locks (source path/inode and output image/manifest), one reservation, four
        // publication receipts, and the intentionally preserved foreign file.
        assert!(root_entries.len() <= 10, "unbounded private residue");
        assert!(
            root_entries
                .iter()
                .filter(|entry| entry.file_name().as_bytes().ends_with(b".lock"))
                .count()
                <= 4
        );
        for entry in root_entries {
            let metadata = entry.metadata().unwrap();
            assert!(metadata.is_file(), "unexpected private residue type");
            assert!(
                metadata.len() <= RECORD_LIMIT.max(RECEIPT_LIMIT),
                "oversized private residue"
            );
        }

        let transaction_entries = fs::read_dir(&fixture.0)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                let name = entry.file_name();
                name.as_bytes().starts_with(b".opemos-")
                    || name == OsStr::new("result.img")
                    || name == OsStr::new("result.img.manifest.json")
            })
            .collect::<Vec<_>>();
        assert!(transaction_entries.len() <= 2, "unbounded output residue");
        assert!(transaction_entries
            .iter()
            .all(|entry| entry.metadata().unwrap().is_file()));
    }

    #[test]
    fn cancelled_source_acquisition_releases_locks_and_preserves_bytes() {
        let bytes = vec![0x5a; 2 * 1024 * 1024 + 17];
        // Before opening, before/mid/after hashing, and during both verification reads.
        for cancel_at in [1, 2, 3, 5, 6, 8, 11, 14] {
            let fixture = Fixture::new("cancel-source-acquisition");
            let path = fixture.source("source-a.img");
            fs::write(&path, &bytes).unwrap();
            let before = FileIdentity::of(&fs::metadata(&path).unwrap());
            let mut checks = 0;
            assert_eq!(
                SourceReservation::acquire_cancellable(&fixture.root(), &path, || {
                    checks += 1;
                    checks == cancel_at
                })
                .unwrap_err(),
                "SOURCE_RESERVATION_CANCELLED"
            );
            assert_eq!(checks, cancel_at);
            let resumed = SourceReservation::acquire(&fixture.root(), &path).unwrap();
            resumed.verify().unwrap();
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(FileIdentity::of(&fs::metadata(&path).unwrap()), before);
            assert!(!fixture.output().exists());
        }
        let fixture = Fixture::new("cancel-before-source-open");
        assert_eq!(
            SourceReservation::acquire_cancellable(
                &fixture.root(),
                &fixture.source("missing.img"),
                || true
            )
            .unwrap_err(),
            "SOURCE_RESERVATION_CANCELLED"
        );
        assert_eq!(fs::read_dir(fixture.root()).unwrap().count(), 0);
    }

    #[test]
    fn cancelled_source_verification_retains_ownership_and_rechecks_mutation() {
        let fixture = Fixture::new("cancel-source-verification");
        let path = fixture.source("source-a.img");
        let bytes = vec![0x3c; 2 * 1024 * 1024 + 17];
        fs::write(&path, &bytes).unwrap();
        let source = SourceReservation::acquire(&fixture.root(), &path).unwrap();
        for cancel_at in [1, 2, 3, 5, 6, 9] {
            let mut checks = 0;
            assert_eq!(
                source
                    .verify_cancellable(|| {
                        checks += 1;
                        checks == cancel_at
                    })
                    .unwrap_err(),
                "SOURCE_RESERVATION_CANCELLED"
            );
            assert_eq!(checks, cancel_at);
            source.verify().unwrap();
        }
        assert_eq!(
            SourceReservation::acquire(&fixture.root(), &path).unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            FileIdentity::of(&fs::metadata(&path).unwrap()),
            source.identity
        );
        // Cancellation must not cache successful verification or bless changed bytes.
        fs::write(&path, vec![0x4d; bytes.len()]).unwrap();
        assert_eq!(
            source.verify_cancellable(|| true).unwrap_err(),
            "SOURCE_RESERVATION_CANCELLED"
        );
        assert_eq!(source.verify().unwrap_err(), "SOURCE_RESERVATION_CHANGED");
        drop(source);
        SourceReservation::acquire(&fixture.root(), &path)
            .unwrap()
            .verify()
            .unwrap();
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
    fn renamed_source_keeps_inode_exclusive_and_failed_acquisition_releases_path_lock() {
        for nested in [false, true] {
            let fixture = Fixture::new("renamed-source-lock");
            let original = fixture.source("source-a.img");
            let held = SourceReservation::acquire(&fixture.root(), &original).unwrap();
            let parent = if nested {
                let path = fixture.0.join("another-parent");
                fs::create_dir(&path).unwrap();
                path
            } else {
                fixture.0.clone()
            };
            let alias = parent.join("renamed.img");
            fs::rename(&original, &alias).unwrap();
            assert!(held.verify().is_err());
            assert_eq!(
                SourceReservation::acquire(&fixture.root(), &alias).unwrap_err(),
                "RESERVATION_ALREADY_HELD"
            );
            let moved_again = parent.join("moved-again.img");
            fs::rename(&alias, &moved_again).unwrap();
            fs::write(&alias, b"foreign source").unwrap();
            // The failed inode acquisition must release its newly acquired path lock.
            let foreign = SourceReservation::acquire(&fixture.root(), &alias).unwrap();
            foreign.verify().unwrap();
            assert_eq!(
                SourceReservation::acquire(&fixture.root(), &moved_again).unwrap_err(),
                "RESERVATION_ALREADY_HELD"
            );
            drop(held);
            let resumed = SourceReservation::acquire(&fixture.root(), &moved_again).unwrap();
            resumed.verify().unwrap();
            assert_eq!(fs::read(&moved_again).unwrap(), b"source-a");
            assert_eq!(fs::read(&alias).unwrap(), b"foreign source");
        }
    }

    #[test]
    fn source_inode_lock_replacement_revokes_the_reservation() {
        let fixture = Fixture::new("source-inode-lock-replacement");
        let source = fixture.source("source-a.img");
        let held = SourceReservation::acquire(&fixture.root(), &source).unwrap();
        let path = fixture
            .root()
            .join(held.inode_lock.basename.to_str().unwrap());
        fs::rename(&path, fixture.root().join("preserved-inode-lock")).unwrap();
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(held.verify().unwrap_err(), "RESERVATION_LOCK_CHANGED");
        assert_eq!(fs::read(source).unwrap(), b"source-a");
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
    fn cancellable_publication_preserves_recoverable_state_and_locks() {
        let image = vec![0x5a; COPY_CHUNK * 2 + 17];
        for cancel_at in [1, 2, 3, 4, 5, 8, 11] {
            let fixture = Fixture::new(&format!("publication-cancel-{cancel_at}"));
            let source_path = fixture.source("source-a.img");
            let source_bytes = fs::read(&source_path).unwrap();
            let source_identity = FileIdentity::of(&fs::metadata(&source_path).unwrap());
            let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
            let reservation =
                OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
            let mut checks = 0;
            let error = reservation
                .publish_bytes_cancellable(&source, &image, || {
                    checks += 1;
                    checks == cancel_at
                })
                .unwrap_err();
            assert_eq!(error, "OUTPUT_PUBLICATION_CANCELLED");
            assert!(checks >= cancel_at);
            assert_eq!(fs::read(&source_path).unwrap(), source_bytes);
            assert_eq!(
                FileIdentity::of(&fs::metadata(&source_path).unwrap()),
                source_identity
            );
            let visible = fixture.output();
            let manifest = visible.with_file_name("result.img.manifest.json");
            assert!(!manifest.exists() || visible.exists());
            assert!(OutputReservation::acquire(&fixture.root(), &source, &visible).is_err());
            assert_eq!(
                reservation
                    .publish_bytes_cancellable(&source, &image, || false)
                    .unwrap(),
                PublicationRecovery::Complete
            );
            assert_eq!(fs::read(visible).unwrap(), image);
            assert!(manifest.exists());
        }
    }

    #[test]
    fn published_sync_failures_retry_exact_renamed_files_after_reopen() {
        use staging_io_faults::{Fault, Guard, Operation};
        for kind in [PublicationFileKind::Image, PublicationFileKind::Manifest] {
            for operation in [Operation::ArtifactSync, Operation::OutputParentSync] {
                for errno in [libc::ENOSPC, libc::EDQUOT, libc::EIO] {
                    let fixture = Fixture::new("published-sync-retry");
                    let source_path = fixture.source("source-a.img");
                    let source_before = FileIdentity::of(&fs::metadata(&source_path).unwrap());
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reservation =
                        OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    let names = reservation.names().unwrap();
                    let (stage, final_path, receipt, rename_phase) = match kind {
                        PublicationFileKind::Image => (
                            names.image_stage,
                            fixture.output(),
                            reservation.published_receipt(3, "image-published").unwrap(),
                            "before-image-rename",
                        ),
                        PublicationFileKind::Manifest => (
                            names.manifest_stage,
                            fixture.output().with_extension("img.manifest.json"),
                            reservation
                                .published_receipt(4, "manifest-published")
                                .unwrap(),
                            "before-manifest-rename",
                        ),
                    };
                    let receipt_path = fixture.root().join(receipt.to_string_lossy().as_ref());
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno,
                        prefix: 0,
                        skip: 0,
                    });
                    let error = reservation
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                        .unwrap_err();
                    assert_eq!(error, map_write_error(io::Error::from_raw_os_error(errno)));
                    assert!(
                        guard.observed_size().is_some(),
                        "fault must fire after rename"
                    );
                    drop(guard);
                    assert!(!fixture.0.join(stage.to_string_lossy().as_ref()).exists());
                    assert!(
                        !receipt_path.exists(),
                        "failed sync cannot produce a published receipt"
                    );
                    let bytes = fs::read(&final_path).unwrap();
                    let identity = FileIdentity::of(&fs::metadata(&final_path).unwrap());
                    let staged_receipts: Vec<_> = [names.image_receipt, names.manifest_receipt]
                        .into_iter()
                        .map(|name| {
                            let path = fixture.root().join(name.to_string_lossy().as_ref());
                            let bytes = fs::read(&path).unwrap();
                            let identity = FileIdentity::of(&fs::metadata(&path).unwrap());
                            (path, bytes, identity)
                        })
                        .collect();
                    if kind == PublicationFileKind::Image {
                        assert!(!fixture
                            .output()
                            .with_extension("img.manifest.json")
                            .exists());
                    }
                    drop(reservation);
                    drop(source);
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reopened =
                        OutputReservation::reopen(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno,
                        prefix: 0,
                        skip: 0,
                    });
                    let error = reopened
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |phase| {
                            assert_ne!(
                                phase, rename_phase,
                                "recovery must not rename the published inode again"
                            );
                            Ok(())
                        })
                        .unwrap_err();
                    assert_eq!(error, map_write_error(io::Error::from_raw_os_error(errno)));
                    assert!(
                        guard.observed_size().is_some(),
                        "recovery must retry the failed sync"
                    );
                    drop(guard);
                    assert!(!receipt_path.exists());
                    assert_eq!(fs::read(&final_path).unwrap(), bytes);
                    assert_eq!(
                        FileIdentity::of(&fs::metadata(&final_path).unwrap()),
                        identity
                    );
                    assert_eq!(
                        reopened
                            .publish_bytes_with_hook(&source, TEST_IMAGE, |phase| {
                                assert_ne!(phase, rename_phase);
                                Ok(())
                            })
                            .unwrap(),
                        PublicationRecovery::Complete
                    );
                    assert_eq!(fs::read(&final_path).unwrap(), bytes);
                    assert_eq!(
                        FileIdentity::of(&fs::metadata(&final_path).unwrap()),
                        identity
                    );
                    for (path, bytes, identity) in staged_receipts {
                        assert_eq!(fs::read(&path).unwrap(), bytes);
                        assert_eq!(FileIdentity::of(&fs::metadata(&path).unwrap()), identity);
                    }
                    assert_eq!(fs::read(&source_path).unwrap(), b"source-a");
                    assert_eq!(
                        FileIdentity::of(&fs::metadata(&source_path).unwrap()),
                        source_before
                    );
                    assert_eq!(
                        fs::read(fixture.source("source-b.img")).unwrap(),
                        b"source-b"
                    );
                }
            }
        }
    }

    #[test]
    fn published_sync_failure_never_accepts_changed_or_replaced_final_files() {
        use staging_io_faults::{Fault, Guard, Operation};
        for kind in [PublicationFileKind::Image, PublicationFileKind::Manifest] {
            for operation in [Operation::ArtifactSync, Operation::OutputParentSync] {
                for replace_inode in [false, true] {
                    let fixture = Fixture::new("published-sync-replacement");
                    let source_path = fixture.source("source-a.img");
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reservation =
                        OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    let path = if kind == PublicationFileKind::Image {
                        fixture.output()
                    } else {
                        fixture.output().with_extension("img.manifest.json")
                    };
                    let receipt = reservation
                        .published_receipt(
                            if kind == PublicationFileKind::Image {
                                3
                            } else {
                                4
                            },
                            if kind == PublicationFileKind::Image {
                                "image-published"
                            } else {
                                "manifest-published"
                            },
                        )
                        .unwrap();
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno: libc::EIO,
                        prefix: 0,
                        skip: 0,
                    });
                    assert!(reservation
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                        .is_err());
                    assert!(guard.observed_size().is_some());
                    drop(guard);
                    let mut bytes = fs::read(&path).unwrap();
                    if replace_inode {
                        fs::rename(&path, fixture.0.join("preserved-final-original")).unwrap();
                    } else {
                        bytes[0] ^= 1;
                    }
                    fs::write(&path, &bytes).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    let identity = FileIdentity::of(&fs::metadata(&path).unwrap());
                    drop(reservation);
                    drop(source);
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reopened =
                        OutputReservation::reopen(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    for _ in 0..2 {
                        assert!(reopened
                            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                            .is_err());
                        assert_eq!(fs::read(&path).unwrap(), bytes);
                        assert_eq!(FileIdentity::of(&fs::metadata(&path).unwrap()), identity);
                        assert!(!fixture
                            .root()
                            .join(receipt.to_string_lossy().as_ref())
                            .exists());
                    }
                    if replace_inode {
                        assert_eq!(
                            fs::read(fixture.0.join("preserved-final-original")).unwrap(),
                            bytes
                        );
                    }
                    source.verify().unwrap();
                    assert_eq!(fs::read(&source_path).unwrap(), b"source-a");
                }
            }
        }
    }

    #[test]
    fn receipt_create_and_partial_write_faults_preserve_ambiguous_evidence() {
        use staging_io_faults::{Fault, Guard, Operation};
        for phase in [
            PublicationPhase::ImageStaged,
            PublicationPhase::ManifestStaged,
            PublicationPhase::ImagePublished,
            PublicationPhase::ManifestPublished,
        ] {
            let staged = matches!(
                phase,
                PublicationPhase::ImageStaged | PublicationPhase::ManifestStaged
            );
            let kind = match phase {
                PublicationPhase::ImageStaged | PublicationPhase::ImagePublished => {
                    PublicationFileKind::Image
                }
                _ => PublicationFileKind::Manifest,
            };
            for (operation, prefix) in [
                (Operation::ReceiptCreate(phase), 0),
                (Operation::ReceiptWrite(phase), 0),
                (Operation::ReceiptWrite(phase), 17),
            ] {
                for errno in [libc::ENOSPC, libc::EDQUOT, libc::EIO] {
                    let fixture = Fixture::new("receipt-storage-failure");
                    let source_path = fixture.source("source-a.img");
                    let source_before = FileIdentity::of(&fs::metadata(&source_path).unwrap());
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reservation =
                        OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    let names = reservation.names().unwrap();
                    let receipt_name = match phase {
                        PublicationPhase::ImageStaged => names.image_receipt,
                        PublicationPhase::ManifestStaged => names.manifest_receipt,
                        PublicationPhase::ImagePublished => {
                            reservation.published_receipt(3, "image-published").unwrap()
                        }
                        PublicationPhase::ManifestPublished => reservation
                            .published_receipt(4, "manifest-published")
                            .unwrap(),
                    };
                    let receipt_path = fixture.root().join(receipt_name.to_string_lossy().as_ref());
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno,
                        prefix,
                        skip: 0,
                    });
                    let error = reservation
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                        .unwrap_err();
                    assert_eq!(error, map_write_error(io::Error::from_raw_os_error(errno)));
                    assert_eq!(guard.observed_size(), Some(prefix as u64));
                    drop(guard);
                    if operation == Operation::ReceiptCreate(phase) {
                        assert!(!receipt_path.exists());
                    } else {
                        assert_eq!(fs::metadata(&receipt_path).unwrap().len(), prefix as u64);
                    }
                    let mut preserved = Vec::new();
                    for directory in [&fixture.0, &fixture.root()] {
                        for entry in fs::read_dir(directory).unwrap() {
                            let entry = entry.unwrap();
                            if entry.file_type().unwrap().is_file() {
                                preserved.push((
                                    entry.path(),
                                    fs::read(entry.path()).unwrap(),
                                    FileIdentity::of(&entry.metadata().unwrap()),
                                ));
                            }
                        }
                    }
                    drop(reservation);
                    drop(source);
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reopened =
                        OutputReservation::reopen(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    if !staged && operation == Operation::ReceiptCreate(phase) {
                        // A missing published receipt can be recovered from the
                        // intact staged chain and exact renamed artifact.
                        assert_eq!(
                            reopened
                                .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                                .unwrap(),
                            PublicationRecovery::Complete
                        );
                    } else {
                        for _ in 0..2 {
                            assert!(reopened
                                .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                                .is_err());
                            for (path, bytes, identity) in &preserved {
                                assert_eq!(&fs::read(path).unwrap(), bytes);
                                assert_eq!(
                                    &FileIdentity::of(&fs::metadata(path).unwrap()),
                                    identity
                                );
                            }
                        }
                    }
                    assert_eq!(fs::read(&source_path).unwrap(), b"source-a");
                    assert_eq!(
                        FileIdentity::of(&fs::metadata(&source_path).unwrap()),
                        source_before
                    );
                    assert_eq!(
                        fs::read(fixture.source("source-b.img")).unwrap(),
                        b"source-b"
                    );
                }
            }
        }
    }

    #[test]
    fn receipt_persistence_rejects_replacement_of_a_validated_snapshot() {
        let fixture = Fixture::new("receipt-persistence-replacement");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        reservation
            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
            .unwrap();
        let name = reservation.names().unwrap().image_receipt;
        let snapshot = read_receipt_snapshot(&reservation.lock.root, &name).unwrap();
        let path = fixture.root().join(name.to_string_lossy().as_ref());
        let original = fs::read(&path).unwrap();
        fs::rename(&path, fixture.root().join("preserved-original-receipt")).unwrap();
        fs::write(&path, &original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            persist_receipt_snapshot(&reservation.lock.root, &snapshot).unwrap_err(),
            "OUTPUT_RECEIPT_CHANGED"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        source.verify().unwrap();
    }

    #[test]
    fn receipt_sync_failure_cannot_be_skipped_after_reopen() {
        use staging_io_faults::{Fault, Guard, Operation};
        for phase in [
            PublicationPhase::ImageStaged,
            PublicationPhase::ManifestStaged,
            PublicationPhase::ImagePublished,
            PublicationPhase::ManifestPublished,
        ] {
            let kind = match phase {
                PublicationPhase::ImageStaged | PublicationPhase::ImagePublished => {
                    PublicationFileKind::Image
                }
                _ => PublicationFileKind::Manifest,
            };
            for operation in [
                Operation::ReceiptSync(phase),
                Operation::ReceiptParentSync(phase),
            ] {
                for errno in [libc::ENOSPC, libc::EDQUOT, libc::EIO] {
                    let fixture = Fixture::new("receipt-sync-retry");
                    let source = SourceReservation::acquire(
                        &fixture.root(),
                        &fixture.source("source-a.img"),
                    )
                    .unwrap();
                    let reservation =
                        OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno,
                        prefix: 0,
                        skip: 0,
                    });
                    assert!(reservation
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                        .is_err());
                    assert!(guard.observed_size().is_some());
                    drop(guard);
                    drop(reservation);
                    drop(source);
                    let source = SourceReservation::acquire(
                        &fixture.root(),
                        &fixture.source("source-a.img"),
                    )
                    .unwrap();
                    let reopened =
                        OutputReservation::reopen(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    // Complete receipt bytes on disk do not prove the failed sync
                    // became durable. A repeated failure must still block completion.
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno,
                        prefix: 0,
                        skip: 0,
                    });
                    let error = reopened
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                        .unwrap_err();
                    assert!(
                        guard.observed_size().is_some(),
                        "recovery skipped failed receipt persistence"
                    );
                    assert_eq!(error, map_write_error(io::Error::from_raw_os_error(errno)));
                    drop(guard);
                    assert_eq!(
                        reopened
                            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                            .unwrap(),
                        PublicationRecovery::Complete
                    );
                    source.verify().unwrap();
                    assert_eq!(fs::read(fixture.output()).unwrap(), TEST_IMAGE);
                }
            }
        }
    }

    #[test]
    fn staging_storage_faults_clean_exact_partial_files_and_resume_after_reopen() {
        use staging_io_faults::{Fault, Guard, Operation};
        let image = vec![0x5a; COPY_CHUNK * 2 + 31];
        for kind in [PublicationFileKind::Image, PublicationFileKind::Manifest] {
            for (operation, prefix) in [
                (Operation::Write, 0),
                (Operation::Write, 17),
                (Operation::Sync, 0),
            ] {
                for errno in [libc::ENOSPC, libc::EDQUOT, libc::EIO] {
                    let fixture = Fixture::new("staging-storage-fault");
                    let source_path = fixture.source("source-a.img");
                    let source_before = FileIdentity::of(&fs::metadata(&source_path).unwrap());
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reservation =
                        OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    let names = reservation.names().unwrap();
                    let stage_name = if kind == PublicationFileKind::Image {
                        &names.image_stage
                    } else {
                        &names.manifest_stage
                    };
                    let receipt_name = if kind == PublicationFileKind::Image {
                        &names.image_receipt
                    } else {
                        &names.manifest_receipt
                    };
                    let skip = usize::from(
                        kind == PublicationFileKind::Image
                            && operation == Operation::Write
                            && prefix > 0,
                    );
                    let guard = Guard::arm(Fault {
                        kind,
                        operation,
                        errno,
                        prefix,
                        skip,
                    });
                    let error = reservation
                        .publish_bytes_with_hook(&source, &image, |_| Ok(()))
                        .unwrap_err();
                    match errno {
                        libc::ENOSPC => assert_eq!(error, "OUTPUT_STORAGE_EXHAUSTED"),
                        libc::EDQUOT => assert_eq!(error, "OUTPUT_STORAGE_QUOTA_EXHAUSTED"),
                        _ => assert!(error.starts_with("OUTPUT_IO_FAILED:")),
                    }
                    let observed = guard.observed_size().expect("fault must actually fire");
                    if operation == Operation::Write {
                        assert_eq!(observed, (skip * COPY_CHUNK + prefix) as u64);
                    } else if kind == PublicationFileKind::Image {
                        assert_eq!(observed, image.len() as u64);
                    } else {
                        assert!(
                            observed > 17,
                            "sync failure must follow a complete manifest write"
                        );
                    }
                    drop(guard);
                    assert!(!fixture
                        .0
                        .join(stage_name.to_string_lossy().as_ref())
                        .exists());
                    assert!(!fixture
                        .root()
                        .join(receipt_name.to_string_lossy().as_ref())
                        .exists());
                    assert!(!fixture.output().exists());
                    assert!(!fixture
                        .output()
                        .with_extension("img.manifest.json")
                        .exists());
                    let image_receipt = fixture
                        .root()
                        .join(names.image_receipt.to_string_lossy().as_ref());
                    let preserved_receipt = if kind == PublicationFileKind::Manifest {
                        assert_eq!(
                            fs::read(fixture.0.join(names.image_stage.to_string_lossy().as_ref()))
                                .unwrap(),
                            image
                        );
                        Some((
                            fs::read(&image_receipt).unwrap(),
                            FileIdentity::of(&fs::metadata(&image_receipt).unwrap()),
                        ))
                    } else {
                        None
                    };
                    drop(reservation);
                    drop(source);
                    let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                    let reopened =
                        OutputReservation::reopen(&fixture.root(), &source, &fixture.output())
                            .unwrap();
                    assert_eq!(
                        reopened
                            .publish_bytes_with_hook(&source, &image, |_| Ok(()))
                            .unwrap(),
                        PublicationRecovery::Complete
                    );
                    assert_eq!(fs::read(fixture.output()).unwrap(), image);
                    if let Some((bytes, identity)) = preserved_receipt {
                        assert_eq!(fs::read(&image_receipt).unwrap(), bytes);
                        assert_eq!(
                            FileIdentity::of(&fs::metadata(&image_receipt).unwrap()),
                            identity
                        );
                    }
                    assert_eq!(fs::read(&source_path).unwrap(), b"source-a");
                    assert_eq!(
                        FileIdentity::of(&fs::metadata(&source_path).unwrap()),
                        source_before
                    );
                    assert_eq!(
                        fs::read(fixture.source("source-b.img")).unwrap(),
                        b"source-b"
                    );
                }
            }
        }
    }

    #[test]
    fn partial_write_failure_preserves_swapped_stage_and_original_descriptor_bytes() {
        use staging_io_faults::{Fault, Guard, Operation};
        for kind in [PublicationFileKind::Image, PublicationFileKind::Manifest] {
            let fixture = Fixture::new("staging-storage-swap");
            let source =
                SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img"))
                    .unwrap();
            let reservation =
                OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
            let names = reservation.names().unwrap();
            let stage_name = if kind == PublicationFileKind::Image {
                &names.image_stage
            } else {
                &names.manifest_stage
            };
            let stage = fixture.0.join(stage_name.to_string_lossy().as_ref());
            let moved = fixture.0.join("moved-owned-stage");
            let guard = Guard::arm(Fault {
                kind,
                operation: Operation::Write,
                errno: libc::ENOSPC,
                prefix: 7,
                skip: 0,
            });
            let error = reservation
                .publish_bytes_with_hook(&source, TEST_IMAGE, |phase| {
                    let target = if kind == PublicationFileKind::Image {
                        "image-stage-created"
                    } else {
                        "manifest-stage-created"
                    };
                    if phase == target {
                        fs::rename(&stage, &moved).unwrap();
                        fs::write(&stage, b"foreign").unwrap();
                        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error, "OUTPUT_STAGE_CHANGED");
            assert_eq!(guard.observed_size(), Some(7));
            drop(guard);
            assert_eq!(fs::read(&stage).unwrap(), b"foreign");
            let expected = if kind == PublicationFileKind::Image {
                TEST_IMAGE.to_vec()
            } else {
                expected_manifest(&source.sha256)
            };
            assert_eq!(fs::read(&moved).unwrap(), &expected[..7]);
            assert!(!fixture.output().exists());
            assert!(!fixture
                .output()
                .with_extension("img.manifest.json")
                .exists());
            assert!(reservation
                .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                .is_err());
            assert_eq!(fs::read(&stage).unwrap(), b"foreign");
            assert_eq!(fs::read(&moved).unwrap(), &expected[..7]);
            source.verify().unwrap();
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
    fn source_and_output_must_share_the_same_lock_directory() {
        let fixture = Fixture::new("split-lock-roots");
        let other_root = fixture.0.join("other-private");
        fs::create_dir(&other_root).unwrap();
        fs::set_permissions(&other_root, fs::Permissions::from_mode(0o700)).unwrap();
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        assert_eq!(
            OutputReservation::acquire(&other_root, &source, &fixture.output()).unwrap_err(),
            "OUTPUT_SOURCE_LOCK_ROOT_MISMATCH"
        );
        assert_eq!(
            OutputReservation::reopen(&other_root, &source, &fixture.output()).unwrap_err(),
            "OUTPUT_SOURCE_LOCK_ROOT_MISMATCH"
        );
        assert_eq!(fs::read_dir(&other_root).unwrap().count(), 0);
        // Compare directory identities, not spelling of the supplied root path.
        let reservation =
            OutputReservation::acquire(&fixture.root().join("."), &source, &fixture.output())
                .unwrap();
        reservation.verify_guards(&source).unwrap();
        assert!(!fixture.output().exists());
    }

    #[test]
    fn equal_source_guards_from_different_lock_roots_cannot_publish() {
        let fixture = Fixture::new("source-guard-lock-root");
        let other_root = fixture.0.join("other-private");
        fs::create_dir(&other_root).unwrap();
        fs::set_permissions(&other_root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fixture.source("source-a.img");
        let source = SourceReservation::acquire(&fixture.root(), &path).unwrap();
        let other = SourceReservation::acquire(&other_root, &path).unwrap();
        assert_eq!(source.identity, other.identity);
        assert_eq!(source.sha256, other.sha256);
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        for _ in 0..2 {
            assert_eq!(
                reservation
                    .publish_bytes_with_hook(&other, TEST_IMAGE, |_| panic!(
                        "split lock roots reached publication"
                    ))
                    .unwrap_err(),
                "OUTPUT_SOURCE_LOCK_ROOT_MISMATCH"
            );
            assert!(!fixture.output().exists());
            assert!(!fixture
                .0
                .join(reservation.names().unwrap().image_stage.to_str().unwrap())
                .exists());
        }
        assert_eq!(
            reservation
                .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                .unwrap(),
            PublicationRecovery::Complete
        );
        assert_eq!(
            reservation
                .publish_bytes_with_hook(&other, TEST_IMAGE, |_| panic!(
                    "split lock roots reached recovery"
                ))
                .unwrap_err(),
            "OUTPUT_SOURCE_LOCK_ROOT_MISMATCH"
        );
        source.verify().unwrap();
        other.verify().unwrap();
    }

    #[test]
    fn publication_rejects_an_unrelated_source_guard_in_every_recovery_state() {
        for phase in ["reserved", "image-staged", "complete"] {
            for identical_bytes in [false, true] {
                let fixture = Fixture::new("publication-source-binding");
                let source_path = fixture.source("source-a.img");
                let other_path = fixture.source("source-b.img");
                if identical_bytes {
                    fs::write(&other_path, b"source-a").unwrap();
                }
                let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                let other = SourceReservation::acquire(&fixture.root(), &other_path).unwrap();
                let reservation =
                    OutputReservation::acquire(&fixture.root(), &source, &fixture.output())
                        .unwrap();
                if phase == "image-staged" {
                    assert_eq!(
                        reservation
                            .publish_bytes_with_hook(&source, TEST_IMAGE, |at| {
                                if at == "image-receipt-synced" {
                                    Err("test-stop".into())
                                } else {
                                    Ok(())
                                }
                            })
                            .unwrap_err(),
                        "test-stop"
                    );
                } else if phase == "complete" {
                    assert_eq!(
                        reservation
                            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                            .unwrap(),
                        PublicationRecovery::Complete
                    );
                }
                let snapshot = || {
                    let mut files = Vec::new();
                    for parent in [&fixture.0, &fixture.root()] {
                        for entry in fs::read_dir(parent).unwrap() {
                            let path = entry.unwrap().path();
                            if path.is_file() {
                                files.push((
                                    path.clone(),
                                    fs::read(&path).unwrap(),
                                    FileIdentity::of(&fs::metadata(&path).unwrap()),
                                ));
                            }
                        }
                    }
                    files.sort_by(|a, b| a.0.cmp(&b.0));
                    files
                };
                let before = snapshot();
                for _ in 0..2 {
                    assert_eq!(
                        reservation
                            .publish_bytes_with_hook(&other, TEST_IMAGE, |_| panic!(
                                "mismatched guard reached publication"
                            ))
                            .unwrap_err(),
                        "OUTPUT_SOURCE_RESERVATION_MISMATCH"
                    );
                    assert_eq!(snapshot(), before);
                }
                drop(source);
                let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
                assert_eq!(
                    reservation
                        .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                        .unwrap(),
                    PublicationRecovery::Complete
                );
                source.verify().unwrap();
                other.verify().unwrap();
            }
        }
    }

    #[test]
    fn unrelated_guard_cannot_hide_mutation_of_the_reserved_source() {
        let fixture = Fixture::new("changed-source-substitution");
        let path = fixture.source("source-a.img");
        let source = SourceReservation::acquire(&fixture.root(), &path).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        drop(source);
        fs::write(&path, b"changed!").unwrap();
        let other =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-b.img")).unwrap();
        assert_eq!(
            reservation
                .publish_bytes_with_hook(&other, TEST_IMAGE, |_| panic!("unexpected publication"))
                .unwrap_err(),
            "OUTPUT_SOURCE_RESERVATION_MISMATCH"
        );
        let changed = SourceReservation::acquire(&fixture.root(), &path).unwrap();
        assert_eq!(
            reservation
                .publish_bytes_with_hook(&changed, TEST_IMAGE, |_| panic!("unexpected publication"))
                .unwrap_err(),
            "OUTPUT_SOURCE_RESERVATION_MISMATCH"
        );
        assert!(!fixture.output().exists());
        assert!(!fixture
            .output()
            .with_extension("img.manifest.json")
            .exists());
        assert!(!fixture
            .0
            .join(reservation.names().unwrap().image_stage.to_str().unwrap())
            .exists());
        assert_eq!(fs::read(path).unwrap(), b"changed!");
        other.verify().unwrap();
        changed.verify().unwrap();
    }

    #[test]
    fn overlapping_image_manifest_reservations_are_exclusive_in_both_orders() {
        for reverse in [false, true] {
            let fixture = Fixture::new("overlapping-output-pairs");
            let a = SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img"))
                .unwrap();
            let b = SourceReservation::acquire(&fixture.root(), &fixture.source("source-b.img"))
                .unwrap();
            let output = fixture.output();
            let manifest = output.with_extension("img.manifest.json");
            let (first_path, second_path) = if reverse {
                (&manifest, &output)
            } else {
                (&output, &manifest)
            };
            let first = OutputReservation::acquire(&fixture.root(), &a, first_path).unwrap();
            assert_eq!(
                OutputReservation::acquire(&fixture.root(), &b, second_path).unwrap_err(),
                "RESERVATION_ALREADY_HELD"
            );
            first.verify().unwrap();
            drop(first);
            // A failed second-lock acquisition must not strand its first lock.
            let second = OutputReservation::acquire(&fixture.root(), &b, second_path).unwrap();
            assert_eq!(
                OutputReservation::reopen(&fixture.root(), &a, first_path).unwrap_err(),
                "RESERVATION_ALREADY_HELD"
            );
            second.verify().unwrap();
            drop(second);
            OutputReservation::reopen(&fixture.root(), &a, first_path)
                .unwrap()
                .verify()
                .unwrap();
            assert!(!output.exists());
            assert!(!manifest.exists());
            assert_eq!(
                fs::read(fixture.source("source-a.img")).unwrap(),
                b"source-a"
            );
            assert_eq!(
                fs::read(fixture.source("source-b.img")).unwrap(),
                b"source-b"
            );
        }
    }

    #[test]
    fn manifest_lock_replacement_blocks_staging_and_preserves_sources() {
        let fixture = Fixture::new("manifest-lock-replacement");
        let source_path = fixture.source("source-a.img");
        let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        let lock_path = fixture
            .root()
            .join(reservation.manifest_lock.basename.to_str().unwrap());
        fs::rename(&lock_path, fixture.root().join("preserved-manifest-lock")).unwrap();
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            reservation.verify().unwrap_err(),
            "RESERVATION_LOCK_CHANGED"
        );
        assert_eq!(
            reservation
                .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
                .unwrap_err(),
            "RESERVATION_LOCK_CHANGED"
        );
        assert!(!fixture.output().exists());
        assert!(!fixture
            .0
            .join(reservation.names().unwrap().image_stage.to_str().unwrap())
            .exists());
        assert_eq!(fs::read(source_path).unwrap(), b"source-a");
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
    fn committed_pair_rejects_a_semantically_forged_receipt_chain() {
        let fixture = Fixture::new("forged-receipt-chain");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        reservation
            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
            .unwrap();
        let names = reservation.names().unwrap();
        let image_published = reservation.published_receipt(3, "image-published").unwrap();
        let manifest_published = reservation
            .published_receipt(4, "manifest-published")
            .unwrap();

        let mut image_staged = read_receipt(&reservation.lock.root, &names.image_receipt).unwrap();
        image_staged.phase = PublicationPhase::ManifestStaged;
        overwrite_receipt(&fixture.root(), &names.image_receipt, &image_staged);

        let mut manifest_staged =
            read_receipt(&reservation.lock.root, &names.manifest_receipt).unwrap();
        manifest_staged.previous_receipt_sha256 = Some(canonical_sha256(&image_staged).unwrap());
        overwrite_receipt(&fixture.root(), &names.manifest_receipt, &manifest_staged);

        let mut image_published_receipt =
            read_receipt(&reservation.lock.root, &image_published).unwrap();
        image_published_receipt.previous_receipt_sha256 =
            Some(canonical_sha256(&manifest_staged).unwrap());
        overwrite_receipt(&fixture.root(), &image_published, &image_published_receipt);

        let mut manifest_published_receipt =
            read_receipt(&reservation.lock.root, &manifest_published).unwrap();
        manifest_published_receipt.previous_receipt_sha256 =
            Some(canonical_sha256(&image_published_receipt).unwrap());
        overwrite_receipt(
            &fixture.root(),
            &manifest_published,
            &manifest_published_receipt,
        );

        let manifest = expected_manifest(&source.sha256);
        assert!(reservation
            .verify_committed_pair(&source, TEST_IMAGE, &manifest)
            .unwrap_err()
            .contains("receipt chain mismatch"));
    }

    #[test]
    fn committed_pair_rejects_forged_staged_payload_claims() {
        let fixture = Fixture::new("forged-staged-payload");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        reservation
            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
            .unwrap();
        let names = reservation.names().unwrap();
        let image_published = reservation.published_receipt(3, "image-published").unwrap();
        let manifest_published = reservation
            .published_receipt(4, "manifest-published")
            .unwrap();

        let mut image_staged = read_receipt(&reservation.lock.root, &names.image_receipt).unwrap();
        image_staged.sha256 = "0".repeat(64);
        image_staged.file_identity.size += 1;
        overwrite_receipt(&fixture.root(), &names.image_receipt, &image_staged);

        let mut manifest_staged =
            read_receipt(&reservation.lock.root, &names.manifest_receipt).unwrap();
        manifest_staged.previous_receipt_sha256 = Some(canonical_sha256(&image_staged).unwrap());
        overwrite_receipt(&fixture.root(), &names.manifest_receipt, &manifest_staged);

        let mut image_published_receipt =
            read_receipt(&reservation.lock.root, &image_published).unwrap();
        image_published_receipt.previous_receipt_sha256 =
            Some(canonical_sha256(&manifest_staged).unwrap());
        overwrite_receipt(&fixture.root(), &image_published, &image_published_receipt);

        let mut manifest_published_receipt =
            read_receipt(&reservation.lock.root, &manifest_published).unwrap();
        manifest_published_receipt.previous_receipt_sha256 =
            Some(canonical_sha256(&image_published_receipt).unwrap());
        overwrite_receipt(
            &fixture.root(),
            &manifest_published,
            &manifest_published_receipt,
        );

        let manifest = expected_manifest(&source.sha256);
        let error = reservation
            .verify_committed_pair(&source, TEST_IMAGE, &manifest)
            .unwrap_err();
        assert!(
            error.contains("staged receipt payload mismatch")
                || error.contains("staged and published receipt mismatch"),
            "unexpected staged-claim result: {error}"
        );
    }

    #[test]
    fn committed_pair_rejects_receipt_replacement_after_predecessor_validation() {
        let fixture = Fixture::new("receipt-replaced-after-validation");
        let source =
            SourceReservation::acquire(&fixture.root(), &fixture.source("source-a.img")).unwrap();
        let reservation =
            OutputReservation::acquire(&fixture.root(), &source, &fixture.output()).unwrap();
        reservation
            .publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()))
            .unwrap();
        let image_published = reservation.published_receipt(3, "image-published").unwrap();
        let manifest_published = reservation
            .published_receipt(4, "manifest-published")
            .unwrap();
        let manifest = expected_manifest(&source.sha256);

        let error = reservation
            .verify_committed_pair_with_hook(&source, TEST_IMAGE, &manifest, || {
                let mut replaced = read_receipt(&reservation.lock.root, &image_published).unwrap();
                replaced.sha256 = "0".repeat(64);
                overwrite_receipt(&fixture.root(), &image_published, &replaced);

                let mut successor =
                    read_receipt(&reservation.lock.root, &manifest_published).unwrap();
                successor.previous_receipt_sha256 = Some(canonical_sha256(&replaced).unwrap());
                overwrite_receipt(&fixture.root(), &manifest_published, &successor);
            })
            .unwrap_err();

        assert!(
            error.contains("receipt chain mismatch") || error.contains("OUTPUT_RECEIPT_CHANGED"),
            "unexpected receipt-race result: {error}"
        );
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
    fn subprocess_sigkill_boundaries_are_fail_closed_and_restartable() {
        struct Boundary {
            phase: &'static str,
            resumable: bool,
            committed_at_kill: bool,
        }

        for boundary in [
            Boundary {
                phase: "image-stage-synced",
                resumable: false,
                committed_at_kill: false,
            },
            Boundary {
                phase: "image-receipt-synced",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "manifest-stage-synced",
                resumable: false,
                committed_at_kill: false,
            },
            Boundary {
                phase: "manifest-receipt-synced",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "image-renamed",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "image-parent-synced",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "image-published-receipt-synced",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "manifest-renamed",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "manifest-parent-synced",
                resumable: true,
                committed_at_kill: false,
            },
            Boundary {
                phase: "manifest-published-receipt-synced",
                resumable: true,
                committed_at_kill: true,
            },
        ] {
            let fixture = Fixture::new(&format!("sigkill-{}", boundary.phase));
            let source_path = fixture.source("source-a.img");
            let source_before = fs::read(&source_path).unwrap();
            let foreign_output = fixture.0.join("foreign.keep");
            let foreign_private = fixture.root().join("foreign.keep");
            fs::write(&foreign_output, b"outside-transaction").unwrap();
            fs::write(&foreign_private, b"private-foreign").unwrap();
            fs::set_permissions(&foreign_private, fs::Permissions::from_mode(0o600)).unwrap();
            let (authority, nonce) = publication_worker_authority(&fixture);
            let mut child = WorkerGuard::new(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "output_transaction::tests::publication_sigkill_worker",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env("PUBLICATION_TEST_ROOT", fixture.root())
                    .env("PUBLICATION_TEST_SOURCE", &source_path)
                    .env("PUBLICATION_TEST_OUTPUT", fixture.output())
                    .env("PUBLICATION_TEST_PHASE", boundary.phase)
                    .env("PUBLICATION_TEST_AUTHORITY", &authority)
                    .env("PUBLICATION_TEST_NONCE", &nonce)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            wait_for_worker(&mut child, boundary.phase);
            kill_worker(&mut child);

            assert_eq!(fs::read(&source_path).unwrap(), source_before);
            assert_eq!(fs::read(&foreign_output).unwrap(), b"outside-transaction");
            assert_eq!(fs::read(&foreign_private).unwrap(), b"private-foreign");
            assert_residue_is_bounded(&fixture);

            // Reacquisition proves both process-owned flock capabilities were
            // released by SIGKILL. Reopen additionally binds the durable
            // reservation to the exact source, parent, and lock inode.
            let source = SourceReservation::acquire(&fixture.root(), &source_path).unwrap();
            let recovered =
                OutputReservation::reopen(&fixture.root(), &source, &fixture.output()).unwrap();
            let manifest = expected_manifest(&source.sha256);
            assert_eq!(
                recovered
                    .verify_committed_pair(&source, TEST_IMAGE, &manifest)
                    .is_ok(),
                boundary.committed_at_kill,
                "wrong trust state after SIGKILL at {}",
                boundary.phase
            );

            let result = recovered.publish_bytes_with_hook(&source, TEST_IMAGE, |_| Ok(()));
            if boundary.resumable {
                assert_eq!(
                    result.unwrap(),
                    PublicationRecovery::Complete,
                    "failed to resume {}",
                    boundary.phase
                );
                recovered
                    .verify_committed_pair(&source, TEST_IMAGE, &manifest)
                    .unwrap();
                assert_eq!(fs::read(fixture.output()).unwrap(), TEST_IMAGE);
                assert_eq!(
                    fs::read(fixture.output().with_extension("img.manifest.json")).unwrap(),
                    manifest
                );
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.contains("STAGE_EXISTS"),
                    "unexpected fail-closed result at {}: {error}",
                    boundary.phase
                );
                assert!(recovered
                    .verify_committed_pair(&source, TEST_IMAGE, &manifest)
                    .is_err());
            }

            assert_eq!(fs::read(&source_path).unwrap(), source_before);
            assert_eq!(fs::read(&foreign_output).unwrap(), b"outside-transaction");
            assert_eq!(fs::read(&foreign_private).unwrap(), b"private-foreign");
            assert_residue_is_bounded(&fixture);
        }
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
        assert_eq!(
            OutputReservation::acquire(
                &fixture.root(),
                &other,
                &fixture.output().with_extension("img.manifest.json")
            )
            .unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        let renamed = fixture.source("renamed-source.img");
        fs::rename(fixture.source("source-a.img"), &renamed).unwrap();
        assert_eq!(
            SourceReservation::acquire(&fixture.root(), &renamed).unwrap_err(),
            "RESERVATION_ALREADY_HELD"
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        SourceReservation::acquire(&fixture.root(), &renamed)
            .unwrap()
            .verify()
            .unwrap();
        assert_eq!(fs::read(&renamed).unwrap(), b"source-a");
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
            source.inode_lock.file.metadata().unwrap().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            output_reservation.lock.file.metadata().unwrap().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            output_reservation
                .manifest_lock
                .file
                .metadata()
                .unwrap()
                .mode()
                & 0o7777,
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

    #[test]
    #[ignore = "subprocess helper for SIGKILL publication boundaries"]
    fn publication_sigkill_worker() {
        let root = fs::canonicalize(PathBuf::from(
            std::env::var_os("PUBLICATION_TEST_ROOT").unwrap(),
        ))
        .unwrap();
        let source_path = fs::canonicalize(PathBuf::from(
            std::env::var_os("PUBLICATION_TEST_SOURCE").unwrap(),
        ))
        .unwrap();
        let output = PathBuf::from(std::env::var_os("PUBLICATION_TEST_OUTPUT").unwrap());
        let authority = fs::canonicalize(PathBuf::from(
            std::env::var_os("PUBLICATION_TEST_AUTHORITY").unwrap(),
        ))
        .unwrap();
        let nonce = std::env::var("PUBLICATION_TEST_NONCE").unwrap();
        let target_phase = std::env::var("PUBLICATION_TEST_PHASE").unwrap();
        let fixture = root.parent().unwrap().to_path_buf();
        let fixture_name = fixture.file_name().unwrap().as_bytes();
        assert!(fixture_name.starts_with(b"steamos-reservation-foundation-sigkill-"));
        assert_eq!(root, fixture.join("private"));
        assert_eq!(source_path, fixture.join("source-a.img"));
        assert_eq!(output.parent().unwrap().canonicalize().unwrap(), fixture);
        assert_eq!(output.file_name().unwrap(), OsStr::new("result.img"));
        assert_eq!(authority, fixture.join(".publication-worker-authority"));
        let authority_metadata = fs::metadata(&authority).unwrap();
        assert!(authority_metadata.file_type().is_file());
        assert_eq!(authority_metadata.nlink(), 1);
        assert_eq!(authority_metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(authority_metadata.mode() & 0o7777, 0o600);
        assert!(is_sha256(&nonce));
        assert_eq!(fs::read_to_string(&authority).unwrap(), nonce);
        thread::spawn(|| {
            let mut byte = [0_u8; 1];
            let _ = io::stdin().read(&mut byte);
            std::process::exit(99);
        });
        let source = SourceReservation::acquire(&root, &source_path).unwrap();
        let reservation = OutputReservation::acquire(&root, &source, &output).unwrap();
        reservation
            .publish_bytes_with_hook(&source, TEST_IMAGE, |phase| {
                if phase == target_phase {
                    println!("\nPUBLICATION_READY:{phase}");
                    io::stdout().flush().unwrap();
                    loop {
                        thread::park_timeout(Duration::from_secs(60));
                    }
                }
                Ok(())
            })
            .unwrap();
        panic!("publication worker passed requested boundary without stopping");
    }
}
