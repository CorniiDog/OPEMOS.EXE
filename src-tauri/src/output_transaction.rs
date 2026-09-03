//! Inactive descriptor-bound reservation foundation.
//!
//! Publication and stale cleanup are intentionally absent. Interrupted durable
//! state is preserved and reported as recovery-required.

use super::*;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};

const RECORD_LIMIT: u64 = 8 * 1024;
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
    phase: OutputPhase,
    source_identity: FileIdentity,
    source_sha256: String,
    parent_identity: FileIdentity,
    output_basename: String,
    manifest_basename: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum OutputPhase {
    Reserved,
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
    source_identity: FileIdentity,
    source_sha256: String,
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
        let mut key = b"output\0".to_vec();
        key.extend_from_slice(&parent.identity.device.to_le_bytes());
        key.extend_from_slice(&parent.identity.inode.to_le_bytes());
        key.extend_from_slice(output.as_bytes());
        let lock = LockCapability::acquire(root, &key)?;
        let stem = lock
            .basename
            .to_str()
            .map_err(|_| "LOCK_BASENAME_UTF8")?
            .strip_suffix(".lock")
            .ok_or("LOCK_BASENAME_INVALID")?;
        let record = strict_basename(&format!("{stem}.record"))?;
        inspect_record(&lock.root, &record)?;
        let mut result = Self {
            lock,
            parent,
            output,
            manifest,
            record,
            source_identity: source.identity,
            source_sha256: source.sha256.clone(),
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
            schema_version: 1,
            phase: OutputPhase::Reserved,
            source_identity: self.source_identity,
            source_sha256: self.source_sha256.clone(),
            parent_identity: self.parent.identity,
            output_basename: self.output.to_string_lossy().into_owned(),
            manifest_basename: self.manifest.to_string_lossy().into_owned(),
        }
    }

    fn create_record(&mut self) -> Result<(), String> {
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
        self.lock.root.file.sync_all().map_err(|e| e.to_string())
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
    let value: OutputRecord =
        serde_json::from_slice(&bytes).map_err(|_| RECORD_MALFORMED.to_string())?;
    let mut canonical = serde_json::to_vec(&value).map_err(|_| RECORD_MALFORMED.to_string())?;
    canonical.push(b'\n');
    if bytes != canonical
        || value.schema_version != 1
        || value.source_sha256.len() != 64
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
