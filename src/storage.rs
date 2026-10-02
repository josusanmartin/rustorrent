use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
#[cfg(not(any(unix, windows)))]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(unix)]
use std::ffi::CString;
#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::torrent::TorrentMeta;

#[cfg_attr(test, derive(Debug))]
pub struct Storage {
    entries: Vec<FileEntry>,
    root: PathBuf,
    #[cfg(unix)]
    root_directory: File,
    #[cfg(windows)]
    root_directory: crate::windows_fs::PinnedDir,
    total_length: u64,
    write_cache: Vec<WriteEntry>,
    write_cache_bytes: usize,
    write_cache_limit: usize,
}

#[derive(Clone, Copy)]
pub struct StorageMetrics {
    pub read_ops: u64,
    pub read_ns: u64,
    pub write_ops: u64,
    pub write_ns: u64,
}

static READ_OPS: AtomicU64 = AtomicU64::new(0);
static READ_NS: AtomicU64 = AtomicU64::new(0);
static WRITE_OPS: AtomicU64 = AtomicU64::new(0);
static WRITE_NS: AtomicU64 = AtomicU64::new(0);

fn record(ops: &AtomicU64, total_ns: &AtomicU64, start: Instant) {
    ops.fetch_add(1, Ordering::Relaxed);
    total_ns.fetch_add(
        u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(unix)]
fn write_all_at(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_write(buf, offset) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(mut file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)
}

#[cfg(not(any(unix, windows)))]
fn write_all_at(mut file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(buf)
}

pub fn metrics_snapshot() -> StorageMetrics {
    StorageMetrics {
        read_ops: READ_OPS.load(Ordering::Relaxed),
        read_ns: READ_NS.load(Ordering::Relaxed),
        write_ops: WRITE_OPS.load(Ordering::Relaxed),
        write_ns: WRITE_NS.load(Ordering::Relaxed),
    }
}

#[derive(Clone, Copy, Default)]
pub struct StorageOptions {
    pub preallocate: bool,
    pub write_cache_bytes: usize,
}

#[cfg_attr(test, derive(Debug))]
struct FileEntry {
    path: PathBuf,
    offset: u64,
    length: u64,
    file: File,
    /// Written since the last successful `flush` sync.
    dirty: bool,
    #[cfg(windows)]
    parent_identity: crate::windows_fs::FileIdentity,
}

struct OpenedPayload {
    file: File,
    #[cfg(windows)]
    parent_identity: crate::windows_fs::FileIdentity,
}

enum Transfer<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

#[cfg_attr(test, derive(Debug))]
struct WriteEntry {
    offset: u64,
    data: Vec<u8>,
}

#[cfg_attr(test, derive(Debug))]
struct FileLayout {
    path: PathBuf,
    offset: u64,
    length: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidName,
    InvalidPathSegment,
    InvalidFiles,
    InvalidLength,
    OutOfBounds,
    SymlinkNotAllowed,
    InsufficientDiskSpace,
    PayloadInUse,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Io(err) => return write!(f, "io error: {err}"),
            Error::InvalidName => "invalid torrent name",
            Error::InvalidPathSegment => "invalid path segment",
            Error::InvalidFiles => "invalid file list",
            Error::InvalidLength => "invalid length",
            Error::OutOfBounds => "read/write out of bounds",
            Error::SymlinkNotAllowed => "symlinks are not allowed in torrent paths",
            Error::InsufficientDiskSpace => "insufficient disk space",
            Error::PayloadInUse => "torrent payload is already in use",
        })
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl Storage {
    pub fn new(
        meta: &TorrentMeta,
        download_dir: &Path,
        options: StorageOptions,
    ) -> Result<Self, Error> {
        Self::new_with_file_renames(meta, download_dir, options, &[])
    }

    pub fn new_with_file_renames(
        meta: &TorrentMeta,
        download_dir: &Path,
        options: StorageOptions,
        file_renames: &[(usize, String)],
    ) -> Result<Self, Error> {
        Self::open(meta, download_dir, options, file_renames, true)
    }

    /// Open an existing payload without creating directories or files. This is
    /// used to verify a crash-recovery destination before adopting it.
    pub fn open_existing_with_file_renames(
        meta: &TorrentMeta,
        download_dir: &Path,
        file_renames: &[(usize, String)],
    ) -> Result<Self, Error> {
        Self::open(
            meta,
            download_dir,
            StorageOptions::default(),
            file_renames,
            false,
        )
    }

    fn open(
        meta: &TorrentMeta,
        download_dir: &Path,
        options: StorageOptions,
        file_renames: &[(usize, String)],
        create: bool,
    ) -> Result<Self, Error> {
        let mut layouts = build_layout(meta, download_dir)?;
        apply_saved_file_renames(&mut layouts, file_renames)?;
        validate_no_reserved_state_paths(download_dir, &layouts)?;
        let total_length = layouts
            .iter()
            .try_fold(0u64, |end, layout| {
                Some(end.max(layout.offset.checked_add(layout.length)?))
            })
            .ok_or(Error::InvalidLength)?;
        #[cfg(unix)]
        raise_open_file_limit();
        if create {
            fs::create_dir_all(download_dir)?;
        }
        #[cfg(unix)]
        let root_directory = open_directory_no_follow(download_dir)?;
        #[cfg(windows)]
        let root_directory =
            crate::windows_fs::PinnedDir::open(download_dir).map_err(windows_path_error)?;
        let mut entries = Vec::with_capacity(layouts.len());
        for layout in layouts {
            #[cfg(unix)]
            let opened =
                open_payload_file_unix(&root_directory, download_dir, &layout.path, create)?;
            #[cfg(windows)]
            let opened =
                open_payload_file_windows(&root_directory, download_dir, &layout.path, create)?;
            #[cfg(not(any(unix, windows)))]
            let opened = {
                if let Some(parent) = layout.path.parent().filter(|_| create) {
                    if !parent.as_os_str().is_empty() {
                        create_dir_secure(download_dir, parent)?;
                    }
                }
                open_payload_file(&layout.path, create)?
            };
            opened.file.try_lock().map_err(|_| Error::PayloadInUse)?;
            if create && opened.file.metadata()?.len() > layout.length {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "existing file is larger than the torrent file; choose another download folder",
                )));
            }
            entries.push(FileEntry {
                path: layout.path,
                offset: layout.offset,
                length: layout.length,
                #[cfg(windows)]
                parent_identity: opened.parent_identity,
                file: opened.file,
                dirty: false,
            });
        }
        validate_distinct_files(&entries)?;
        // Validate every path and file identity before changing any file size.
        if create && options.preallocate {
            for entry in &entries {
                entry.file.set_len(entry.length).map_err(|err| {
                    if is_disk_full(&err) {
                        Error::InsufficientDiskSpace
                    } else {
                        Error::Io(err)
                    }
                })?;
            }
        }

        Ok(Self {
            entries,
            root: download_dir.to_path_buf(),
            #[cfg(any(unix, windows))]
            root_directory,
            total_length,
            write_cache: Vec::new(),
            write_cache_bytes: 0,
            write_cache_limit: options.write_cache_bytes,
        })
    }

    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    pub fn file_path(&self, file_index: usize) -> Option<&Path> {
        self.entries
            .get(file_index)
            .map(|entry| entry.path.as_path())
    }

    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.write_at_inner(offset, data);
        record(&WRITE_OPS, &WRITE_NS, start);
        result
    }

    fn write_at_inner(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        self.check_bounds(offset, data.len())?;
        if data.is_empty() {
            return Ok(());
        }
        if data.len() >= self.write_cache_limit {
            // Also covers a disabled cache (limit 0). Earlier cached writes are
            // flushed first so overlapping ranges keep their write order.
            self.flush_cache()?;
            return self.transfer(offset, Transfer::Write(data));
        }
        self.write_cache.push(WriteEntry {
            offset,
            data: data.to_vec(),
        });
        self.write_cache_bytes = self.write_cache_bytes.saturating_add(data.len());
        if self.write_cache_bytes >= self.write_cache_limit {
            self.flush_cache()?;
        }
        Ok(())
    }

    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        let start = Instant::now();
        let read_end = offset.saturating_add(out.len() as u64);
        let overlaps = self.write_cache.iter().any(|entry| {
            let entry_end = entry.offset.saturating_add(entry.data.len() as u64);
            entry.offset < read_end && entry_end > offset
        });
        let result = if overlaps { self.flush_cache() } else { Ok(()) }
            .and_then(|()| self.transfer(offset, Transfer::Read(out)));
        record(&READ_OPS, &READ_NS, start);
        result
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<(), Error> {
        match offset.checked_add(len as u64) {
            Some(end) if end <= self.total_length => Ok(()),
            _ => Err(Error::OutOfBounds),
        }
    }

    /// Positioned I/O across file boundaries. Entries are sorted by offset,
    /// so the first touched file is found by binary search instead of a scan
    /// over every file, and positioned reads/writes avoid a seek per block.
    fn transfer(&mut self, offset: u64, mut io: Transfer<'_>) -> Result<(), Error> {
        let len = match &io {
            Transfer::Read(buf) => buf.len(),
            Transfer::Write(buf) => buf.len(),
        };
        self.check_bounds(offset, len)?;
        let mut index = self
            .entries
            .partition_point(|entry| entry.offset + entry.length <= offset);
        let mut cursor = offset;
        let mut done = 0usize;
        while done < len {
            let entry = self.entries.get_mut(index).ok_or(Error::OutOfBounds)?;
            index += 1;
            // v2 layouts pad files to piece boundaries; the gap is not backed
            // by any file and must never be read or written.
            if cursor < entry.offset {
                return Err(Error::OutOfBounds);
            }
            let available = (entry.offset + entry.length)
                .checked_sub(cursor)
                .ok_or(Error::OutOfBounds)?;
            let take = available.min((len - done) as u64) as usize;
            if take == 0 {
                continue;
            }
            let at = cursor - entry.offset;
            let range = done..done + take;
            match &mut io {
                Transfer::Read(buf) => read_exact_at(&entry.file, &mut buf[range], at)?,
                Transfer::Write(buf) => {
                    entry.dirty = true;
                    write_all_at(&entry.file, &buf[range], at)?;
                }
            }
            done += take;
            cursor += take as u64;
        }
        Ok(())
    }

    /// Write queued blocks to the files. Durability is established by
    /// `flush`, which syncs every file written since the previous flush; an
    /// fsync here would run once per cache fill or overlapping read.
    fn flush_cache(&mut self) -> Result<(), Error> {
        let pending = std::mem::take(&mut self.write_cache);
        self.write_cache_bytes = 0;
        for (idx, entry) in pending.iter().enumerate() {
            if let Err(err) = self.transfer(entry.offset, Transfer::Write(&entry.data)) {
                let remaining = pending.into_iter().skip(idx).collect::<Vec<_>>();
                self.write_cache_bytes = remaining.iter().map(|e| e.data.len()).sum();
                self.write_cache = remaining;
                return Err(err);
            }
        }
        Ok(())
    }

    /// Persist all queued writes and report any write or sync failure.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_cache()?;
        for entry in &mut self.entries {
            if entry.dirty {
                entry.file.sync_data()?;
                entry.dirty = false;
            }
        }
        Ok(())
    }

    pub fn rename_file(
        &mut self,
        file_index: usize,
        old_path: &Path,
        new_path: &Path,
    ) -> Result<(), Error> {
        self.validate_file_rename(file_index, old_path, new_path)?;
        self.flush_cache()?;
        #[cfg(unix)]
        {
            let new_name = new_path.file_name().ok_or(Error::InvalidPathSegment)?;
            let (parent, old_name) =
                open_payload_parent_unix(&self.root_directory, &self.root, old_path, false)?;
            let entry = &mut self.entries[file_index];
            verify_open_file_entry(&parent, &old_name, &entry.file)?;
            rename_at_no_overwrite(&parent, &old_name, new_name)?;
        }
        #[cfg(windows)]
        {
            let new_name = new_path.file_name().ok_or(Error::InvalidPathSegment)?;
            let relative = old_path
                .strip_prefix(&self.root)
                .map_err(|_| Error::InvalidPathSegment)?;
            let parent = relative.parent().unwrap_or_else(|| Path::new(""));
            let entry = &mut self.entries[file_index];
            let info = crate::windows_fs::file_info(&entry.file).map_err(windows_path_error)?;
            if info.is_directory() || info.is_reparse_point() || info.number_of_links != 1 {
                return Err(Error::InvalidFiles);
            }
            let opened_parent = self
                .root_directory
                .open_relative_dir(parent, false)
                .map_err(windows_path_error)?
                .0;
            if opened_parent.identity() != entry.parent_identity {
                return Err(Error::InvalidFiles);
            }
            opened_parent
                .rename_open_file_here(&entry.file, new_name, false)
                .map_err(windows_path_error)?;
        }
        #[cfg(not(any(unix, windows)))]
        crate::rename_path_no_overwrite(old_path, new_path, false)?;
        // A successful filesystem rename keeps the already-open handle bound
        // to the same file. Reopening here would introduce a fallible window
        // after the path has moved but before the caller can commit its rename
        // journal.
        self.entries[file_index].path = new_path.to_path_buf();
        Ok(())
    }

    pub fn validate_file_rename(
        &self,
        file_index: usize,
        old_path: &Path,
        new_path: &Path,
    ) -> Result<(), Error> {
        if file_index >= self.entries.len() {
            return Err(Error::OutOfBounds);
        }
        if old_path != self.entries[file_index].path {
            return Err(Error::InvalidPathSegment);
        }
        validate_path_beneath(&self.root, old_path)?;
        validate_path_beneath(&self.root, new_path)?;
        let new_name = new_path.file_name().ok_or(Error::InvalidPathSegment)?;
        validate_os_file_name(new_name)?;
        if new_path.parent() == Some(self.root.as_path()) && is_reserved_app_name(new_name) {
            return Err(Error::InvalidPathSegment);
        }
        if old_path
            .symlink_metadata()
            .map(|metadata| metadata.is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::SymlinkNotAllowed);
        }
        match new_path.symlink_metadata() {
            Ok(_) => return Err(Error::InvalidFiles),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(Error::Io(err)),
        }
        if let Some(parent) = new_path.parent() {
            if parent != old_path.parent().unwrap_or_else(|| Path::new("")) {
                return Err(Error::InvalidPathSegment);
            }
        }
        Ok(())
    }
}

/// Every payload file stays open for the lifetime of `Storage` (pinned
/// identity and exclusive lock), so a multi-file torrent needs one
/// descriptor per file. Default soft limits (256 on macOS, often 1024 on
/// Linux) fail larger torrents with EMFILE, so raise the soft limit once
/// toward the hard limit.
#[cfg(unix)]
fn raise_open_file_limit() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // macOS rejects soft limits above OPEN_MAX (10240).
        let cap: libc::rlim_t = if cfg!(target_os = "macos") {
            10_240
        } else {
            65_536
        };
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit/setrlimit only read or write the given struct.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                let target = limit.rlim_max.min(cap);
                if limit.rlim_cur < target {
                    limit.rlim_cur = target;
                    libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
                }
            }
        }
    });
}

fn is_disk_full(err: &std::io::Error) -> bool {
    // ENOSPC on Unix; ERROR_HANDLE_DISK_FULL / ERROR_DISK_FULL on Windows.
    #[cfg(windows)]
    let full = matches!(err.raw_os_error(), Some(39 | 112));
    #[cfg(not(windows))]
    let full = err.raw_os_error() == Some(28);
    full
}

fn apply_saved_file_renames(
    layouts: &mut [FileLayout],
    file_renames: &[(usize, String)],
) -> Result<(), Error> {
    let mut seen = HashSet::with_capacity(file_renames.len());
    for (index, name) in file_renames {
        if !seen.insert(*index) {
            return Err(Error::InvalidFiles);
        }
        let layout = layouts.get_mut(*index).ok_or(Error::OutOfBounds)?;
        let name = OsStr::new(name);
        // Persisted rename data is untrusted state. Reserved application names
        // are never valid payload rename targets, regardless of platform path
        // normalization or the file's current nesting depth.
        if is_reserved_app_name(name) {
            return Err(Error::InvalidName);
        }
        validate_os_file_name(name)?;
        layout.path.set_file_name(name);
    }
    validate_layout_paths(layouts)
}

#[cfg(unix)]
fn validate_distinct_files(entries: &[FileEntry]) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;

    let mut identities = HashSet::with_capacity(entries.len());
    for entry in entries {
        let metadata = entry.file.metadata()?;
        if !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(Error::InvalidFiles);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_distinct_files(entries: &[FileEntry]) -> Result<(), Error> {
    let mut identities = HashSet::with_capacity(entries.len());
    for entry in entries {
        let info = crate::windows_fs::file_info(&entry.file).map_err(windows_path_error)?;
        if !identities.insert(info.identity) {
            return Err(Error::InvalidFiles);
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_distinct_files(_entries: &[FileEntry]) -> Result<(), Error> {
    Ok(())
}

impl Drop for Storage {
    fn drop(&mut self) {
        // Drop cannot return an error. Normal shutdown paths should call
        // `flush`; this still prevents a below-limit cache from being silently
        // discarded on routine scope exit.
        let _ = self.flush();
    }
}

#[cfg(unix)]
fn component_name(name: &OsStr) -> Result<CString, Error> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(Error::InvalidPathSegment);
    }
    CString::new(bytes).map_err(|_| Error::InvalidPathSegment)
}

#[cfg(unix)]
fn component_open_error(error: std::io::Error) -> Error {
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        Error::SymlinkNotAllowed
    } else {
        Error::Io(error)
    }
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let directory = options.open(path).map_err(component_open_error)?;
    let opened = directory.metadata()?;
    if !opened.is_dir() {
        return Err(Error::InvalidFiles);
    }
    let canonical = fs::canonicalize(path)?;
    let resolved = fs::metadata(canonical)?;
    use std::os::unix::fs::MetadataExt;
    if !resolved.is_dir() || opened.dev() != resolved.dev() || opened.ino() != resolved.ino() {
        return Err(Error::SymlinkNotAllowed);
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_child_directory(parent: &File, name: &OsStr, create: bool) -> Result<File, Error> {
    let name = component_name(name)?;
    let open = || {
        // SAFETY: `parent` is a live directory descriptor and `name` is a
        // validated, NUL-terminated single path component.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // SAFETY: openat returned a new owned descriptor.
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    };
    match open() {
        Ok(directory) => Ok(directory),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            // SAFETY: the parent descriptor and component remain live for the
            // call. EEXIST is expected if another creator wins the race.
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
            if created != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(component_open_error(error));
                }
            }
            open().map_err(component_open_error)
        }
        Err(error) => Err(component_open_error(error)),
    }
}

#[cfg(unix)]
fn open_payload_file_unix(
    root_directory: &File,
    root: &Path,
    path: &Path,
    create: bool,
) -> Result<OpenedPayload, Error> {
    open_payload_file_unix_with_hook(root_directory, root, path, create, || Ok(()))
}

#[cfg(unix)]
fn open_payload_file_unix_with_hook<F>(
    root_directory: &File,
    root: &Path,
    path: &Path,
    create: bool,
    before_final_open: F,
) -> Result<OpenedPayload, Error>
where
    F: FnOnce() -> Result<(), Error>,
{
    let (parent, file_name) = open_payload_parent_unix(root_directory, root, path, create)?;

    before_final_open()?;
    let file_name_c = component_name(&file_name)?;
    let mut flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    if create {
        flags |= libc::O_CREAT;
    }
    // SAFETY: the pinned parent descriptor is live and the final component is
    // validated and NUL terminated. O_NOFOLLOW rejects a final symlink.
    let descriptor =
        unsafe { libc::openat(parent.as_raw_fd(), file_name_c.as_ptr(), flags, 0o644) };
    if descriptor < 0 {
        return Err(component_open_error(std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::InvalidFiles);
    }
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() > 1 {
        return Err(Error::InvalidFiles);
    }
    Ok(OpenedPayload { file })
}

#[cfg(unix)]
fn open_payload_parent_unix(
    root_directory: &File,
    root: &Path,
    path: &Path,
    create: bool,
) -> Result<(File, OsString), Error> {
    use std::path::Component;

    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::InvalidPathSegment)?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(Error::InvalidPathSegment),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (file_name, parents) = components.split_last().ok_or(Error::InvalidPathSegment)?;
    let mut parent = root_directory.try_clone()?;
    for component in parents {
        parent = open_child_directory(&parent, component, create)?;
    }
    Ok((parent, file_name.clone()))
}

#[cfg(unix)]
fn rename_at_no_overwrite(parent: &File, old_name: &OsStr, new_name: &OsStr) -> Result<(), Error> {
    let old_name = component_name(old_name)?;
    let new_name = component_name(new_name)?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let result = {
        // SAFETY: both names are live, validated C strings and the same pinned
        // directory descriptor is used for source and destination.
        unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                old_name.as_ptr(),
                parent.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        }
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = {
        // SAFETY: renameat2 receives live descriptors and validated C strings.
        unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                old_name.as_ptr(),
                parent.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            ) as libc::c_int
        }
    };
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )))]
    let result = {
        // Use a no-overwrite link/unlink fallback on less common Unix targets.
        // If unlink fails, remove the new link again before surfacing failure.
        let linked = unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                old_name.as_ptr(),
                parent.as_raw_fd(),
                new_name.as_ptr(),
                0,
            )
        };
        if linked != 0 {
            linked
        } else {
            let removed = unsafe { libc::unlinkat(parent.as_raw_fd(), old_name.as_ptr(), 0) };
            if removed != 0 {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), new_name.as_ptr(), 0);
                }
            }
            removed
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::last_os_error()))
    }
}

#[cfg(unix)]
fn verify_open_file_entry(parent: &File, name: &OsStr, opened: &File) -> Result<(), Error> {
    use std::mem::MaybeUninit;
    use std::os::unix::fs::MetadataExt;

    let name = component_name(name)?;
    let mut linked = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: the parent descriptor and component are live and `linked`
    // points to writable stat storage.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            linked.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(component_open_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstatat initialized the structure on success.
    let linked = unsafe { linked.assume_init() };
    let metadata = opened.metadata()?;
    // `libc::dev_t` is already `u64` on Linux but is narrower on some of the
    // other Unix targets supported here. Keep the common comparison type
    // explicit without making the Linux-only Clippy result dictate the cast.
    #[allow(clippy::unnecessary_cast)]
    let linked_device = linked.st_dev as u64;
    if linked.st_mode & libc::S_IFMT != libc::S_IFREG
        || linked.st_nlink != 1
        || linked_device != metadata.dev()
        || linked.st_ino != metadata.ino()
    {
        return Err(Error::InvalidFiles);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn open_payload_file(path: &Path, create: bool) -> Result<OpenedPayload, Error> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_symlink() => return Err(Error::SymlinkNotAllowed),
        Ok(metadata) if !metadata.is_file() => return Err(Error::InvalidFiles),
        Ok(_) => {}
        Err(err) if create && err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Error::Io(err)),
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).truncate(false);
    if create {
        opts.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        opts.mode(0o644);
    }
    let file = opts.open(path).map_err(Error::Io)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::InvalidFiles);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(Error::InvalidFiles);
        }
    }
    Ok(OpenedPayload { file })
}

#[cfg(windows)]
fn windows_path_error(error: std::io::Error) -> Error {
    // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION mean another payload
    // owner already holds the deliberately exclusive Windows file handle.
    if matches!(error.raw_os_error(), Some(32 | 33)) {
        return Error::PayloadInUse;
    }
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Error::SymlinkNotAllowed,
        std::io::ErrorKind::InvalidData => Error::InvalidFiles,
        _ => Error::Io(error),
    }
}

#[cfg(windows)]
fn open_payload_file_windows(
    root_directory: &crate::windows_fs::PinnedDir,
    root: &Path,
    path: &Path,
    create: bool,
) -> Result<OpenedPayload, Error> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::InvalidPathSegment)?;
    let disposition = if create {
        crate::windows_fs::CreateDisposition::OpenOrCreate
    } else {
        crate::windows_fs::CreateDisposition::OpenExisting
    };
    let opened = root_directory
        .open_regular(relative, disposition, create)
        .map_err(windows_path_error)?;
    Ok(OpenedPayload {
        file: opened.file,
        parent_identity: opened.parent_identity,
    })
}

#[cfg(not(any(unix, windows)))]
fn create_dir_secure(root: &Path, path: &Path) -> Result<(), Error> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::InvalidPathSegment)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        use std::path::Component;
        let Component::Normal(segment) = component else {
            return Err(Error::InvalidPathSegment);
        };
        current.push(segment);
        match current.symlink_metadata() {
            Ok(metadata) if metadata.is_symlink() => return Err(Error::SymlinkNotAllowed),
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "torrent path component is not a directory",
                )))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    DirBuilder::new().mode(0o755).create(&current)?;
                }
                #[cfg(not(unix))]
                {
                    fs::create_dir(&current)?;
                }
            }
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Ok(())
}

fn validate_path_beneath(root: &Path, path: &Path) -> Result<(), Error> {
    use std::path::Component;

    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::InvalidPathSegment)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::InvalidPathSegment);
    }
    Ok(())
}

/// Return the exact filesystem root used for this torrent. On Unix this
/// preserves non-UTF-8 metainfo names and must be preferred over lossy string
/// reconstruction in move/cleanup code.
pub fn root_path(meta: &TorrentMeta, download_dir: &Path) -> Result<PathBuf, Error> {
    Ok(download_dir.join(clean_name(&meta.info.name)?))
}

/// Return the exact filesystem paths for torrent data without opening or
/// creating them. Cleanup code must use these raw-safe paths instead of lossy
/// UI display strings.
pub fn data_paths(meta: &TorrentMeta, download_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    data_paths_with_file_renames(meta, download_dir, &[])
}

/// Return the exact filesystem paths for torrent data after applying saved
/// per-file renames, without opening or creating any files.
pub fn data_paths_with_file_renames(
    meta: &TorrentMeta,
    download_dir: &Path,
    file_renames: &[(usize, String)],
) -> Result<Vec<PathBuf>, Error> {
    let mut layouts = build_layout(meta, download_dir)?;
    apply_saved_file_renames(&mut layouts, file_renames)?;
    validate_no_reserved_state_paths(download_dir, &layouts)?;
    Ok(layouts.into_iter().map(|layout| layout.path).collect())
}

fn validate_no_reserved_state_paths(
    download_dir: &Path,
    layouts: &[FileLayout],
) -> Result<(), Error> {
    if layouts.iter().any(|layout| {
        layout
            .path
            .strip_prefix(download_dir)
            .is_ok_and(|relative| relative.components().count() == 1)
            && layout.path.file_name().is_some_and(is_reserved_app_name)
    }) {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn build_layout(meta: &TorrentMeta, download_dir: &Path) -> Result<Vec<FileLayout>, Error> {
    let root = root_path(meta, download_dir)?;
    let total_length = meta
        .info
        .checked_total_length()
        .ok_or(Error::InvalidLength)?;
    if total_length == 0 {
        return Err(Error::InvalidLength);
    }

    if let Some(length) = meta.info.length {
        return Ok(vec![FileLayout {
            path: root,
            offset: 0,
            length,
        }]);
    }

    // v1/hybrid metadata lists `files`; v2-only metadata has a file tree.
    let files: Vec<(&[Vec<u8>], u64)> = if meta.info.files.is_empty() {
        let tree = meta.info.file_tree.iter();
        tree.map(|file| (file.path.as_slice(), file.length))
            .collect()
    } else {
        let list = meta.info.files.iter();
        list.map(|file| (file.path.as_slice(), file.length))
            .collect()
    };
    if files.is_empty() {
        return Err(Error::InvalidFiles);
    }
    let file_offsets = meta.file_offsets().ok_or(Error::InvalidLength)?;
    let mut layouts = Vec::with_capacity(files.len());
    for ((segments, length), offset) in files.into_iter().zip(file_offsets) {
        if segments.is_empty() {
            return Err(Error::InvalidPathSegment);
        }
        let mut path = root.clone();
        for segment in segments {
            path.push(clean_segment(segment)?);
        }
        layouts.push(FileLayout {
            path,
            offset,
            length,
        });
    }

    let laid_out_content = layouts
        .iter()
        .try_fold(0u64, |total, layout| total.checked_add(layout.length))
        .ok_or(Error::InvalidLength)?;
    if laid_out_content != total_length {
        return Err(Error::InvalidLength);
    }
    validate_layout_paths(&layouts)?;
    Ok(layouts)
}

fn validate_layout_paths(layouts: &[FileLayout]) -> Result<(), Error> {
    let mut paths: Vec<&Path> = layouts.iter().map(|layout| layout.path.as_path()).collect();
    crate::util::sort(&mut paths);
    for pair in paths.windows(2) {
        if pair[0] == pair[1] || pair[1].starts_with(pair[0]) {
            return Err(Error::InvalidFiles);
        }
    }
    Ok(())
}

fn clean_name(bytes: &[u8]) -> Result<OsString, Error> {
    if is_reserved_app_name_bytes(bytes) {
        return Err(Error::InvalidName);
    }
    clean_segment(bytes).map_err(|_| Error::InvalidName)
}

fn is_reserved_app_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| is_reserved_app_name_bytes(name.as_bytes()))
}

fn is_reserved_app_name_bytes(bytes: &[u8]) -> bool {
    bytes.eq_ignore_ascii_case(b".rustorrent") || bytes.eq_ignore_ascii_case(b".rustorrent.lock")
}

#[cfg(unix)]
fn validate_os_file_name(name: &std::ffi::OsStr) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    clean_segment(name.as_bytes()).map(|_| ())
}

#[cfg(not(unix))]
fn validate_os_file_name(name: &std::ffi::OsStr) -> Result<(), Error> {
    let name = name.to_str().ok_or(Error::InvalidPathSegment)?;
    clean_segment(name.as_bytes()).map(|_| ())
}

fn clean_segment(bytes: &[u8]) -> Result<OsString, Error> {
    if bytes.is_empty() {
        return Err(Error::InvalidPathSegment);
    }
    if bytes == b"." || bytes == b".." {
        return Err(Error::InvalidPathSegment);
    }
    if bytes.iter().any(|b| *b == 0 || *b == b'/' || *b == b'\\') {
        return Err(Error::InvalidPathSegment);
    }
    if bytes.iter().any(|b| *b < 0x20) {
        return Err(Error::InvalidPathSegment);
    }
    #[cfg(not(unix))]
    {
        let invalid = *b":*?\"<>|";
        if bytes.iter().any(|b| invalid.contains(b)) {
            return Err(Error::InvalidPathSegment);
        }
        if matches!(bytes.last(), Some(b'.' | b' ')) {
            return Err(Error::InvalidPathSegment);
        }
        let name = std::str::from_utf8(bytes).map_err(|_| Error::InvalidPathSegment)?;
        let trimmed = name.trim_end_matches([' ', '.']);
        let upper = trimmed.to_ascii_uppercase();
        if is_windows_reserved(&upper) {
            return Err(Error::InvalidPathSegment);
        }
    }
    bytes_to_os_string(bytes)
}

#[cfg(not(unix))]
fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    if stem.is_empty() {
        return true;
    }
    matches!(
        stem,
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(unix)]
fn bytes_to_os_string(bytes: &[u8]) -> Result<OsString, Error> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsStringExt::from_vec(bytes.to_vec()))
}

#[cfg(not(unix))]
fn bytes_to_os_string(bytes: &[u8]) -> Result<OsString, Error> {
    String::from_utf8(bytes.to_vec())
        .map(OsString::from)
        .map_err(|_| Error::InvalidPathSegment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::{FileInfo, FileTreeEntry, InfoDict};
    #[cfg(unix)]
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dummy_meta() -> TorrentMeta {
        TorrentMeta {
            announce: None,
            announce_list: Vec::new(),
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [0u8; 20],
            info_hash_v2: None,
            piece_layers: Vec::new(),
            meta_version: 1,
            info: InfoDict {
                name: b"root".to_vec(),
                piece_length: 16384,
                pieces: vec![[0u8; 20]; 2],
                length: None,
                files: vec![
                    FileInfo {
                        length: 3,
                        path: vec![b"a.txt".to_vec()],
                        attr: Vec::new(),
                    },
                    FileInfo {
                        length: 5,
                        path: vec![b"dir".to_vec(), b"b.bin".to_vec()],
                        attr: Vec::new(),
                    },
                ],
                private: false,
                file_tree: Vec::new(),
            },
        }
    }

    fn dummy_meta_v2_tree() -> TorrentMeta {
        let mut meta = dummy_meta();
        meta.meta_version = 2;
        meta.info.files.clear();
        meta.info.file_tree = vec![
            FileTreeEntry {
                path: vec![b"a.txt".to_vec()],
                length: 3,
                pieces_root: None,
            },
            FileTreeEntry {
                path: vec![b"dir".to_vec(), b"b.bin".to_vec()],
                length: 5,
                pieces_root: None,
            },
        ];
        meta
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustorrent-storage-{label}-{nanos}"))
    }

    #[test]
    fn builds_multi_file_layout() {
        let meta = dummy_meta();
        let base = Path::new("/tmp");
        let layout = build_layout(&meta, base).unwrap();
        assert_eq!(layout.len(), 2);
        assert_eq!(layout[0].offset, 0);
        assert_eq!(layout[0].length, 3);
        assert_eq!(layout[1].offset, 3);
        assert_eq!(layout[1].length, 5);
    }

    #[test]
    fn builds_v2_file_tree_layout() {
        let meta = dummy_meta_v2_tree();
        let base = Path::new("/tmp");
        let layout = build_layout(&meta, base).unwrap();
        assert_eq!(layout.len(), 2);
        assert_eq!(layout[0].offset, 0);
        assert_eq!(layout[0].length, 3);
        assert_eq!(layout[1].offset, 16_384);
        assert_eq!(layout[1].length, 5);
    }

    #[test]
    fn rejects_invalid_path_segments() {
        let mut meta = dummy_meta();
        meta.info.files[0].path = vec![b"..".to_vec()];
        let err = build_layout(&meta, Path::new("/tmp")).unwrap_err();
        assert!(matches!(err, Error::InvalidPathSegment));
    }

    #[test]
    fn rejects_roots_reserved_for_application_state() {
        for name in [b".rustorrent".as_slice(), b".RUSTORRENT.LOCK".as_slice()] {
            let mut meta = dummy_meta();
            meta.info.name = name.to_vec();
            assert!(matches!(
                build_layout(&meta, Path::new("/tmp")),
                Err(Error::InvalidName)
            ));
        }
    }

    #[test]
    fn malicious_search_plugin_layout_is_rejected_before_creation() {
        let dir = temp_dir("reserved-search-plugin");
        let mut meta = dummy_meta();
        meta.info.name = b".rustorrent".to_vec();
        meta.info.files = vec![FileInfo {
            length: 3,
            path: vec![
                b"search".to_vec(),
                b"nova3".to_vec(),
                b"engines".to_vec(),
                b"evil.py".to_vec(),
            ],
            attr: Vec::new(),
        }];

        let result = Storage::new(
            &meta,
            &dir,
            StorageOptions {
                preallocate: false,
                write_cache_bytes: 0,
            },
        );
        assert!(matches!(result, Err(Error::InvalidName)));
        assert!(!dir.exists());
    }

    #[test]
    fn single_file_rename_cannot_enter_reserved_state_namespace() {
        let dir = temp_dir("reserved-live-rename");
        fs::create_dir_all(&dir).unwrap();
        let mut meta = dummy_meta();
        meta.info.length = Some(3);
        meta.info.files.clear();
        let mut storage = Storage::new(
            &meta,
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();
        let old_path = storage.file_path(0).unwrap().to_path_buf();

        assert!(matches!(
            storage.rename_file(0, &old_path, &dir.join(".RUSTORRENT")),
            Err(Error::InvalidPathSegment)
        ));
        assert!(old_path.exists());
        assert!(matches!(
            data_paths_with_file_renames(&meta, &dir, &[(0, ".rustorrent.lock".to_string())]),
            Err(Error::InvalidName)
        ));

        drop(storage);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_zero_total_length() {
        let mut meta = dummy_meta();
        meta.info.files[0].length = 0;
        meta.info.files[1].length = 0;
        let err = build_layout(&meta, Path::new("/tmp")).unwrap_err();
        assert!(matches!(err, Error::InvalidLength));
    }

    #[test]
    fn storage_reads_and_writes_across_file_boundaries() {
        let dir = temp_dir("cross-file");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();

        storage.write_at(2, &[9, 8, 7, 6]).unwrap();
        let mut out = vec![0u8; 8];
        storage.read_at(0, &mut out).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(out, vec![0, 0, 9, 8, 7, 6, 0, 0]);
    }

    #[test]
    fn storage_rejects_out_of_bounds_io() {
        let dir = temp_dir("bounds");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();

        assert!(matches!(storage.write_at(8, &[1]), Err(Error::OutOfBounds)));
        let mut out = [0u8; 1];
        assert!(matches!(
            storage.read_at(8, &mut out),
            Err(Error::OutOfBounds)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_flushes_overlapping_write_cache() {
        let dir = temp_dir("cache-flush");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 1024,
            },
        )
        .unwrap();

        storage.write_at(1, &[7, 8, 9]).unwrap();
        let mut out = [0u8; 3];
        storage.read_at(1, &mut out).unwrap();
        assert_eq!(out, [7, 8, 9]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_storage_flushes_below_limit_cached_writes() {
        let dir = temp_dir("cache-drop");
        fs::create_dir_all(&dir).unwrap();
        {
            let mut storage = Storage::new(
                &dummy_meta(),
                &dir,
                StorageOptions {
                    preallocate: true,
                    write_cache_bytes: 1024,
                },
            )
            .unwrap();
            storage.write_at(0, &[1, 2, 3]).unwrap();
        }

        assert_eq!(fs::read(dir.join("root/a.txt")).unwrap(), [1, 2, 3]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_storage_uses_piece_aligned_file_offsets() {
        let dir = temp_dir("v2-alignment");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta_v2_tree(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();

        storage.write_at(0, &[1, 2, 3]).unwrap();
        storage.write_at(16_384, &[4, 5, 6, 7, 8]).unwrap();
        let mut second = [0u8; 5];
        storage.read_at(16_384, &mut second).unwrap();
        assert_eq!(second, [4, 5, 6, 7, 8]);
        let mut gap = [0u8; 1];
        assert!(matches!(
            storage.read_at(3, &mut gap),
            Err(Error::OutOfBounds)
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn layout_rejects_duplicate_and_prefix_colliding_paths() {
        let mut duplicate = dummy_meta();
        duplicate.info.files[1].path = vec![b"a.txt".to_vec()];
        assert!(matches!(
            build_layout(&duplicate, Path::new("/tmp")),
            Err(Error::InvalidFiles)
        ));

        let mut prefix = dummy_meta();
        prefix.info.files[0].path = vec![b"node".to_vec()];
        prefix.info.files[1].path = vec![b"node".to_vec(), b"child".to_vec()];
        assert!(matches!(
            build_layout(&prefix, Path::new("/tmp")),
            Err(Error::InvalidFiles)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn storage_rejects_symlinked_parent_components() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("parent-symlink");
        let outside = temp_dir("parent-symlink-outside");
        fs::create_dir_all(dir.join("root")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dir.join("root/dir")).unwrap();

        let err = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::SymlinkNotAllowed));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn pinned_parent_open_cannot_be_redirected_by_a_symlink_swap() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("pinned-parent-swap");
        let outside = temp_dir("pinned-parent-swap-outside");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let path = dir.join("root/dir/payload.bin");
        let original_parent = dir.join("root/dir");
        let moved_parent = dir.join("root/pinned-dir");
        let root = open_directory_no_follow(&dir).unwrap();

        let mut opened = open_payload_file_unix_with_hook(&root, &dir, &path, true, || {
            fs::rename(&original_parent, &moved_parent)?;
            symlink(&outside, &original_parent)?;
            Ok(())
        })
        .unwrap();
        opened.file.write_all(b"safe").unwrap();
        opened.file.sync_all().unwrap();

        assert_eq!(fs::read(moved_parent.join("payload.bin")).unwrap(), b"safe");
        assert!(!outside.join("payload.bin").exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn storage_rejects_two_paths_to_the_same_file() {
        let dir = temp_dir("hardlink-alias");
        fs::create_dir_all(dir.join("root/dir")).unwrap();
        fs::write(dir.join("root/a.txt"), []).unwrap();
        fs::hard_link(dir.join("root/a.txt"), dir.join("root/dir/b.bin")).unwrap();

        let err = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: false,
                write_cache_bytes: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidFiles));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_renames_are_applied_before_files_are_opened() {
        let dir = temp_dir("saved-rename");
        fs::create_dir_all(&dir).unwrap();
        let options = StorageOptions {
            preallocate: true,
            write_cache_bytes: 0,
        };
        {
            let mut storage = Storage::new(&dummy_meta(), &dir, options).unwrap();
            storage.write_at(0, &[1, 2, 3]).unwrap();
            let old_path = storage.file_path(0).unwrap().to_path_buf();
            let new_path = old_path.with_file_name("renamed.txt");
            storage.rename_file(0, &old_path, &new_path).unwrap();
        }

        let mut reopened = Storage::new_with_file_renames(
            &dummy_meta(),
            &dir,
            options,
            &[(0, "renamed.txt".to_string())],
        )
        .unwrap();
        let mut data = [0u8; 3];
        reopened.read_at(0, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3]);
        assert!(!dir.join("root/a.txt").exists());

        drop(reopened);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn payload_files_are_exclusively_locked_while_storage_is_open() {
        let dir = temp_dir("exclusive-lock");
        fs::create_dir_all(&dir).unwrap();
        let options = StorageOptions {
            preallocate: true,
            write_cache_bytes: 0,
        };
        let storage = Storage::new(&dummy_meta(), &dir, options).unwrap();

        assert!(matches!(
            Storage::new(&dummy_meta(), &dir, options),
            Err(Error::PayloadInUse)
        ));

        drop(storage);
        Storage::new(&dummy_meta(), &dir, options).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_paths_include_saved_file_renames_without_creating_files() {
        let dir = temp_dir("renamed-data-paths");
        let paths =
            data_paths_with_file_renames(&dummy_meta(), &dir, &[(0, "renamed.txt".to_string())])
                .unwrap();

        assert_eq!(paths[0], dir.join("root/renamed.txt"));
        assert_eq!(paths[1], dir.join("root/dir/b.bin"));
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rename_rejects_a_replaced_source_directory_entry() {
        let dir = temp_dir("rename-replaced-entry");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();
        let old_path = storage.file_path(0).unwrap().to_path_buf();
        let displaced = old_path.with_file_name("displaced.bin");
        let requested = old_path.with_file_name("requested.bin");
        fs::rename(&old_path, &displaced).unwrap();
        fs::write(&old_path, b"replacement").unwrap();

        assert!(matches!(
            storage.rename_file(0, &old_path, &requested),
            Err(Error::InvalidFiles)
        ));
        assert_eq!(storage.file_path(0), Some(old_path.as_path()));
        assert!(old_path.exists());
        assert!(displaced.exists());
        assert!(!requested.exists());

        drop(storage);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rename_uses_the_exact_non_utf8_stored_path() {
        let dir = temp_dir("rename-non-utf8");
        fs::create_dir_all(&dir).unwrap();
        let mut meta = dummy_meta();
        meta.info.files[0].path = vec![vec![0xff, b'a']];
        let mut storage = Storage::new(
            &meta,
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();
        let old_path = storage.file_path(0).unwrap().to_path_buf();
        let new_path = old_path.with_file_name("renamed.bin");
        storage.rename_file(0, &old_path, &new_path).unwrap();
        assert_eq!(storage.file_path(0), Some(new_path.as_path()));
        assert!(new_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    fn many_file_meta(files: usize, file_len: u64, zero_every: usize) -> TorrentMeta {
        let mut meta = dummy_meta();
        meta.info.files = (0..files)
            .map(|index| FileInfo {
                length: if zero_every > 0 && index % zero_every == 0 {
                    0
                } else {
                    file_len
                },
                path: vec![format!("f{index:05}").into_bytes()],
                attr: Vec::new(),
            })
            .collect();
        let total: u64 = meta.info.files.iter().map(|file| file.length).sum();
        meta.info.piece_length = 16_384;
        meta.info.pieces = vec![[0u8; 20]; total.div_ceil(16_384) as usize];
        meta
    }

    #[test]
    fn positioned_io_spans_many_files_including_empty_ones() {
        let dir = temp_dir("many-files");
        fs::create_dir_all(&dir).unwrap();
        // Every third file is empty; blocks straddle several file boundaries.
        let meta = many_file_meta(60, 7, 3);
        let total: u64 = meta.info.files.iter().map(|file| file.length).sum();
        let payload = (0..total).map(|i| (i * 31 % 251) as u8).collect::<Vec<_>>();
        let mut storage = Storage::new(
            &meta,
            &dir,
            StorageOptions {
                preallocate: false,
                write_cache_bytes: 0,
            },
        )
        .unwrap();
        for chunk_start in (0..payload.len()).step_by(11) {
            let end = (chunk_start + 11).min(payload.len());
            storage
                .write_at(chunk_start as u64, &payload[chunk_start..end])
                .unwrap();
        }
        let mut out = vec![0u8; payload.len()];
        storage.read_at(0, &mut out).unwrap();
        assert_eq!(out, payload);
        let mut middle = [0u8; 20];
        storage.read_at(100, &mut middle).unwrap();
        assert_eq!(&middle[..], &payload[100..120]);
        storage.flush().unwrap();
        assert!(storage.entries.iter().all(|entry| !entry.dirty));
        // Windows payload handles deny other readers, so close them first.
        drop(storage);
        assert_eq!(fs::read(dir.join("root/f00001")).unwrap(), &payload[..7]);
        assert_eq!(fs::read(dir.join("root/f00000")).unwrap(), b"");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_marks_only_written_files_dirty() {
        let dir = temp_dir("dirty-files");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 0,
            },
        )
        .unwrap();
        storage.write_at(4, &[1]).unwrap();
        assert!(!storage.entries[0].dirty);
        assert!(storage.entries[1].dirty);
        storage.flush().unwrap();
        assert!(!storage.entries[1].dirty);
        drop(storage);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cached_overlapping_writes_keep_their_order() {
        let dir = temp_dir("cache-order");
        fs::create_dir_all(&dir).unwrap();
        let mut storage = Storage::new(
            &dummy_meta(),
            &dir,
            StorageOptions {
                preallocate: true,
                write_cache_bytes: 1024,
            },
        )
        .unwrap();
        storage.write_at(2, &[1, 1, 1, 1]).unwrap();
        storage.write_at(0, &[2, 2, 2]).unwrap();
        // A write at least as large as the cache bypasses it only after the
        // queued writes are applied.
        storage.flush().unwrap();
        let mut out = [0u8; 8];
        storage.read_at(0, &mut out).unwrap();
        assert_eq!(out, [2, 2, 2, 1, 1, 1, 0, 0]);
        drop(storage);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn open_file_limit_is_raised_toward_the_hard_limit() {
        raise_open_file_limit();
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit only writes the given struct.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert!(limit.rlim_cur >= limit.rlim_max.min(10_240));
    }

    #[test]
    fn disk_full_errors_are_recognized() {
        #[cfg(not(windows))]
        assert!(is_disk_full(&std::io::Error::from_raw_os_error(28)));
        #[cfg(windows)]
        assert!(is_disk_full(&std::io::Error::from_raw_os_error(112)));
        assert!(!is_disk_full(&std::io::Error::other("x")));
    }

    /// `cargo test --release storage_io_benchmark -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn storage_io_benchmark() {
        let dir = temp_dir("bench");
        fs::create_dir_all(&dir).unwrap();
        let files = 4_000;
        let meta = many_file_meta(files, 16_384, 0);
        let block = vec![7u8; 16_384];
        let total = files as u64 * 16_384;
        for cache in [0usize, 1 << 20] {
            let mut storage = Storage::new(
                &meta,
                &dir,
                StorageOptions {
                    preallocate: false,
                    write_cache_bytes: cache,
                },
            )
            .unwrap();
            let started = Instant::now();
            for round in 0..2u64 {
                let mut offset = round * 8_192;
                while offset + 16_384 <= total {
                    storage.write_at(offset, &block).unwrap();
                    offset += 16_384;
                }
            }
            storage.flush().unwrap();
            let write_elapsed = started.elapsed();
            let started = Instant::now();
            let mut out = vec![0u8; 16_384];
            for _ in 0..4 {
                let mut offset = 0;
                while offset + 16_384 <= total {
                    storage.read_at(offset, &mut out).unwrap();
                    offset += 16_384;
                }
            }
            println!(
                "cache={cache}: write+flush {:?}, read {:?}",
                write_elapsed,
                started.elapsed()
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
