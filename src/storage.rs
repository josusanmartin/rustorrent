use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::torrent::TorrentMeta;

#[derive(Debug)]
pub struct Storage {
    entries: Vec<FileEntry>,
    total_length: u64,
    write_cache: Vec<WriteEntry>,
    write_cache_bytes: usize,
    write_cache_limit: usize,
}

#[derive(Debug, Clone, Copy)]
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

pub fn metrics_snapshot() -> StorageMetrics {
    StorageMetrics {
        read_ops: READ_OPS.load(Ordering::Relaxed),
        read_ns: READ_NS.load(Ordering::Relaxed),
        write_ops: WRITE_OPS.load(Ordering::Relaxed),
        write_ns: WRITE_NS.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StorageOptions {
    pub preallocate: bool,
    pub write_cache_bytes: usize,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            preallocate: false,
            write_cache_bytes: 0,
        }
    }
}

#[derive(Debug)]
struct FileEntry {
    offset: u64,
    length: u64,
    file: File,
}

#[derive(Debug)]
struct WriteEntry {
    offset: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "io error: {err}"),
            Error::InvalidName => write!(f, "invalid torrent name"),
            Error::InvalidPathSegment => write!(f, "invalid path segment"),
            Error::InvalidFiles => write!(f, "invalid file list"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::OutOfBounds => write!(f, "read/write out of bounds"),
        }
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
        let layouts = build_layout(meta, download_dir)?;
        let mut entries = Vec::with_capacity(layouts.len());
        for layout in layouts {
            if let Some(parent) = layout.path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&layout.path)?;
            if options.preallocate {
                file.set_len(layout.length)?;
            }
            entries.push(FileEntry {
                offset: layout.offset,
                length: layout.length,
                file,
            });
        }

        let total_length = meta.info.total_length();
        Ok(Self {
            entries,
            total_length,
            write_cache: Vec::new(),
            write_cache_bytes: 0,
            write_cache_limit: options.write_cache_bytes,
        })
    }

    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        let start = Instant::now();
        let result = (|| {
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or(Error::OutOfBounds)?;
            if end > self.total_length {
                return Err(Error::OutOfBounds);
            }
            if self.write_cache_limit == 0 {
                return self.write_direct(offset, data);
            }
            if data.len() >= self.write_cache_limit {
                self.flush_cache()?;
                return self.write_direct(offset, data);
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
        })();
        let elapsed = start.elapsed().as_nanos() as u64;
        WRITE_OPS.fetch_add(1, Ordering::Relaxed);
        WRITE_NS.fetch_add(elapsed, Ordering::Relaxed);
        result
    }

    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        let start = Instant::now();
        if self.write_cache_limit > 0 {
            let read_end = offset.saturating_add(out.len() as u64);
            let overlaps = self.write_cache.iter().any(|entry| {
                let entry_end = entry.offset.saturating_add(entry.data.len() as u64);
                entry.offset < read_end && entry_end > offset
            });
            if overlaps {
                self.flush_cache()?;
            }
        }
        let result = self.read_direct(offset, out);
        let elapsed = start.elapsed().as_nanos() as u64;
        READ_OPS.fetch_add(1, Ordering::Relaxed);
        READ_NS.fetch_add(elapsed, Ordering::Relaxed);
        result
    }

    fn write_direct(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::OutOfBounds)?;
        if end > self.total_length {
            return Err(Error::OutOfBounds);
        }

        let mut cursor = offset;
        let mut remaining = data;

        for entry in &mut self.entries {
            if remaining.is_empty() {
                break;
            }
            let entry_end = entry.offset + entry.length;
            if cursor < entry.offset {
                return Err(Error::OutOfBounds);
            }
            if cursor >= entry_end {
                continue;
            }

            let file_offset = cursor - entry.offset;
            let max_len = (entry_end - cursor) as usize;
            let chunk_len = remaining.len().min(max_len);

            entry.file.seek(SeekFrom::Start(file_offset))?;
            entry.file.write_all(&remaining[..chunk_len])?;

            cursor += chunk_len as u64;
            remaining = &remaining[chunk_len..];
        }

        if !remaining.is_empty() {
            return Err(Error::OutOfBounds);
        }
        Ok(())
    }

    fn read_direct(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or(Error::OutOfBounds)?;
        if end > self.total_length {
            return Err(Error::OutOfBounds);
        }

        let mut cursor = offset;
        let mut remaining = out;

        for entry in &mut self.entries {
            if remaining.is_empty() {
                break;
            }
            let entry_end = entry.offset + entry.length;
            if cursor < entry.offset {
                return Err(Error::OutOfBounds);
            }
            if cursor >= entry_end {
                continue;
            }

            let file_offset = cursor - entry.offset;
            let max_len = (entry_end - cursor) as usize;
            let chunk_len = remaining.len().min(max_len);

            entry.file.seek(SeekFrom::Start(file_offset))?;
            entry.file.read_exact(&mut remaining[..chunk_len])?;

            cursor += chunk_len as u64;
            remaining = &mut remaining[chunk_len..];
        }

        if !remaining.is_empty() {
            return Err(Error::OutOfBounds);
        }
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), Error> {
        if self.write_cache.is_empty() {
            return Ok(());
        }
        let mut entries = Vec::new();
        std::mem::swap(&mut entries, &mut self.write_cache);
        self.write_cache_bytes = 0;
        for entry in entries {
            self.write_direct(entry.offset, &entry.data)?;
        }
        Ok(())
    }
}

fn build_layout(meta: &TorrentMeta, download_dir: &Path) -> Result<Vec<FileLayout>, Error> {
    let name = clean_name(&meta.info.name)?;
    let total_length = meta.info.total_length();
    if total_length == 0 {
        return Err(Error::InvalidLength);
    }

    if let Some(length) = meta.info.length {
        let path = download_dir.join(name);
        return Ok(vec![FileLayout {
            path,
            offset: 0,
            length,
        }]);
    }

    if meta.info.files.is_empty() {
        return Err(Error::InvalidFiles);
    }

    let base = download_dir.join(name);
    let mut layouts = Vec::with_capacity(meta.info.files.len());
    let mut offset = 0u64;
    for file in &meta.info.files {
        if file.path.is_empty() {
            return Err(Error::InvalidPathSegment);
        }
        let mut path = base.clone();
        for segment in &file.path {
            let segment = clean_segment(segment)?;
            path.push(segment);
        }
        layouts.push(FileLayout {
            path,
            offset,
            length: file.length,
        });
        offset = offset.saturating_add(file.length);
    }

    if offset != total_length {
        return Err(Error::InvalidLength);
    }
    Ok(layouts)
}

fn clean_name(bytes: &[u8]) -> Result<OsString, Error> {
    clean_segment(bytes).map_err(|_| Error::InvalidName)
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
        let invalid = [b':', b'*', b'?', b'"', b'<', b'>', b'|'];
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
    if name.is_empty() {
        return true;
    }
    matches!(
        name,
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
    use crate::torrent::{FileInfo, InfoDict};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dummy_meta() -> TorrentMeta {
        TorrentMeta {
            announce: None,
            announce_list: Vec::new(),
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [0u8; 20],
            info: InfoDict {
                name: b"root".to_vec(),
                piece_length: 16384,
                pieces: vec![[0u8; 20]; 2],
                length: None,
                files: vec![
                    FileInfo {
                        length: 3,
                        path: vec![b"a.txt".to_vec()],
                    },
                    FileInfo {
                        length: 5,
                        path: vec![b"dir".to_vec(), b"b.bin".to_vec()],
                    },
                ],
                private: false,
            },
        }
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
    fn rejects_invalid_path_segments() {
        let mut meta = dummy_meta();
        meta.info.files[0].path = vec![b"..".to_vec()];
        let err = build_layout(&meta, Path::new("/tmp")).unwrap_err();
        assert!(matches!(err, Error::InvalidPathSegment));
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
}
