//! Handle-relative Windows filesystem primitives.
//!
//! Every relative open starts from a pinned directory handle, opens one path
//! component at a time with `FILE_OPEN_REPARSE_POINT`, and omits
//! `FILE_SHARE_DELETE`.  That makes path validation and the operation which
//! consumes it one descriptor-bound action instead of a check-then-open race.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::mem::{offset_of, MaybeUninit};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf};

const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_LIST_DIRECTORY: u32 = FILE_READ_DATA;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_ADD_FILE: u32 = FILE_WRITE_DATA;
const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
const FILE_TRAVERSE: u32 = 0x0000_0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;

const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

const FILE_RENAME_INFORMATION_CLASS: u32 = 10;
const FILE_DISPOSITION_INFORMATION_CLASS: u32 = 13;
const FILE_ID_INFO_CLASS: u32 = 18;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: RawHandle,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
union IoStatusBlockStatus {
    status: i32,
    pointer: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: IoStatusBlockStatus,
    information: usize,
}

#[repr(C)]
struct FileTime {
    _low: u32,
    _high: u32,
}

#[repr(C)]
struct ByHandleFileInformation {
    attributes: u32,
    _creation_time: FileTime,
    _last_access_time: FileTime,
    _last_write_time: FileTime,
    _volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    _file_index_high: u32,
    _file_index_low: u32,
}

#[repr(C)]
struct FileId128 {
    identifier: [u8; 16],
}

#[repr(C)]
struct FileIdInformation {
    volume_serial_number: u64,
    file_id: FileId128,
}

#[repr(C)]
union RenameMode {
    replace_if_exists: u8,
    flags: u32,
}

#[repr(C)]
struct FileRenameInformation {
    mode: RenameMode,
    root_directory: RawHandle,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[repr(C)]
struct FileDispositionInformation {
    delete_file: u8,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFinalPathNameByHandleW(file: RawHandle, path: *mut u16, path_len: u32, flags: u32)
        -> u32;
    fn GetFileInformationByHandle(
        file: RawHandle,
        information: *mut ByHandleFileInformation,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        file: RawHandle,
        information_class: u32,
        information: *mut c_void,
        information_size: u32,
    ) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut RawHandle,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        file_handle: RawHandle,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut c_void,
        length: u32,
        file_information_class: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    pub(crate) volume_serial_number: u64,
    pub(crate) file_id: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileInfo {
    pub(crate) identity: FileIdentity,
    pub(crate) attributes: u32,
    pub(crate) number_of_links: u32,
    pub(crate) length: u64,
}

impl FileInfo {
    pub(crate) fn is_directory(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub(crate) fn is_reparse_point(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreateDisposition {
    OpenExisting,
    CreateNew,
    OpenOrCreate,
}

impl CreateDisposition {
    fn native(self) -> u32 {
        match self {
            Self::OpenExisting => FILE_OPEN,
            Self::CreateNew => FILE_CREATE,
            Self::OpenOrCreate => FILE_OPEN_IF,
        }
    }
}

#[derive(Debug)]
pub(crate) struct OpenedFile {
    pub(crate) file: File,
    pub(crate) info: FileInfo,
    pub(crate) parent_identity: FileIdentity,
    pub(crate) created: bool,
}

#[derive(Debug)]
pub(crate) struct PinnedDir {
    file: File,
    info: FileInfo,
    final_path: PathBuf,
}

impl PinnedDir {
    /// Open and pin an existing directory. The final component may not be a
    /// reparse point, and the handle must resolve to the same object which the
    /// supplied path named during the open.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let canonical = fs::canonicalize(path)?;
        let mut options = fs::OpenOptions::new();
        let file = options
            .access_mode(directory_access())
            // Omitting FILE_SHARE_DELETE pins this directory entry.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let opened = Self::from_file(file)?;
        if opened.final_path != canonical {
            return Err(permission_denied(
                "directory changed or was redirected while it was opened",
            ));
        }
        Ok(opened)
    }

    fn from_file(file: File) -> io::Result<Self> {
        let info = file_info(&file)?;
        if !info.is_directory() {
            return Err(invalid_data("opened object is not a directory"));
        }
        if info.is_reparse_point() {
            return Err(permission_denied(
                "filesystem reparse points are not allowed in pinned paths",
            ));
        }
        let final_path = final_path(&file)?;
        Ok(Self {
            file,
            info,
            final_path,
        })
    }

    pub(crate) fn identity(&self) -> FileIdentity {
        self.info.identity
    }

    pub(crate) fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub(crate) fn as_file(&self) -> &File {
        &self.file
    }

    /// Reopen the lexical directory path without following its final reparse
    /// point and verify that it still names this pinned object.
    pub(crate) fn verify_path(&self, path: &Path) -> io::Result<()> {
        let reopened = Self::open(path)?;
        if reopened.identity() != self.identity() || reopened.final_path != self.final_path {
            return Err(permission_denied(
                "directory path no longer names the pinned object",
            ));
        }
        Ok(())
    }

    /// Safely walk a relative directory path. Missing components are created
    /// with NT `FILE_OPEN_IF` only when `create` is true. The boolean reports
    /// whether the final component was created by this call.
    pub(crate) fn open_relative_dir(
        &self,
        relative: &Path,
        create: bool,
    ) -> io::Result<(Self, bool)> {
        let desired_access = if create {
            directory_access()
        } else {
            directory_read_access()
        };
        self.open_relative_dir_with_access(relative, create, desired_access, None)
    }

    /// State-directory variant which requests ACL access and attaches a
    /// caller-provided self-relative SECURITY_DESCRIPTOR to atomic creates.
    /// The descriptor is ignored by the kernel when the object already exists;
    /// callers must validate an existing directory before trusting its files.
    pub(crate) fn open_relative_dir_secure(
        &self,
        relative: &Path,
        create: bool,
        security_descriptor: Option<&[u8]>,
    ) -> io::Result<(Self, bool)> {
        let desired_access = if create {
            directory_access()
        } else {
            directory_read_access()
        };
        self.open_relative_dir_with_access(
            relative,
            create,
            desired_access | READ_CONTROL | WRITE_DAC,
            security_descriptor,
        )
    }

    fn open_relative_dir_with_access(
        &self,
        relative: &Path,
        create: bool,
        desired_access: u32,
        security_descriptor: Option<&[u8]>,
    ) -> io::Result<(Self, bool)> {
        let components = normal_components(relative)?;
        if components.is_empty() {
            return Ok((Self::from_file(self.file.try_clone()?)?, false));
        }

        let mut current = Self::from_file(self.file.try_clone()?)?;
        let mut final_created = false;
        let last_index = components.len() - 1;
        for (index, component) in components.iter().enumerate() {
            let disposition = if create {
                CreateDisposition::OpenOrCreate
            } else {
                CreateDisposition::OpenExisting
            };
            let opened = nt_open_component(
                &current.file,
                component,
                desired_access,
                disposition,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                security_descriptor,
            )?;
            let next = Self::from_file(opened.file)?;
            let expected = current.final_path.join(component);
            if next.final_path != expected {
                return Err(permission_denied("relative directory open was redirected"));
            }
            if index == last_index {
                final_created = opened.created;
            }
            current = next;
        }
        Ok((current, final_created))
    }

    /// Open a regular payload/state file relative to this pinned directory.
    /// The returned handle has read, write, attribute, synchronization, and
    /// DELETE access and deliberately omits FILE_SHARE_DELETE, so the entry
    /// cannot be swapped while the handle is live.
    pub(crate) fn open_regular(
        &self,
        relative: &Path,
        disposition: CreateDisposition,
        create_parents: bool,
    ) -> io::Result<OpenedFile> {
        let (parent_relative, name) = split_parent_name(relative)?;
        let parent = self.open_relative_dir(&parent_relative, create_parents)?.0;
        let opened = nt_open_component(
            &parent.file,
            &name,
            regular_access(),
            disposition,
            false,
            0,
            None,
        )?;
        checked_regular(opened, &parent, &name)
    }

    /// State-file variant with READ_CONTROL in addition to ordinary
    /// read/write/delete rights, so the owner and DACL can be inspected before
    /// any bytes are consumed.
    pub(crate) fn open_regular_with_read_control(
        &self,
        relative: &Path,
        disposition: CreateDisposition,
        create_parents: bool,
    ) -> io::Result<OpenedFile> {
        let (parent_relative, name) = split_parent_name(relative)?;
        let parent = self.open_relative_dir(&parent_relative, create_parents)?.0;
        let opened = nt_open_component(
            &parent.file,
            &name,
            regular_access() | READ_CONTROL,
            disposition,
            false,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
        )?;
        checked_regular(opened, &parent, &name)
    }

    /// Private-state variant which can apply a self-relative security
    /// descriptor atomically when creating a file under a broadly writable
    /// download root. Existing files are opened with READ_CONTROL|WRITE_DAC so
    /// the caller can validate before deliberately normalizing their DACL.
    pub(crate) fn open_regular_secure(
        &self,
        relative: &Path,
        disposition: CreateDisposition,
        create_parents: bool,
        security_descriptor: Option<&[u8]>,
    ) -> io::Result<OpenedFile> {
        let (parent_relative, name) = split_parent_name(relative)?;
        let parent = self.open_relative_dir(&parent_relative, create_parents)?.0;
        let opened = nt_open_component(
            &parent.file,
            &name,
            regular_access() | READ_CONTROL | WRITE_DAC,
            disposition,
            false,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            security_descriptor,
        )?;
        checked_regular(opened, &parent, &name)
    }

    /// Rename an open file into this already-pinned directory. Callers which
    /// retained an earlier parent identity can compare it before this method,
    /// keeping the identity check and rename bound to the same handle.
    pub(crate) fn rename_open_file_here(
        &self,
        file: &File,
        new_name: &OsStr,
        replace: bool,
    ) -> io::Result<()> {
        validate_component(new_name)?;
        rename_relative(file, &self.file, new_name, replace)
    }
}

fn checked_regular(opened: NativeOpen, parent: &PinnedDir, name: &OsStr) -> io::Result<OpenedFile> {
    let info = file_info(&opened.file)?;
    if info.is_directory() {
        return Err(invalid_data("payload path names a directory"));
    }
    if info.is_reparse_point() {
        return Err(permission_denied("payload reparse points are not allowed"));
    }
    if info.number_of_links != 1 {
        return Err(invalid_data(
            "multiply-linked payload files are not allowed",
        ));
    }
    let resolved = final_path(&opened.file)?;
    let expected = parent.final_path.join(name);
    if resolved != expected {
        return Err(permission_denied("relative file open was redirected"));
    }
    Ok(OpenedFile {
        file: opened.file,
        info,
        parent_identity: parent.identity(),
        created: opened.created,
    })
}

pub(crate) fn file_info(file: &File) -> io::Result<FileInfo> {
    let mut information = MaybeUninit::<ByHandleFileInformation>::uninit();
    // SAFETY: `file` owns a live handle and Windows initializes the complete
    // BY_HANDLE_FILE_INFORMATION structure on success.
    let result =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the API initialized the output on a nonzero return.
    let information = unsafe { information.assume_init() };
    let mut identity = MaybeUninit::<FileIdInformation>::uninit();
    // SAFETY: `file` owns a live non-pipe handle, `FileIdInfo` requests the
    // documented FILE_ID_INFO layout, and the output buffer has its exact size.
    // This 128-bit identifier is required because ReFS does not guarantee that
    // BY_HANDLE_FILE_INFORMATION's legacy 64-bit file index is unique.
    let identity_result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            identity.as_mut_ptr().cast(),
            std::mem::size_of::<FileIdInformation>() as u32,
        )
    };
    if identity_result == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the API initialized the complete FILE_ID_INFO output on success.
    let identity = unsafe { identity.assume_init() };
    let length =
        (u64::from(information.file_size_high) << 32) | u64::from(information.file_size_low);
    Ok(FileInfo {
        identity: FileIdentity {
            volume_serial_number: identity.volume_serial_number,
            file_id: identity.file_id.identifier,
        },
        attributes: information.attributes,
        number_of_links: information.number_of_links,
        length,
    })
}

pub(crate) fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut capacity = 512usize;
    loop {
        if capacity > 65_536 {
            return Err(invalid_data("resolved Windows path is unreasonably long"));
        }
        let mut buffer = vec![0u16; capacity];
        // SAFETY: the file handle is live and buffer exposes its full writable
        // capacity to GetFinalPathNameByHandleW.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                0,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity = (length as usize).saturating_add(1);
    }
}

/// Mark an object, opened with DELETE access, for deletion.
pub(crate) fn mark_delete(file: &File) -> io::Result<()> {
    let mut information = FileDispositionInformation { delete_file: 1 };
    let mut io_status = empty_io_status();
    // SAFETY: the file handle is live, was opened with DELETE access, and the
    // information buffer has the native FILE_DISPOSITION_INFORMATION layout.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut io_status,
            (&mut information as *mut FileDispositionInformation).cast(),
            std::mem::size_of::<FileDispositionInformation>() as u32,
            FILE_DISPOSITION_INFORMATION_CLASS,
        )
    };
    nt_result(status)
}

struct NativeOpen {
    file: File,
    created: bool,
}

fn nt_open_component(
    parent: &File,
    component: &OsStr,
    desired_access: u32,
    disposition: CreateDisposition,
    directory: bool,
    share_access: u32,
    security_descriptor: Option<&[u8]>,
) -> io::Result<NativeOpen> {
    let mut wide = validate_component(component)?;
    let mut aligned_security = Vec::<usize>::new();
    if let Some(descriptor) = security_descriptor {
        if descriptor.is_empty() {
            return Err(invalid_input("empty Windows security descriptor"));
        }
        aligned_security.resize(descriptor.len().div_ceil(std::mem::size_of::<usize>()), 0);
        // SAFETY: aligned_security has at least descriptor.len() writable
        // bytes, and the source/destination allocations cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                descriptor.as_ptr(),
                aligned_security.as_mut_ptr().cast::<u8>(),
                descriptor.len(),
            );
        }
    }
    let byte_length = u16::try_from(wide.len().saturating_mul(2))
        .map_err(|_| invalid_input("Windows path component is too long"))?;
    let mut name = UnicodeString {
        length: byte_length,
        maximum_length: byte_length,
        buffer: wide.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &mut name,
        // Deliberately omit OBJ_CASE_INSENSITIVE. Exact case avoids opening an
        // attacker-controlled alias in a case-sensitive Windows directory.
        attributes: 0,
        security_descriptor: if aligned_security.is_empty() {
            std::ptr::null_mut()
        } else {
            aligned_security.as_mut_ptr().cast()
        },
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut io_status = empty_io_status();
    let mut handle: RawHandle = std::ptr::null_mut();
    let create_options = FILE_OPEN_FOR_BACKUP_INTENT
        | FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    // SAFETY: all native structures are live and use their documented C
    // layouts. The object name is one validated relative component and parent
    // owns the RootDirectory handle. A successful call transfers one handle.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &mut attributes,
            &mut io_status,
            std::ptr::null_mut(),
            if directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
            // FILE_SHARE_DELETE is always omitted to pin the entry. Payload
            // callers additionally pass zero so ownership is exclusive even
            // between multiple handles opened by the same process.
            share_access,
            disposition.native(),
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    nt_result(status)?;
    if handle.is_null() {
        return Err(io::Error::other("Windows returned an empty file handle"));
    }
    // FILE_CREATED is 2 in IO_STATUS_BLOCK.Information for create/open calls.
    let created = io_status.information == 2;
    // SAFETY: NtCreateFile returned a newly-owned non-null handle.
    let file = unsafe { File::from_raw_handle(handle) };
    Ok(NativeOpen { file, created })
}

fn rename_relative(file: &File, parent: &File, new_name: &OsStr, replace: bool) -> io::Result<()> {
    let wide = validate_component(new_name)?;
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| invalid_input("Windows rename target is too long"))?;
    let name_bytes_u32 = u32::try_from(name_bytes)
        .map_err(|_| invalid_input("Windows rename target is too long"))?;
    let header = offset_of!(FileRenameInformation, file_name);
    let total = header
        .checked_add(name_bytes)
        .ok_or_else(|| invalid_input("Windows rename buffer is too large"))?;
    let total_u32 =
        u32::try_from(total).map_err(|_| invalid_input("Windows rename buffer is too large"))?;
    let words = total.div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; words];
    let information = storage.as_mut_ptr().cast::<FileRenameInformation>();
    // SAFETY: storage is pointer-aligned, large enough for the header plus all
    // UTF-16 name bytes, and remains live across NtSetInformationFile.
    unsafe {
        std::ptr::addr_of_mut!((*information).mode).write(RenameMode {
            replace_if_exists: u8::from(replace),
        });
        std::ptr::addr_of_mut!((*information).root_directory).write(parent.as_raw_handle());
        std::ptr::addr_of_mut!((*information).file_name_length).write(name_bytes_u32);
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*information).file_name).cast::<u16>(),
            wide.len(),
        );
    }
    let mut io_status = empty_io_status();
    // SAFETY: file has DELETE access, parent is a pinned directory handle, and
    // information is the native FILE_RENAME_INFORMATION variable-size layout.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut io_status,
            information.cast(),
            total_u32,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    nt_result(status)
}

fn directory_access() -> u32 {
    directory_read_access() | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
}

fn directory_read_access() -> u32 {
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
}

fn regular_access() -> u32 {
    FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | SYNCHRONIZE
}

fn normal_components(path: &Path) -> io::Result<Vec<OsString>> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => {
                validate_component(name)?;
                Ok(name.to_os_string())
            }
            _ => Err(invalid_input("unsafe relative Windows path")),
        })
        .collect()
}

fn split_parent_name(path: &Path) -> io::Result<(PathBuf, OsString)> {
    let components = normal_components(path)?;
    let (name, parents) = components
        .split_last()
        .ok_or_else(|| invalid_input("empty relative Windows path"))?;
    let mut parent = PathBuf::new();
    for component in parents {
        parent.push(component);
    }
    Ok((parent, name.clone()))
}

fn validate_component(component: &OsStr) -> io::Result<Vec<u16>> {
    let wide = component.encode_wide().collect::<Vec<_>>();
    if wide.is_empty()
        || wide == [b'.' as u16]
        || wide == [b'.' as u16, b'.' as u16]
        || wide.contains(&0)
        || wide.contains(&(b'/' as u16))
        || wide.contains(&(b'\\' as u16))
        || wide.len() > (u16::MAX as usize / 2)
    {
        return Err(invalid_input("invalid Windows path component"));
    }
    Ok(wide)
}

fn empty_io_status() -> IoStatusBlock {
    IoStatusBlock {
        status: IoStatusBlockStatus {
            pointer: std::ptr::null_mut(),
        },
        information: 0,
    }
}

fn nt_result(status: i32) -> io::Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: translating an NTSTATUS has no preconditions.
    let error = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::from_raw_os_error(error as i32))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::{FileIdInformation, FileIdentity};

    #[test]
    fn identity_compares_all_128_file_id_bits() {
        let first = FileIdentity {
            volume_serial_number: 7,
            file_id: [0; 16],
        };
        let mut second = first;
        second.file_id[15] = 1;

        assert_ne!(first, second);
        let identities = std::collections::HashSet::from([first, second]);
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn file_id_info_ffi_layout_carries_the_full_identifier() {
        assert_eq!(std::mem::offset_of!(FileIdInformation, file_id), 8);
        assert_eq!(std::mem::size_of::<FileIdInformation>(), 24);
    }
}
