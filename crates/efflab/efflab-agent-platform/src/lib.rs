//! Efflab Agent Kit 共享的平台安全原语。
//!
//! Windows 实现把路径访问收敛到本地磁盘上的句柄相对操作，并在对象创建或读取时
//! 验证 reparse point、普通文件类型、单链接和受保护的当前用户 DACL。Host 与 sidecar
//! 只通过本模块使用这些原语，避免各自维护一套容易漂移的 Windows hardening。

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

/// 私有目录要求使用的 Unix 对照权限；Windows 对应受保护 owner-only DACL。
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
/// 私有文件要求使用的 Unix 对照权限；Windows 对应受保护 owner-only DACL。
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// sidecar home 的唯一生命周期锁文件名。
pub const HOME_LOCK_FILENAME: &str = ".efflab-sidecar.lock";
/// 当前 runtime config 的固定文件名。
pub const RUNTIME_CONFIG_FILENAME: &str = "runtime-config.v1.toml";

/// 已打开并完成 reparse/类型校验的目录句柄。
pub struct SecureDirectory {
    #[cfg(windows)]
    handle: File,
}

/// 启动阶段保存的 home 与 session cwd 句柄。
pub struct StartupHandles {
    #[cfg(windows)]
    home: SecureDirectory,
    #[cfg(windows)]
    session_cwd: SecureDirectory,
}

impl SecureDirectory {
    /// 复制一个已验证目录句柄，供需要独立生命周期的调用方使用。
    pub fn try_clone(&self) -> io::Result<Self> {
        #[cfg(windows)]
        {
            return Ok(Self {
                handle: self.handle.try_clone()?,
            });
        }
        #[cfg(not(windows))]
        {
            Err(unsupported())
        }
    }
}

impl StartupHandles {
    /// 在已钉住的 home 目录下读取受保护的私有文件。
    pub fn read_private_file(&self, name: &OsStr, max_bytes: usize) -> io::Result<Vec<u8>> {
        #[cfg(windows)]
        {
            return windows::read_private_file_at(&self.home, name, max_bytes);
        }
        #[cfg(not(windows))]
        {
            let _ = (name, max_bytes);
            Err(unsupported())
        }
    }

    /// 在已钉住的 home 目录下检查单一目录项是否存在。
    pub fn path_entry_exists(&self, name: &OsStr) -> io::Result<bool> {
        #[cfg(windows)]
        {
            return windows::path_entry_exists_at(&self.home, name);
        }
        #[cfg(not(windows))]
        {
            let _ = name;
            Err(unsupported())
        }
    }

    /// 在已钉住的 home 目录下打开生命周期锁文件。
    pub fn open_or_create_private_lock(&self) -> io::Result<File> {
        #[cfg(windows)]
        {
            return windows::open_or_create_private_lock_at(&self.home);
        }
        #[cfg(not(windows))]
        {
            Err(unsupported())
        }
    }

    /// 用已钉住的 session cwd 句柄设置当前目录。
    pub fn set_current_dir_secure(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            return windows::set_current_dir_from_handle(&self.session_cwd);
        }
        #[cfg(not(windows))]
        {
            Err(unsupported())
        }
    }
}

/// 校验 Windows/Unix 共用的绝对路径形状，不解析任何文件系统对象。
pub fn validate_absolute_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.to_str().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "安全路径必须是绝对路径且不包含 ..",
        ));
    }
    Ok(())
}

/// 逐级创建或验证私有目录；新建目录立即应用 owner-only protected DACL。
pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        return windows::ensure_private_directory(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 只创建一个新的私有目录，任何已有目录项都视为冲突。
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        return windows::create_private_directory(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 校验路径最终对象是普通目录且不存在 reparse point。
pub fn verify_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        return windows::verify_directory(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 通过已验证目录句柄枚举直接子项，并拒绝 reparse 或特殊目录项。
pub fn list_directory(path: &Path) -> io::Result<Vec<OsString>> {
    #[cfg(windows)]
    {
        windows::list_directory(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 在句柄相对边界内递归删除普通文件和目录，不跟随 reparse point。
pub fn remove_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::remove_directory(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 在同一安全父目录内以句柄相对方式发布目录。
pub fn rename_directory(path: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::rename_directory(path, destination)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, destination);
        Err(unsupported())
    }
}

/// 刷新已验证目录句柄，确保目录元数据落盘。
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::sync_directory(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 逐级 no-reparse 打开普通单硬链接文件并执行有界读取。
pub fn read_regular_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        windows::read_regular_file(path, max_bytes)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, max_bytes);
        Err(unsupported())
    }
}

/// 校验路径最终目录使用受保护的当前用户 owner-only DACL。
pub fn verify_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        return windows::verify_private_directory(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 打开已有目录链；任何中间 reparse point、非目录或非本地磁盘都被拒绝。
pub fn open_existing_directory(path: &Path) -> io::Result<SecureDirectory> {
    #[cfg(windows)]
    {
        return windows::open_directory_chain(path, false, false);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 打开已有目录链，并验证最终目录的 owner-only protected DACL。
pub fn open_existing_private_directory(path: &Path) -> io::Result<SecureDirectory> {
    #[cfg(windows)]
    {
        return windows::open_directory_chain(path, false, true);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 保存启动阶段已经校验的 home 与 session cwd 目录句柄。
pub fn open_startup_handles(home: &Path, session_cwd: &Path) -> io::Result<StartupHandles> {
    #[cfg(windows)]
    {
        let session_cwd = windows::open_directory_chain(session_cwd, false, true)?;
        let home = windows::open_directory_chain(home, false, true)?;
        return Ok(StartupHandles { home, session_cwd });
    }
    #[cfg(not(windows))]
    {
        let _ = (home, session_cwd);
        Err(unsupported())
    }
}

/// 打开已验证父目录内的已有普通文件；最终文件不会跟随 reparse point。
pub fn open_existing_file(parent: &SecureDirectory, name: &OsStr, write: bool) -> io::Result<File> {
    #[cfg(windows)]
    {
        return windows::open_file_at(parent, name, write, false, false, false);
    }
    #[cfg(not(windows))]
    {
        let _ = (parent, name, write);
        Err(unsupported())
    }
}

/// 读取指定路径下受保护的普通文件，并限制最大读取字节数。
pub fn read_private_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        return windows::read_private_file(path, max_bytes);
    }
    #[cfg(not(windows))]
    {
        let _ = (path, max_bytes);
        Err(unsupported())
    }
}

/// 创建或打开受保护的追加文件，供 sidecar 独立 stderr 日志使用。
pub fn open_or_create_private_append(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        return windows::open_or_create_private_append(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 创建或打开 home 生命周期锁文件；锁本身由调用方使用平台文件锁保持。
pub fn open_or_create_private_lock(home: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        return windows::open_or_create_private_lock(home);
    }
    #[cfg(not(windows))]
    {
        let _ = home;
        Err(unsupported())
    }
}

/// 在同一受保护父目录内执行 flush、句柄相对 rename 和父目录刷新。
pub fn atomic_write_private(path: &Path, content: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        return windows::atomic_write_private(path, content);
    }
    #[cfg(not(windows))]
    {
        let _ = (path, content);
        Err(unsupported())
    }
}

/// 检查受保护父目录下的单一目录项是否存在。
pub fn path_entry_exists(path: &Path) -> io::Result<bool> {
    #[cfg(windows)]
    {
        return windows::path_entry_exists(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 用已打开目录句柄校验并设置当前工作目录，避免按未验证路径直接切换。
pub fn set_current_dir_secure(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        return windows::set_current_dir_secure(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// 获取 Windows 卷序列号与 128 位 FileId 组成的稳定目录身份。
pub fn file_id(directory: &SecureDirectory) -> io::Result<[u8; 24]> {
    #[cfg(windows)]
    {
        return windows::file_id(&directory.handle);
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        Err(unsupported())
    }
}

/// 在已钉住的目录句柄下逐级创建或验证私有目录。
#[cfg(windows)]
pub fn ensure_private_directory_relative(
    root: &SecureDirectory,
    relative: &Path,
) -> io::Result<()> {
    windows::ensure_private_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下独占创建私有目录。
#[cfg(windows)]
pub fn create_private_directory_relative(
    root: &SecureDirectory,
    relative: &Path,
) -> io::Result<()> {
    windows::create_private_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下验证普通目录。
#[cfg(windows)]
pub fn verify_directory_relative(root: &SecureDirectory, relative: &Path) -> io::Result<()> {
    windows::verify_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下验证 owner-only 私有目录。
#[cfg(windows)]
pub fn verify_private_directory_relative(
    root: &SecureDirectory,
    relative: &Path,
) -> io::Result<()> {
    windows::verify_private_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下枚举普通直接子项。
#[cfg(windows)]
pub fn list_directory_relative(
    root: &SecureDirectory,
    relative: &Path,
) -> io::Result<Vec<OsString>> {
    windows::list_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下递归删除目录。
#[cfg(windows)]
pub fn remove_directory_relative(root: &SecureDirectory, relative: &Path) -> io::Result<()> {
    windows::remove_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下递归删除私有目录，且逐级验证私有父目录。
#[cfg(windows)]
pub fn remove_private_directory_relative(
    root: &SecureDirectory,
    relative: &Path,
) -> io::Result<()> {
    windows::remove_private_directory_relative(root, relative)
}

/// 在已钉住的目录句柄下执行同父目录原子目录发布。
#[cfg(windows)]
pub fn rename_directory_relative(
    root: &SecureDirectory,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    windows::rename_directory_relative(root, source, destination)
}

/// 在已钉住的目录句柄下发布私有目录，且逐级验证私有父目录。
#[cfg(windows)]
pub fn rename_private_directory_relative(
    root: &SecureDirectory,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    windows::rename_private_directory_relative(root, source, destination)
}

/// 刷新已钉住目录句柄下的目录元数据。
#[cfg(windows)]
pub fn sync_directory_relative(root: &SecureDirectory, relative: &Path) -> io::Result<()> {
    windows::sync_directory_relative(root, relative)
}

/// 刷新已钉住目录句柄下的私有目录元数据，且逐级验证私有目录。
#[cfg(windows)]
pub fn sync_private_directory_relative(root: &SecureDirectory, relative: &Path) -> io::Result<()> {
    windows::sync_private_directory_relative(root, relative)
}

/// 从已钉住目录句柄下读取普通单硬链接文件。
#[cfg(windows)]
pub fn read_regular_file_relative(
    root: &SecureDirectory,
    relative: &Path,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    windows::read_regular_file_relative(root, relative, max_bytes)
}

/// 从已钉住目录句柄下读取 owner-only 私有文件。
#[cfg(windows)]
pub fn read_private_file_relative(
    root: &SecureDirectory,
    relative: &Path,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    windows::read_private_file_relative(root, relative, max_bytes)
}

/// 检查已钉住目录句柄下的相对目录项是否存在。
#[cfg(windows)]
pub fn path_entry_exists_relative(root: &SecureDirectory, relative: &Path) -> io::Result<bool> {
    windows::path_entry_exists_relative(root, relative)
}

/// 在已钉住的目录句柄下检查私有相对目录项，且逐级验证私有父目录。
#[cfg(windows)]
pub fn path_entry_exists_private_relative(
    root: &SecureDirectory,
    relative: &Path,
) -> io::Result<bool> {
    windows::path_entry_exists_private_relative(root, relative)
}

/// 在已钉住目录句柄下原子替换 owner-only 私有文件。
#[cfg(windows)]
pub fn atomic_write_private_relative(
    root: &SecureDirectory,
    relative: &Path,
    content: &[u8],
) -> io::Result<()> {
    windows::atomic_write_private_relative(root, relative, content)
}

/// 返回指定启动句柄所钉住的 home 目录副本。
#[cfg(windows)]
impl StartupHandles {
    pub fn home_directory(&self) -> io::Result<SecureDirectory> {
        self.home.try_clone()
    }
}

/// 获取最近现有路径前缀的物理路径，并保留尚不存在的尾部组件。
pub fn canonicalize_existing_path_prefix(path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        return windows::canonicalize_existing_path_prefix(path);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(unsupported())
    }
}

#[cfg(not(windows))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows 文件系统硬化原语只在 Windows 目标提供",
    )
}

#[cfg(windows)]
mod windows {
    use super::{
        Component, File, HOME_LOCK_FILENAME, OsStr, OsString, Path, PathBuf, SecureDirectory,
        validate_absolute_path,
    };
    use std::ffi::c_void;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::mem::{align_of, size_of, size_of_val};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    type Handle = *mut c_void;
    type NtStatus = i32;

    const INVALID_HANDLE_VALUE: Handle = (-1isize) as Handle;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_TYPE_DISK: u32 = 1;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_RAMDISK: u32 = 6;

    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const OBJ_DONT_REPARSE: u32 = 0x0000_1000;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const FILE_CREATED: usize = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    const FILE_INFO_BY_HANDLE_CLASS_STANDARD: u32 = 1;
    const FILE_INFORMATION_CLASS_INTERNAL: u32 = 6;
    const FILE_INFO_BY_HANDLE_CLASS_ATTRIBUTE_TAG: u32 = 9;
    const FILE_INFO_BY_HANDLE_CLASS_ID: u32 = 18;
    const FILE_INFORMATION_CLASS_RENAME: u32 = 10;
    const FILE_INFORMATION_CLASS_DISPOSITION: u32 = 13;
    const FILE_INFORMATION_CLASS_ID_BOTH_DIRECTORY: u32 = 37;
    const DIRECTORY_BUFFER_WORDS: usize = 8192;

    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_REPARSE_POINT_ENCOUNTERED: u32 = 0xC000_050B;
    const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
    const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
    const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
    const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
    const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const SECURITY_DESCRIPTOR_CONTROL_PROTECTED_DACL: u16 = 0x1000;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const SE_FILE_OBJECT: u32 = 1;
    const ACL_SIZE_INFORMATION_CLASS: u32 = 2;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    const SET_ACCESS: u32 = 2;
    const NO_MULTIPLE_TRUSTEE: u32 = 0;
    const TRUSTEE_IS_SID: u32 = 0;
    const TRUSTEE_IS_USER: u32 = 1;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: NtStatus,
        information: usize,
    }

    #[repr(C)]
    struct FileAttributeTagInfo {
        file_attributes: u32,
        reparse_tag: u32,
    }

    #[repr(C)]
    struct FileStandardInfo {
        _allocation_size: i64,
        _end_of_file: i64,
        number_of_links: u32,
        _delete_pending: u8,
        _directory: u8,
    }

    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    #[repr(C)]
    struct FileInternalInformation {
        file_id: i64,
    }

    #[repr(C)]
    struct FileIdBothDirectoryInformation {
        next_entry_offset: u32,
        _file_index: u32,
        _creation_time: i64,
        _last_access_time: i64,
        _last_write_time: i64,
        _change_time: i64,
        _end_of_file: i64,
        _allocation_size: i64,
        file_attributes: u32,
        file_name_length: u32,
        _ea_size: u32,
        _short_name_length: u8,
        _short_name: [u16; 12],
        file_id: i64,
        _file_name: [u16; 1],
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        _attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct TrusteeW {
        multiple_trustee: *mut c_void,
        multiple_trustee_operation: u32,
        trustee_form: u32,
        trustee_type: u32,
        name: *mut u16,
    }

    #[repr(C)]
    struct ExplicitAccessW {
        access_permissions: u32,
        access_mode: u32,
        inheritance: u32,
        trustee: TrusteeW,
    }

    #[repr(C)]
    struct Acl {
        _acl_revision: u8,
        _sbz1: u8,
        _acl_size: u16,
        _ace_count: u16,
        _sbz2: u16,
    }

    /// Win32 absolute SECURITY_DESCRIPTOR；其 SID/ACL 指针由保护描述符 owner 持有。
    #[repr(C)]
    struct SecurityDescriptor {
        revision: u8,
        sbz1: u8,
        control: u16,
        owner: Handle,
        group: Handle,
        sacl: *mut Acl,
        dacl: *mut Acl,
    }

    #[repr(C)]
    struct AclSizeInformation {
        ace_count: u32,
        _acl_bytes_in_use: u32,
        _acl_bytes_free: u32,
    }

    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    struct AccessAllowedAce {
        header: AceHeader,
        mask: u32,
        sid_start: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn GetFileInformationByHandleEx(
            file: Handle,
            info_class: u32,
            info: *mut c_void,
            info_size: u32,
        ) -> i32;
        fn GetFileType(file: Handle) -> u32;
        fn FlushFileBuffers(file: Handle) -> i32;
        fn GetFinalPathNameByHandleW(
            file: Handle,
            file_path: *mut u16,
            file_path_length: u32,
            flags: u32,
        ) -> u32;
        fn GetDriveTypeW(root_path_name: *const u16) -> u32;
        fn SetCurrentDirectoryW(path: *const u16) -> i32;
        fn GetLastError() -> u32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: u32,
            token_handle: *mut Handle,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: Handle,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn GetLengthSid(sid: *mut c_void) -> u32;
        fn EqualSid(sid1: *mut c_void, sid2: *mut c_void) -> i32;
        fn SetEntriesInAclW(
            count_entries: u32,
            list_of_explicit_entries: *mut ExplicitAccessW,
            old_acl: *mut Acl,
            new_acl: *mut *mut Acl,
        ) -> u32;
        fn SetSecurityInfo(
            handle: Handle,
            object_type: u32,
            security_info: u32,
            owner: *mut c_void,
            group: *mut c_void,
            dacl: *mut Acl,
            sacl: *mut Acl,
        ) -> u32;
        fn GetSecurityInfo(
            handle: Handle,
            object_type: u32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut Acl,
            sacl: *mut *mut Acl,
            security_descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetSecurityDescriptorControl(
            security_descriptor: *mut c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn InitializeSecurityDescriptor(security_descriptor: *mut c_void, revision: u32) -> i32;
        fn SetSecurityDescriptorOwner(
            security_descriptor: *mut c_void,
            owner: *mut c_void,
            owner_defaulted: i32,
        ) -> i32;
        fn SetSecurityDescriptorDacl(
            security_descriptor: *mut c_void,
            dacl_present: i32,
            dacl: *mut Acl,
            dacl_defaulted: i32,
        ) -> i32;
        fn SetSecurityDescriptorControl(
            security_descriptor: *mut c_void,
            control_bits_of_interest: u16,
            control_bits_to_set: u16,
        ) -> i32;
        fn GetAclInformation(
            acl: *mut Acl,
            acl_information: *mut c_void,
            acl_information_length: u32,
            acl_information_class: u32,
        ) -> i32;
        fn GetAce(acl: *mut Acl, ace_index: u32, ace: *mut *mut c_void) -> i32;
        fn LocalFree(memory: Handle) -> Handle;
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut Handle,
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
        ) -> NtStatus;
        // 使用同步目录句柄查询直接子项，避免把路径重新交给高层文件系统 API。
        fn NtQueryDirectoryFile(
            file_handle: Handle,
            event: Handle,
            apc_routine: *mut c_void,
            apc_context: *mut c_void,
            io_status_block: *mut IoStatusBlock,
            file_information: *mut c_void,
            length: u32,
            file_information_class: u32,
            return_single_entry: u8,
            file_name: *mut UnicodeString,
            restart_scan: u8,
        ) -> NtStatus;
        // 读取句柄内部 FileId，用于把枚举快照与随后打开的对象对拍。
        fn NtQueryInformationFile(
            file_handle: Handle,
            io_status_block: *mut IoStatusBlock,
            file_information: *mut c_void,
            length: u32,
            file_information_class: u32,
        ) -> NtStatus;
        fn NtSetInformationFile(
            file_handle: Handle,
            io_status_block: *mut IoStatusBlock,
            file_information: *mut c_void,
            length: u32,
            file_information_class: u32,
        ) -> NtStatus;
    }

    struct HandleGuard(Handle);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: 句柄由对应 Win32 API 返回且只由此 guard 负责关闭。
                unsafe {
                    let _ = windows_sys_close_handle(self.0);
                }
            }
        }
    }

    // 只声明 CloseHandle 的最小签名，避免把 Windows crate 的句柄类型带入共享 API。
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CloseHandle(handle: Handle) -> i32;
    }

    unsafe fn windows_sys_close_handle(handle: Handle) -> i32 {
        // SAFETY: 调用方保证 handle 是有效内核句柄或本函数不会被调用。
        unsafe { CloseHandle(handle) }
    }

    fn last_error() -> io::Error {
        // SAFETY: GetLastError 不读取调用方内存。
        let code = unsafe { GetLastError() };
        io::Error::from_raw_os_error(code as i32)
    }

    fn nt_error(status: NtStatus) -> io::Error {
        let kind = match status as u32 {
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => io::ErrorKind::NotFound,
            STATUS_OBJECT_NAME_COLLISION => io::ErrorKind::AlreadyExists,
            STATUS_ACCESS_DENIED | STATUS_REPARSE_POINT_ENCOUNTERED | STATUS_SHARING_VIOLATION => {
                io::ErrorKind::PermissionDenied
            }
            STATUS_NOT_A_DIRECTORY => io::ErrorKind::NotADirectory,
            STATUS_DIRECTORY_NOT_EMPTY => io::ErrorKind::Other,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(
            kind,
            format!("Windows 安全文件操作失败: NTSTATUS 0x{status:08x}"),
        )
    }

    fn encode_component(name: &OsStr) -> io::Result<Vec<u16>> {
        let mut wide = name.encode_wide().collect::<Vec<_>>();
        if wide.is_empty()
            || wide.iter().any(|unit| {
                *unit == 0 || *unit == b'/' as u16 || *unit == b'\\' as u16 || *unit == b':' as u16
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 安全路径组件不是普通目录项",
            ));
        }
        if name == OsStr::new(".") || name == OsStr::new("..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 安全路径组件不能是 dot segment",
            ));
        }
        if wide.len() > (u16::MAX as usize / 2).saturating_sub(1) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 安全路径组件过长",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    fn ensure_disk_handle(handle: Handle) -> io::Result<()> {
        // SAFETY: handle 来自打开成功的文件/目录对象。
        if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows 安全对象不是本地磁盘句柄",
            ));
        }
        Ok(())
    }

    fn has_reparse_point(handle: Handle) -> io::Result<bool> {
        let mut info = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        // SAFETY: info 是足够大的可写结构，handle 是有效句柄。
        let result = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FILE_INFO_BY_HANDLE_CLASS_ATTRIBUTE_TAG,
                (&mut info as *mut FileAttributeTagInfo).cast(),
                size_of::<FileAttributeTagInfo>() as u32,
            )
        };
        if result == 0 {
            return Err(last_error());
        }
        Ok(info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    fn validate_no_reparse(handle: Handle) -> io::Result<()> {
        ensure_disk_handle(handle)?;
        if has_reparse_point(handle)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows 安全对象不能是 reparse point",
            ));
        }
        Ok(())
    }

    fn validate_directory_handle(file: &File) -> io::Result<()> {
        validate_no_reparse(file.as_raw_handle())?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Windows 安全对象必须是普通目录",
            ));
        }
        Ok(())
    }

    fn validate_regular_file_type(file: &File) -> io::Result<()> {
        validate_no_reparse(file.as_raw_handle())?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows 安全对象必须是普通文件",
            ));
        }
        Ok(())
    }

    fn validate_regular_directory_entry(file: &File) -> io::Result<()> {
        validate_no_reparse(file.as_raw_handle())?;
        let metadata = file.metadata()?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows 安全目录项必须是普通文件或目录",
            ));
        }
        Ok(())
    }

    fn validate_single_link_regular_file(file: &File) -> io::Result<()> {
        validate_regular_file_type(file)?;
        let mut info = FileStandardInfo {
            _allocation_size: 0,
            _end_of_file: 0,
            number_of_links: 0,
            _delete_pending: 0,
            _directory: 0,
        };
        // SAFETY: info 是可写结构，句柄是已打开的普通文件。
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_INFO_BY_HANDLE_CLASS_STANDARD,
                (&mut info as *mut FileStandardInfo).cast(),
                size_of::<FileStandardInfo>() as u32,
            )
        } == 0
        {
            return Err(last_error());
        }
        if info.number_of_links != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows 安全文件不能有多个硬链接",
            ));
        }
        Ok(())
    }

    fn current_user_sid() -> io::Result<Vec<u8>> {
        let process = (-1isize) as Handle;
        let mut token = ptr::null_mut();
        // SAFETY: process 是当前进程伪句柄，token 指向可写句柄槽。
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error());
        }
        let token_guard = HandleGuard(token);
        let mut required = 0_u32;
        // SAFETY: 第一次调用只查询所需缓冲区长度。
        unsafe {
            let _ = GetTokenInformation(
                token_guard.0,
                TOKEN_USER_CLASS,
                ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required == 0 {
            return Err(last_error());
        }
        let mut buffer = vec![0_u8; required as usize];
        // SAFETY: buffer 长度由系统返回，指针和长度有效。
        if unsafe {
            GetTokenInformation(
                token_guard.0,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(last_error());
        }
        // SAFETY: TOKEN_USER 是 GetTokenInformation 返回的对齐结构，SID 指针位于 buffer 内部。
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TokenUser>()) };
        let sid_length = unsafe { GetLengthSid(token_user.user.sid) };
        if sid_length == 0 {
            return Err(last_error());
        }
        let mut sid = vec![0_u8; sid_length as usize];
        // SAFETY: sid 目标按系统返回长度分配，源 SID 已由 TokenUser 校验并保持有效。
        unsafe {
            ptr::copy_nonoverlapping(
                token_user.user.sid.cast::<u8>(),
                sid.as_mut_ptr(),
                sid.len(),
            );
        }
        Ok(sid)
    }

    /// 按对象创建时直接提交 owner-only protected DACL，避免先继承默认 ACL 再收紧的暴露窗口。
    struct ProtectedSecurityDescriptor {
        descriptor: SecurityDescriptor,
        _owner_sid: Vec<u8>,
        acl: *mut Acl,
    }

    impl ProtectedSecurityDescriptor {
        fn new() -> io::Result<Self> {
            let owner_sid = current_user_sid()?;
            let mut explicit = ExplicitAccessW {
                access_permissions: FILE_ALL_ACCESS,
                access_mode: SET_ACCESS,
                inheritance: 0,
                trustee: TrusteeW {
                    multiple_trustee: ptr::null_mut(),
                    multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                    trustee_form: TRUSTEE_IS_SID,
                    trustee_type: TRUSTEE_IS_USER,
                    name: owner_sid.as_ptr().cast_mut().cast(),
                },
            };
            let mut acl = ptr::null_mut();
            // SAFETY: explicit 中的 SID 在整个 API 调用期间保持有效；系统负责分配 ACL。
            let result = unsafe { SetEntriesInAclW(1, &mut explicit, ptr::null_mut(), &mut acl) };
            if result != 0 || acl.is_null() {
                if !acl.is_null() {
                    // SAFETY: acl 若非空则由 SetEntriesInAclW 分配，必须释放。
                    unsafe {
                        let _ = LocalFree(acl.cast());
                    }
                }
                return Err(io::Error::from_raw_os_error(result as i32));
            }

            let mut descriptor = std::mem::MaybeUninit::<SecurityDescriptor>::zeroed();
            // SAFETY: descriptor 指向按 C ABI 对齐且大小正确的可写结构。
            if unsafe {
                InitializeSecurityDescriptor(
                    descriptor.as_mut_ptr().cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                )
            } == 0
            {
                let error = last_error();
                // SAFETY: acl 由 SetEntriesInAclW 分配，必须释放。
                unsafe {
                    let _ = LocalFree(acl.cast());
                }
                return Err(error);
            }
            // SAFETY: InitializeSecurityDescriptor 已初始化 descriptor 的绝对格式。
            let mut descriptor = unsafe { descriptor.assume_init() };
            // SAFETY: owner_sid 与 acl 在返回对象生命周期内保持稳定有效。
            if unsafe {
                SetSecurityDescriptorOwner(
                    (&mut descriptor as *mut SecurityDescriptor).cast(),
                    owner_sid.as_ptr().cast_mut().cast(),
                    0,
                )
            } == 0
            {
                let error = last_error();
                // SAFETY: acl 由 SetEntriesInAclW 分配，必须释放。
                unsafe {
                    let _ = LocalFree(acl.cast());
                }
                return Err(error);
            }
            // SAFETY: descriptor 与 acl 均为当前函数持有的有效可写内存。
            if unsafe {
                SetSecurityDescriptorDacl(
                    (&mut descriptor as *mut SecurityDescriptor).cast(),
                    1,
                    acl.cast(),
                    0,
                )
            } == 0
            {
                let error = last_error();
                // SAFETY: acl 由 SetEntriesInAclW 分配，必须释放。
                unsafe {
                    let _ = LocalFree(acl.cast());
                }
                return Err(error);
            }
            // SAFETY: 仅修改 DACL 继承控制位，调用满足 Win32 绝对描述符合同。
            if unsafe {
                SetSecurityDescriptorControl(
                    (&mut descriptor as *mut SecurityDescriptor).cast(),
                    SECURITY_DESCRIPTOR_CONTROL_PROTECTED_DACL,
                    SECURITY_DESCRIPTOR_CONTROL_PROTECTED_DACL,
                )
            } == 0
            {
                let error = last_error();
                // SAFETY: acl 由 SetEntriesInAclW 分配，必须释放。
                unsafe {
                    let _ = LocalFree(acl.cast());
                }
                return Err(error);
            }

            Ok(Self {
                descriptor,
                _owner_sid: owner_sid,
                acl,
            })
        }

        fn as_ptr(&self) -> *mut c_void {
            (&self.descriptor as *const SecurityDescriptor)
                .cast_mut()
                .cast()
        }
    }

    impl Drop for ProtectedSecurityDescriptor {
        fn drop(&mut self) {
            if !self.acl.is_null() && self.acl.cast::<c_void>() != INVALID_HANDLE_VALUE {
                // SAFETY: acl 由 SetEntriesInAclW 分配且只由此 guard 负责释放。
                unsafe {
                    let _ = LocalFree(self.acl.cast());
                }
                self.acl = ptr::null_mut();
            }
        }
    }

    fn set_owner_only_acl(file: &File) -> io::Result<()> {
        let sid = current_user_sid()?;
        let mut explicit = ExplicitAccessW {
            access_permissions: FILE_ALL_ACCESS,
            access_mode: SET_ACCESS,
            inheritance: 0,
            trustee: TrusteeW {
                multiple_trustee: ptr::null_mut(),
                multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                trustee_form: TRUSTEE_IS_SID,
                trustee_type: TRUSTEE_IS_USER,
                name: sid.as_ptr().cast_mut().cast(),
            },
        };
        let mut acl = ptr::null_mut();
        // SAFETY: explicit 中的 SID 在整个 API 调用期间保持有效；系统负责分配 ACL。
        let result = unsafe { SetEntriesInAclW(1, &mut explicit, ptr::null_mut(), &mut acl) };
        if result != 0 || acl.is_null() {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        // SAFETY: acl 由 SetEntriesInAclW 分配，file 是有 WRITE_DAC 的有效句柄。
        let result = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            )
        };
        // SAFETY: acl 由系统本次分配，释放不会影响对象 DACL 的已提交副本。
        unsafe {
            let _ = LocalFree(acl.cast());
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Ok(())
    }

    fn verify_owner_only_acl(file: &File) -> io::Result<()> {
        let sid = current_user_sid()?;
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: 输出指针均指向可写槽，句柄只读访问足以读取安全描述符。
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let verification = (|| {
            if owner.is_null() || dacl.is_null() || descriptor.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows 私有对象缺少 owner 或 DACL",
                ));
            }
            // SAFETY: owner 由 GetSecurityInfo 返回，并与 descriptor 保持同一生命周期。
            if unsafe { EqualSid(owner, sid.as_ptr().cast_mut().cast()) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows 私有对象 owner SID 不匹配当前用户",
                ));
            }
            let mut control = 0_u16;
            let mut revision = 0_u32;
            // SAFETY: descriptor 由 GetSecurityInfo 返回，输出槽有效。
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            {
                return Err(last_error());
            }
            if control & SECURITY_DESCRIPTOR_CONTROL_PROTECTED_DACL == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows 私有对象 DACL 未受保护",
                ));
            }
            let mut size = AclSizeInformation {
                ace_count: 0,
                _acl_bytes_in_use: 0,
                _acl_bytes_free: 0,
            };
            // SAFETY: size 是可写结构，dacl 由系统返回。
            if unsafe {
                GetAclInformation(
                    dacl,
                    (&mut size as *mut AclSizeInformation).cast(),
                    size_of::<AclSizeInformation>() as u32,
                    ACL_SIZE_INFORMATION_CLASS,
                )
            } == 0
            {
                return Err(last_error());
            }
            if size.ace_count != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows 私有对象 DACL 不是单一 owner ACE",
                ));
            }
            let mut ace = ptr::null_mut();
            // SAFETY: ace 输出槽有效，索引由上面的 ACE 数量检查保证。
            if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
                return Err(last_error());
            }
            // SAFETY: 单一 ACE 的布局由 Windows ACL ABI 定义，GetAce 返回其起始地址。
            let allowed = unsafe { &*(ace.cast::<AccessAllowedAce>()) };
            if allowed.header.ace_type != ACCESS_ALLOWED_ACE_TYPE
                || allowed.header.ace_flags != 0
                || allowed.mask != FILE_ALL_ACCESS
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows 私有对象 ACE 不是无继承的 owner full-control",
                ));
            }
            // SAFETY: SidStart 是 ACCESS_ALLOWED_ACE 中紧随 mask 的 SID 起始地址。
            let ace_sid = (&allowed.sid_start as *const u32).cast_mut().cast();
            // SAFETY: 两个 SID 均由系统返回/本地缓冲区持有。
            if unsafe { EqualSid(sid.as_ptr().cast_mut().cast(), ace_sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows 私有对象 owner SID 不匹配当前用户",
                ));
            }
            Ok(())
        })();
        if !descriptor.is_null() {
            // SAFETY: descriptor 由 GetSecurityInfo 分配，必须由 LocalFree 释放。
            unsafe {
                let _ = LocalFree(descriptor);
            }
        }
        verification
    }

    fn verify_private_file(file: &File) -> io::Result<()> {
        validate_regular_file_type(file)?;
        let mut info = FileStandardInfo {
            _allocation_size: 0,
            _end_of_file: 0,
            number_of_links: 0,
            _delete_pending: 0,
            _directory: 0,
        };
        // SAFETY: info 是可写结构，句柄有效。
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_INFO_BY_HANDLE_CLASS_STANDARD,
                (&mut info as *mut FileStandardInfo).cast(),
                size_of::<FileStandardInfo>() as u32,
            )
        } == 0
        {
            return Err(last_error());
        }
        if info.number_of_links != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows 私有文件不能有多个硬链接",
            ));
        }
        verify_owner_only_acl(file)
    }

    #[derive(Clone, Copy)]
    enum EntryKind {
        Any,
        Directory,
        NonDirectory,
    }

    fn open_drive_root_with_sharing(drive: u8, share_delete: bool) -> io::Result<SecureDirectory> {
        let root = [drive as u16, b':' as u16, b'\\' as u16, 0];
        // SAFETY: root 是固定 NUL 终止 UTF-16 字符串。
        let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
        if drive_type != DRIVE_FIXED && drive_type != DRIVE_RAMDISK {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows Agent 状态只能位于本地固定磁盘",
            ));
        }
        let share_mode =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        // SAFETY: 参数均为固定值或空指针，返回句柄的所有权立即转给 File。
        let handle = unsafe {
            CreateFileW(
                root.as_ptr(),
                GENERIC_READ | SYNCHRONIZE,
                share_mode,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        // SAFETY: handle 刚由 CreateFileW 返回且尚未交给其它 owner。
        let file = unsafe { File::from_raw_handle(handle) };
        validate_directory_handle(&file)?;
        Ok(SecureDirectory { handle: file })
    }

    pub(super) fn open_file_at(
        parent: &SecureDirectory,
        name: &OsStr,
        write: bool,
        directory: bool,
        create: bool,
        exclusive: bool,
    ) -> io::Result<File> {
        let (_, file) = open_file_at_with_state(parent, name, write, directory, create, exclusive)?;
        Ok(file)
    }

    fn open_file_at_with_state(
        parent: &SecureDirectory,
        name: &OsStr,
        write: bool,
        directory: bool,
        create: bool,
        exclusive: bool,
    ) -> io::Result<(bool, File)> {
        let kind = if directory {
            EntryKind::Directory
        } else {
            EntryKind::NonDirectory
        };
        open_file_at_with_options(
            parent.handle.as_raw_handle(),
            name,
            write,
            kind,
            create,
            exclusive,
            true,
            false,
        )
    }

    fn open_file_at_with_options(
        root: Handle,
        name: &OsStr,
        write: bool,
        kind: EntryKind,
        create: bool,
        exclusive: bool,
        share_delete: bool,
        delete_access: bool,
    ) -> io::Result<(bool, File)> {
        let mut wide = encode_component(name)?;
        let byte_length = ((wide.len() - 1) * 2) as u16;
        let mut unicode = UnicodeString {
            length: byte_length,
            maximum_length: byte_length.saturating_add(2),
            buffer: wide.as_mut_ptr(),
        };
        // 新建对象时把受保护描述符直接交给 NtCreateFile；已有对象打开不需要构造它。
        let security_descriptor = if create || exclusive {
            Some(ProtectedSecurityDescriptor::new()?)
        } else {
            None
        };
        let mut attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: root,
            object_name: &mut unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: security_descriptor
                .as_ref()
                .map_or(ptr::null_mut(), ProtectedSecurityDescriptor::as_ptr),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut status_block = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut handle = ptr::null_mut();
        // 简体中文注释：已有目录只申请列举/遍历。C:\Users 对 Users 组通常只有 RX，
        // 再申请 GENERIC_WRITE 会在商店包和普通 AppData 上直接 ACCESS_DENIED。
        let desired_access = if delete_access {
            GENERIC_READ | DELETE | SYNCHRONIZE
        } else if exclusive {
            GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC | SYNCHRONIZE
        } else if create {
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | SYNCHRONIZE
        } else if write {
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE
        } else if matches!(kind, EntryKind::Directory) {
            GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE
        } else {
            GENERIC_READ | SYNCHRONIZE
        };
        let type_options = match kind {
            EntryKind::Any => 0,
            EntryKind::Directory => FILE_DIRECTORY_FILE,
            EntryKind::NonDirectory => FILE_NON_DIRECTORY_FILE,
        };
        let options = type_options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;
        let disposition = if exclusive {
            FILE_CREATE
        } else if create {
            FILE_OPEN_IF
        } else {
            FILE_OPEN
        };
        let share_mode =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        // SAFETY: 所有指针均指向本函数栈上仍存活的结构或父目录句柄。
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &mut attributes,
                &mut status_block,
                ptr::null_mut(),
                if matches!(kind, EntryKind::Directory) {
                    FILE_ATTRIBUTE_DIRECTORY
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
                share_mode,
                disposition,
                options,
                ptr::null_mut(),
                0,
            )
        };
        if exclusive && status as u32 == STATUS_OBJECT_NAME_COLLISION {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Windows 安全对象名称已存在",
            ));
        }
        if status < 0 {
            return Err(nt_error(status));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("Windows NtCreateFile 返回了无效句柄"));
        }
        // SAFETY: handle 刚由 NtCreateFile 返回且尚未交给其它 owner。
        let file = unsafe { File::from_raw_handle(handle) };
        validate_no_reparse(file.as_raw_handle())?;
        match kind {
            EntryKind::Directory => validate_directory_handle(&file)?,
            EntryKind::NonDirectory => validate_regular_file_type(&file)?,
            EntryKind::Any => validate_regular_directory_entry(&file)?,
        }
        Ok((status_block.information == FILE_CREATED, file))
    }

    fn open_file_at_handle(
        root: Handle,
        name: &OsStr,
        kind: EntryKind,
        share_delete: bool,
        delete_access: bool,
    ) -> io::Result<File> {
        let (_, file) = open_file_at_with_options(
            root,
            name,
            false,
            kind,
            false,
            false,
            share_delete,
            delete_access,
        )?;
        Ok(file)
    }

    fn open_existing_directory_component(
        parent: &SecureDirectory,
        name: &OsStr,
        share_delete: bool,
        write: bool,
    ) -> io::Result<File> {
        let (_, file) = open_file_at_with_options(
            parent.handle.as_raw_handle(),
            name,
            write,
            EntryKind::Directory,
            false,
            false,
            share_delete,
            false,
        )?;
        Ok(file)
    }

    fn open_directory_component_with_sharing(
        parent: &SecureDirectory,
        name: &OsStr,
        create: bool,
        share_delete: bool,
    ) -> io::Result<(SecureDirectory, bool)> {
        // 简体中文注释：已有祖先先尝试写打开；C:\Users 这类 RX 目录会 ACCESS_DENIED，
        // 再回退只读遍历。最终可写目录仍拿到 GENERIC_WRITE，以便创建子项和刷新。
        match open_existing_directory_component(parent, name, share_delete, true) {
            Ok(file) => return Ok((SecureDirectory { handle: file }, false)),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                match open_existing_directory_component(parent, name, share_delete, false) {
                    Ok(file) => return Ok((SecureDirectory { handle: file }, false)),
                    Err(fallback) if !create || fallback.kind() != io::ErrorKind::NotFound => {
                        return Err(fallback);
                    }
                    Err(_) => {}
                }
            }
            Err(error) if !create || error.kind() != io::ErrorKind::NotFound => {
                return Err(error);
            }
            Err(_) => {}
        }

        let (created, file) = open_file_at_with_options(
            parent.handle.as_raw_handle(),
            name,
            true,
            EntryKind::Directory,
            true,
            false,
            share_delete,
            false,
        )?;
        Ok((SecureDirectory { handle: file }, created))
    }

    fn path_components(path: &Path) -> io::Result<(u8, Vec<OsString>)> {
        validate_absolute_path(path)?;
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                std::path::Prefix::Disk(value) | std::path::Prefix::VerbatimDisk(value) => value,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Windows Agent 路径只支持本地磁盘盘符",
                    ));
                }
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows Agent 路径缺少磁盘盘符",
                ));
            }
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows Agent 路径缺少盘符根目录",
            ));
        }
        let mut names = Vec::new();
        for component in components {
            match component {
                Component::Normal(name) => {
                    let _ = super::windows::encode_component(name)?;
                    names.push(name.to_os_string());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows Agent 路径包含 ..",
                    ));
                }
                Component::Prefix(_) | Component::RootDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows Agent 路径包含无效组件",
                    ));
                }
            }
        }
        Ok((drive, names))
    }

    /// 解析相对于已钉住目录的普通目录项组件。
    fn relative_components(path: &Path) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    let _ = encode_component(name)?;
                    names.push(name.to_os_string());
                }
                Component::CurDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows 相对安全路径不能包含 .",
                    ));
                }
                Component::ParentDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows 相对安全路径不能包含 ..",
                    ));
                }
                Component::Prefix(_) | Component::RootDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows 相对安全路径不能包含盘符或根目录",
                    ));
                }
            }
        }
        if names.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 相对安全路径不能为空",
            ));
        }
        Ok(names)
    }

    /// 拆分相对路径，确保后续文件操作从已钉住的父目录句柄开始。
    fn split_relative(path: &Path) -> io::Result<(Vec<OsString>, OsString)> {
        let mut components = relative_components(path)?;
        let name = components
            .pop()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "相对路径缺少最终名称"))?;
        Ok((components, name))
    }

    /// 从已钉住的根目录句柄逐级打开或创建相对目录。
    fn open_directory_components(
        root: &SecureDirectory,
        components: &[OsString],
        create: bool,
        private_final: bool,
        share_delete: bool,
    ) -> io::Result<SecureDirectory> {
        let mut current = root.try_clone()?;
        if components.is_empty() {
            if private_final {
                verify_owner_only_acl(&current.handle)?;
            }
            return Ok(current);
        }
        for name in components {
            let (next, created) =
                open_directory_component_with_sharing(&current, name, create, share_delete)?;
            if created {
                set_owner_only_acl(&next.handle)?;
            }
            if private_final {
                verify_owner_only_acl(&next.handle)?;
            }
            current = next;
        }
        Ok(current)
    }

    /// 在已钉住根目录下逐级打开或创建相对目录。
    fn open_directory_chain_relative(
        root: &SecureDirectory,
        relative: &Path,
        create: bool,
        private_final: bool,
        share_delete: bool,
    ) -> io::Result<SecureDirectory> {
        let components = relative_components(relative)?;
        open_directory_components(root, &components, create, private_final, share_delete)
    }

    pub(super) fn open_directory_chain(
        path: &Path,
        create: bool,
        private_final: bool,
    ) -> io::Result<SecureDirectory> {
        open_directory_chain_with_sharing(path, create, private_final, true)
    }

    fn open_directory_chain_with_sharing(
        path: &Path,
        create: bool,
        private_final: bool,
        share_delete: bool,
    ) -> io::Result<SecureDirectory> {
        let (drive, names) = path_components(path)?;
        if names.is_empty() && private_final {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 私有目录不能是磁盘根",
            ));
        }
        // 磁盘根不可重命名；其后的组件按调用方要求关闭 delete sharing。
        let mut current = open_drive_root_with_sharing(drive, true)?;
        for (index, name) in names.iter().enumerate() {
            let is_final = index + 1 == names.len();
            let (next, created) =
                open_directory_component_with_sharing(&current, name, create, share_delete)?;
            if created {
                set_owner_only_acl(&next.handle)?;
                verify_owner_only_acl(&next.handle)?;
            } else if private_final && is_final {
                verify_owner_only_acl(&next.handle)?;
            }
            current = next;
        }
        Ok(current)
    }

    fn file_internal_id(file: &File) -> io::Result<i64> {
        let mut info = FileInternalInformation { file_id: 0 };
        let mut status_block = IoStatusBlock {
            status: 0,
            information: 0,
        };
        // SAFETY: info 和状态结构可写，句柄是本模块打开的有效磁盘对象。
        let status = unsafe {
            NtQueryInformationFile(
                file.as_raw_handle(),
                &mut status_block,
                (&mut info as *mut FileInternalInformation).cast(),
                size_of::<FileInternalInformation>() as u32,
                FILE_INFORMATION_CLASS_INTERNAL,
            )
        };
        if status < 0 {
            return Err(nt_error(status));
        }
        Ok(info.file_id)
    }

    #[derive(Clone)]
    struct DirectoryEntry {
        name: OsString,
        file_id: i64,
        attributes: u32,
    }

    impl DirectoryEntry {
        fn is_directory(&self) -> bool {
            self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        }
    }

    fn query_directory_entries(directory: Handle) -> io::Result<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();
        let mut buffer = vec![0_u64; DIRECTORY_BUFFER_WORDS];
        let mut restart_scan = 1_u8;
        loop {
            let mut status_block = IoStatusBlock {
                status: 0,
                information: 0,
            };
            // SAFETY: directory 是同步目录句柄，buffer 和状态结构在调用期间保持有效。
            let status = unsafe {
                NtQueryDirectoryFile(
                    directory,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut status_block,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(buffer.as_slice()) as u32,
                    FILE_INFORMATION_CLASS_ID_BOTH_DIRECTORY,
                    0,
                    ptr::null_mut(),
                    restart_scan,
                )
            };
            restart_scan = 0;
            let status_code = status as u32;
            if status_code == STATUS_NO_MORE_FILES {
                break;
            }
            if status < 0 && status_code != STATUS_BUFFER_OVERFLOW {
                return Err(nt_error(status));
            }
            let returned = status_block.information;
            if returned == 0 {
                if status_code == STATUS_BUFFER_OVERFLOW {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows 目录枚举返回空的溢出缓冲区",
                    ));
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows 目录枚举返回空结果",
                ));
            }
            if returned > size_of_val(buffer.as_slice()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows 目录枚举长度超出缓冲区",
                ));
            }
            parse_directory_entries(&buffer, returned, &mut entries)?;
        }
        Ok(entries)
    }

    fn parse_directory_entries(
        buffer: &[u64],
        length: usize,
        entries: &mut Vec<DirectoryEntry>,
    ) -> io::Result<()> {
        let bytes = unsafe {
            // SAFETY: buffer 的元素对齐且长度覆盖系统报告的返回字节数。
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size_of_val(buffer))
        };
        let name_offset = std::mem::offset_of!(FileIdBothDirectoryInformation, _file_name);
        let mut offset = 0_usize;
        loop {
            if !offset.is_multiple_of(align_of::<FileIdBothDirectoryInformation>())
                || offset > length
                || length - offset < name_offset
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows 目录枚举项布局无效",
                ));
            }
            let header = unsafe {
                // SAFETY: 上面的边界和对齐检查覆盖完整固定头部。
                &*(bytes
                    .as_ptr()
                    .add(offset)
                    .cast::<FileIdBothDirectoryInformation>())
            };
            let next_offset = header.next_entry_offset as usize;
            let entry_length = if next_offset == 0 {
                length - offset
            } else {
                if !next_offset.is_multiple_of(align_of::<FileIdBothDirectoryInformation>())
                    || next_offset < name_offset
                    || next_offset >= length - offset
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows 目录枚举项链损坏",
                    ));
                }
                next_offset
            };
            let name_length = header.file_name_length as usize;
            if !name_length.is_multiple_of(2) || name_length > entry_length - name_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows 目录项名称长度无效",
                ));
            }
            let name = unsafe {
                // SAFETY: 文件名位于当前枚举项边界内，长度来自已校验的系统字段。
                let name_ptr = bytes.as_ptr().add(offset + name_offset).cast::<u16>();
                OsString::from_wide(std::slice::from_raw_parts(
                    name_ptr,
                    name_length / size_of::<u16>(),
                ))
            };
            if name != OsStr::new(".") && name != OsStr::new("..") {
                let _ = encode_component(&name)?;
                if header.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Windows 目录项不能是 reparse point",
                    ));
                }
                entries.push(DirectoryEntry {
                    name,
                    file_id: header.file_id,
                    attributes: header.file_attributes,
                });
            }
            if next_offset == 0 {
                break;
            }
            offset += next_offset;
        }
        Ok(())
    }

    fn open_validated_entry(
        parent: Handle,
        entry: &DirectoryEntry,
        share_delete: bool,
        delete_access: bool,
        require_single_link: bool,
    ) -> io::Result<File> {
        if entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows 目录项不能是 reparse point",
            ));
        }
        let kind = if entry.is_directory() {
            EntryKind::Directory
        } else {
            EntryKind::NonDirectory
        };
        let file = open_file_at_handle(parent, &entry.name, kind, share_delete, delete_access)?;
        if file_internal_id(&file)? != entry.file_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows 目录项身份在打开期间发生变化",
            ));
        }
        if !entry.is_directory() && require_single_link {
            validate_single_link_regular_file(&file)?;
        }
        Ok(file)
    }

    fn find_directory_entry(parent: Handle, name: &OsStr) -> io::Result<DirectoryEntry> {
        query_directory_entries(parent)?
            .into_iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Windows 目录项不存在"))
    }

    fn reject_existing_entry(parent: Handle, name: &OsStr) -> io::Result<()> {
        match open_file_at_handle(parent, name, EntryKind::Any, false, false) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Windows 目录发布目标已存在",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn list_directory(path: &Path) -> io::Result<Vec<OsString>> {
        let directory = open_directory_chain(path, false, false)?;
        let entries = query_directory_entries(directory.handle.as_raw_handle())?;
        let mut names = Vec::with_capacity(entries.len());
        for entry in entries {
            let _file =
                open_validated_entry(directory.handle.as_raw_handle(), &entry, true, false, true)?;
            names.push(entry.name);
        }
        names.sort_unstable();
        if names.windows(2).any(|window| window[0] == window[1]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows 目录枚举返回重复名称",
            ));
        }
        Ok(names)
    }

    struct RemovalNode {
        file: File,
        directory: bool,
        children: Vec<RemovalNode>,
    }

    fn build_removal_node(parent: Handle, entry: &DirectoryEntry) -> io::Result<RemovalNode> {
        let file = open_validated_entry(parent, entry, false, true, true)?;
        let directory = entry.is_directory();
        let children = if directory {
            let children = query_directory_entries(file.as_raw_handle())?;
            children
                .iter()
                .map(|child| build_removal_node(file.as_raw_handle(), child))
                .collect::<io::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        Ok(RemovalNode {
            file,
            directory,
            children,
        })
    }

    fn reject_nonempty_directory(directory: &File) -> io::Result<()> {
        let entries = query_directory_entries(directory.as_raw_handle())?;
        if entries.is_empty() {
            return Ok(());
        }
        for entry in &entries {
            let _ = open_validated_entry(directory.as_raw_handle(), entry, false, true, true)?;
        }
        Err(io::Error::other("Windows 目录在删除期间出现新的目录项"))
    }

    /// 递归提交删除；Windows 没有跨文件事务，因此错误时明确标记可能已部分提交。
    fn delete_removal_node(node: RemovalNode) -> io::Result<()> {
        let mut committed = false;
        let result = delete_removal_node_inner(node, &mut committed);
        if let Err(error) = result {
            if committed {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Windows 递归删除已部分提交，无法回滚: {error}"),
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    fn delete_removal_node_inner(node: RemovalNode, committed: &mut bool) -> io::Result<()> {
        for child in node.children {
            delete_removal_node_inner(child, committed)?;
        }
        if node.directory {
            reject_nonempty_directory(&node.file)?;
        }
        mark_delete_on_close(&node.file)?;
        *committed = true;
        Ok(())
    }

    pub(super) fn remove_directory(path: &Path) -> io::Result<()> {
        validate_absolute_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "待删除目录缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "待删除目录缺少最终名称"))?;
        let parent = open_directory_chain_with_sharing(parent_path, false, false, false)?;
        let entry = find_directory_entry(parent.handle.as_raw_handle(), name)?;
        if !entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Windows 删除目标必须是普通目录",
            ));
        }
        let root = build_removal_node(parent.handle.as_raw_handle(), &entry)?;
        delete_removal_node(root)
    }

    pub(super) fn rename_directory(path: &Path, destination: &Path) -> io::Result<()> {
        validate_absolute_path(path)?;
        validate_absolute_path(destination)?;
        let source_parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "源目录缺少父目录"))?;
        let destination_parent_path = destination
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "目标目录缺少父目录"))?;
        let source_name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "源目录缺少最终名称"))?;
        let destination_name = destination
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "目标目录缺少最终名称"))?;
        let source_parent =
            open_directory_chain_with_sharing(source_parent_path, false, false, false)?;
        let destination_parent =
            open_directory_chain_with_sharing(destination_parent_path, false, false, false)?;
        if file_id(&source_parent.handle)? != file_id(&destination_parent.handle)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 目录 rename 必须位于同一父目录",
            ));
        }
        let source_entry = find_directory_entry(source_parent.handle.as_raw_handle(), source_name)?;
        if !source_entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Windows rename 源必须是普通目录",
            ));
        }
        let source = open_validated_entry(
            source_parent.handle.as_raw_handle(),
            &source_entry,
            false,
            true,
            false,
        )?;
        reject_existing_entry(destination_parent.handle.as_raw_handle(), destination_name)?;
        let mut rename = rename_info_buffer(
            destination_parent.handle.as_raw_handle(),
            destination_name,
            false,
        )?;
        let mut info = IoStatusBlock {
            status: 0,
            information: 0,
        };
        // SAFETY: rename 缓冲区在调用期间保持可写，源句柄与 RootDirectory 均有效。
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle(),
                &mut info,
                rename.as_mut_ptr().cast(),
                rename.len() as u32,
                FILE_INFORMATION_CLASS_RENAME,
            )
        };
        if status < 0 {
            return Err(nt_error(status));
        }
        // SAFETY: 目标父目录是本模块打开的同步目录句柄。
        if unsafe { FlushFileBuffers(destination_parent.handle.as_raw_handle()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        let directory = open_directory_chain(path, false, false)?;
        // SAFETY: directory 由逐级 no-reparse 打开并完成磁盘/目录校验。
        if unsafe { FlushFileBuffers(directory.handle.as_raw_handle()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn read_regular_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        validate_absolute_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "普通文件缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "普通文件缺少最终名称"))?;
        let parent = open_directory_chain(parent_path, false, false)?;
        let file = open_file_at(&parent, name, false, false, false, false)?;
        validate_single_link_regular_file(&file)?;
        let mut file = file;
        read_bounded(&mut file, max_bytes)
    }

    pub(super) fn ensure_private_directory(path: &Path) -> io::Result<()> {
        let _ = open_directory_chain(path, true, true)?;
        Ok(())
    }

    pub(super) fn create_private_directory(path: &Path) -> io::Result<()> {
        validate_absolute_path(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "私有目录缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "私有目录缺少最终名称"))?;
        let parent = open_directory_chain(parent, false, false)?;
        let (_, directory) = open_file_at_with_state(&parent, name, true, true, false, true)?;
        set_owner_only_acl(&directory)?;
        verify_owner_only_acl(&directory)
    }

    pub(super) fn verify_directory(path: &Path) -> io::Result<()> {
        let _ = open_directory_chain(path, false, false)?;
        Ok(())
    }

    pub(super) fn verify_private_directory(path: &Path) -> io::Result<()> {
        let _ = open_directory_chain(path, false, true)?;
        Ok(())
    }

    pub(super) fn open_or_create_private_lock(path: &Path) -> io::Result<File> {
        validate_absolute_path(path)?;
        let home = open_directory_chain(path, false, true)?;
        open_or_create_private_lock_at(&home)
    }

    pub(super) fn open_or_create_private_lock_at(home: &SecureDirectory) -> io::Result<File> {
        // 锁文件禁止 delete sharing，避免其它句柄在 sidecar 生命周期内删除或改名它。
        let (created, file) = open_file_at_with_options(
            home.handle.as_raw_handle(),
            OsStr::new(HOME_LOCK_FILENAME),
            true,
            EntryKind::NonDirectory,
            true,
            false,
            false,
            false,
        )?;
        if created {
            set_owner_only_acl(&file)?;
        }
        verify_private_file(&file)?;
        Ok(file)
    }

    fn open_private_file_path(path: &Path) -> io::Result<File> {
        validate_absolute_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "私有文件缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "私有文件缺少最终名称"))?;
        let parent = open_directory_chain(parent_path, false, true)?;
        let file = open_file_at(&parent, name, false, false, false, false)?;
        verify_private_file(&file)?;
        Ok(file)
    }

    pub(super) fn read_private_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut file = open_private_file_path(path)?;
        read_bounded(&mut file, max_bytes)
    }

    pub(super) fn read_private_file_at(
        parent: &SecureDirectory,
        name: &OsStr,
        max_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        let file = open_file_at(parent, name, false, false, false, false)?;
        verify_private_file(&file)?;
        let mut file = file;
        read_bounded(&mut file, max_bytes)
    }

    fn read_bounded(file: &mut File, max_bytes: usize) -> io::Result<Vec<u8>> {
        let max_plus_one = max_bytes.saturating_add(1);
        let mut bytes = Vec::with_capacity(max_plus_one.min(64 * 1024));
        file.take(max_plus_one as u64).read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows 私有文件超过读取上限",
            ));
        }
        Ok(bytes)
    }

    pub(super) fn open_or_create_private_append(path: &Path) -> io::Result<File> {
        validate_absolute_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "日志文件缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "日志文件缺少最终名称"))?;
        // 产品日志目录由 Tauri 管理，允许其继承 ACL；只保护最终 sidecar 日志文件。
        let parent = open_directory_chain(parent_path, true, false)?;
        let (created, mut file) = open_file_at_with_state(&parent, name, true, false, true, false)?;
        if created {
            set_owner_only_acl(&file)?;
        }
        verify_private_file(&file)?;
        file.seek(SeekFrom::End(0))?;
        Ok(file)
    }

    pub(super) fn path_entry_exists(path: &Path) -> io::Result<bool> {
        validate_absolute_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "路径缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "路径缺少最终名称"))?;
        let parent = open_directory_chain(parent_path, false, false)?;
        path_entry_exists_at(&parent, name)
    }

    pub(super) fn path_entry_exists_at(parent: &SecureDirectory, name: &OsStr) -> io::Result<bool> {
        // 直接按句柄相对方式打开 Any 类型，让 Windows 对目录项执行原生大小写不敏感匹配。
        let _ = encode_component(name)?;
        match open_file_at_handle(
            parent.handle.as_raw_handle(),
            name,
            EntryKind::Any,
            true,
            false,
        ) {
            Ok(_file) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    struct TemporaryFile {
        file: File,
        committed: bool,
    }

    impl Drop for TemporaryFile {
        fn drop(&mut self) {
            if !self.committed {
                let _ = mark_delete_on_close(&self.file);
            }
        }
    }

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_name() -> OsString {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        OsString::from(format!(
            ".efflab-agent-tmp-{}-{timestamp:x}-{counter:x}.tmp",
            std::process::id()
        ))
    }

    fn create_unique_temp_file(parent: &SecureDirectory) -> io::Result<TemporaryFile> {
        for _ in 0..128 {
            let name = unique_name();
            match open_file_at_with_state(parent, &name, true, false, false, true) {
                Ok((true, file)) => {
                    set_owner_only_acl(&file)?;
                    verify_private_file(&file)?;
                    return Ok(TemporaryFile {
                        file,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
                Ok((false, _)) => continue,
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Windows 私有临时文件名称分配失败",
        ))
    }

    fn reject_existing_destination(parent: &SecureDirectory, name: &OsStr) -> io::Result<()> {
        match open_file_at(parent, name, false, false, false, false) {
            Ok(file) => verify_private_file(&file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn rename_info_buffer(
        root: Handle,
        destination: &OsStr,
        replace_if_exists: bool,
    ) -> io::Result<Vec<u8>> {
        let wide = encode_component(destination)?;
        let name_bytes = ((wide.len() - 1) * 2) as u32;
        let handle_size = size_of::<Handle>();
        let root_offset = if handle_size == 8 { 8 } else { 4 };
        let length_offset = root_offset + handle_size;
        let name_offset = length_offset + size_of::<u32>();
        let mut buffer = vec![0_u8; name_offset + name_bytes as usize];
        buffer[0] = u8::from(replace_if_exists);
        buffer[root_offset..root_offset + handle_size]
            .copy_from_slice(&(root as usize).to_le_bytes()[..handle_size]);
        buffer[length_offset..length_offset + size_of::<u32>()]
            .copy_from_slice(&name_bytes.to_le_bytes());
        for (index, unit) in wide[..wide.len() - 1].iter().enumerate() {
            let offset = name_offset + index * 2;
            buffer[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        Ok(buffer)
    }

    fn mark_delete_on_close(file: &File) -> io::Result<()> {
        let mut info = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut disposition = [1_u8];
        // SAFETY: 文件句柄以 DELETE 权限打开，缓冲区符合 FILE_DISPOSITION_INFORMATION。
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut info,
                disposition.as_mut_ptr().cast(),
                disposition.len() as u32,
                FILE_INFORMATION_CLASS_DISPOSITION,
            )
        };
        if status < 0 {
            Err(nt_error(status))
        } else {
            Ok(())
        }
    }

    fn atomic_replace_relative(
        parent: &SecureDirectory,
        temporary: &mut TemporaryFile,
        destination: &OsStr,
    ) -> io::Result<()> {
        let mut rename = rename_info_buffer(parent.handle.as_raw_handle(), destination, true)?;
        let mut info = IoStatusBlock {
            status: 0,
            information: 0,
        };
        // SAFETY: rename 缓冲区在调用期间保持可写，源句柄与 RootDirectory 均有效。
        let status = unsafe {
            NtSetInformationFile(
                temporary.file.as_raw_handle(),
                &mut info,
                rename.as_mut_ptr().cast(),
                rename.len() as u32,
                FILE_INFORMATION_CLASS_RENAME,
            )
        };
        if status < 0 {
            return Err(nt_error(status));
        }
        // rename 成功后临时句柄已经指向正式目标；此刻即视为已发布，避免后续 flush
        // 失败时 Drop 把刚发布的新目标错误标记为 delete-pending。
        temporary.committed = true;
        // SAFETY: parent 是本模块打开的目录句柄，刷新其目录元数据完成提交屏障。
        if unsafe { FlushFileBuffers(parent.handle.as_raw_handle()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn atomic_write_private(path: &Path, content: &[u8]) -> io::Result<()> {
        validate_absolute_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "原子写目标缺少父目录"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "原子写目标缺少最终名称"))?;
        let parent = open_directory_chain(parent_path, false, true)?;
        reject_existing_destination(&parent, name)?;
        let mut temporary = create_unique_temp_file(&parent)?;
        temporary.file.write_all(content)?;
        temporary.file.sync_all()?;
        verify_private_file(&temporary.file)?;
        atomic_replace_relative(&parent, &mut temporary, name)
    }

    /// 在已钉住根目录下逐级创建或验证私有目录。
    pub(super) fn ensure_private_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        let _ = open_directory_chain_relative(root, relative, true, true, true)?;
        Ok(())
    }

    /// 在已钉住根目录下独占创建私有目录。
    pub(super) fn create_private_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        let (parent_components, name) = split_relative(relative)?;
        let parent = open_directory_components(root, &parent_components, false, true, true)?;
        let (_, directory) = open_file_at_with_state(&parent, &name, true, true, false, true)?;
        set_owner_only_acl(&directory)?;
        verify_owner_only_acl(&directory)
    }

    /// 在已钉住根目录下验证普通目录。
    pub(super) fn verify_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        let _ = open_directory_chain_relative(root, relative, false, false, true)?;
        Ok(())
    }

    /// 在已钉住根目录下验证 owner-only 私有目录。
    pub(super) fn verify_private_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        let _ = open_directory_chain_relative(root, relative, false, true, true)?;
        Ok(())
    }

    /// 在已钉住根目录下枚举并校验普通直接子项。
    pub(super) fn list_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<Vec<OsString>> {
        let directory = open_directory_chain_relative(root, relative, false, false, true)?;
        let entries = query_directory_entries(directory.handle.as_raw_handle())?;
        let mut names = Vec::with_capacity(entries.len());
        for entry in entries {
            let _file =
                open_validated_entry(directory.handle.as_raw_handle(), &entry, true, false, true)?;
            names.push(entry.name);
        }
        names.sort_unstable();
        if names.windows(2).any(|window| window[0] == window[1]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows 目录枚举返回重复名称",
            ));
        }
        Ok(names)
    }

    /// 在已钉住根目录下递归删除普通目录树，不跟随 reparse point。
    fn remove_directory_relative_impl(
        root: &SecureDirectory,
        relative: &Path,
        private_parent: bool,
    ) -> io::Result<()> {
        let (parent_components, name) = split_relative(relative)?;
        let parent =
            open_directory_components(root, &parent_components, false, private_parent, false)?;
        let entry = find_directory_entry(parent.handle.as_raw_handle(), &name)?;
        if !entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Windows 删除目标必须是普通目录",
            ));
        }
        let node = build_removal_node(parent.handle.as_raw_handle(), &entry)?;
        delete_removal_node(node)
    }

    pub(super) fn remove_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        remove_directory_relative_impl(root, relative, false)
    }

    /// 在已钉住根目录下递归删除私有目录树，逐级验证私有父目录。
    pub(super) fn remove_private_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        remove_directory_relative_impl(root, relative, true)
    }

    /// 在已钉住根目录下执行同父目录原子目录发布。
    fn rename_directory_relative_impl(
        root: &SecureDirectory,
        source: &Path,
        destination: &Path,
        private_parent: bool,
    ) -> io::Result<()> {
        let (source_components, source_name) = split_relative(source)?;
        let (destination_components, destination_name) = split_relative(destination)?;
        let source_parent =
            open_directory_components(root, &source_components, false, private_parent, false)?;
        let destination_parent =
            open_directory_components(root, &destination_components, false, private_parent, false)?;
        if file_id(&source_parent.handle)? != file_id(&destination_parent.handle)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows 相对目录 rename 必须位于同一父目录",
            ));
        }
        let source_entry =
            find_directory_entry(source_parent.handle.as_raw_handle(), &source_name)?;
        if !source_entry.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Windows rename 源必须是普通目录",
            ));
        }
        let source_handle = open_validated_entry(
            source_parent.handle.as_raw_handle(),
            &source_entry,
            false,
            true,
            false,
        )?;
        reject_existing_entry(destination_parent.handle.as_raw_handle(), &destination_name)?;
        let mut rename = rename_info_buffer(
            destination_parent.handle.as_raw_handle(),
            &destination_name,
            false,
        )?;
        let mut info = IoStatusBlock {
            status: 0,
            information: 0,
        };
        // SAFETY: rename 缓冲区在调用期间保持可写，源句柄与 RootDirectory 均有效。
        let status = unsafe {
            NtSetInformationFile(
                source_handle.as_raw_handle(),
                &mut info,
                rename.as_mut_ptr().cast(),
                rename.len() as u32,
                FILE_INFORMATION_CLASS_RENAME,
            )
        };
        if status < 0 {
            return Err(nt_error(status));
        }
        // SAFETY: 目标父目录是本模块打开的同步目录句柄。
        if unsafe { FlushFileBuffers(destination_parent.handle.as_raw_handle()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn rename_directory_relative(
        root: &SecureDirectory,
        source: &Path,
        destination: &Path,
    ) -> io::Result<()> {
        rename_directory_relative_impl(root, source, destination, false)
    }

    /// 在已钉住根目录下发布私有目录，逐级验证私有父目录。
    pub(super) fn rename_private_directory_relative(
        root: &SecureDirectory,
        source: &Path,
        destination: &Path,
    ) -> io::Result<()> {
        rename_directory_relative_impl(root, source, destination, true)
    }

    /// 刷新已钉住根目录下的目录元数据。
    fn sync_directory_relative_impl(
        root: &SecureDirectory,
        relative: &Path,
        private_directory: bool,
    ) -> io::Result<()> {
        let directory =
            open_directory_chain_relative(root, relative, false, private_directory, true)?;
        // SAFETY: directory 由已钉住根目录逐级 no-reparse 打开。
        if unsafe { FlushFileBuffers(directory.handle.as_raw_handle()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn sync_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        sync_directory_relative_impl(root, relative, false)
    }

    /// 刷新已钉住根目录下的私有目录元数据。
    pub(super) fn sync_private_directory_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<()> {
        sync_directory_relative_impl(root, relative, true)
    }

    /// 从已钉住根目录读取普通单硬链接文件。
    pub(super) fn read_regular_file_relative(
        root: &SecureDirectory,
        relative: &Path,
        max_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        let (parent_components, name) = split_relative(relative)?;
        let parent = open_directory_components(root, &parent_components, false, false, true)?;
        let file = open_file_at(&parent, &name, false, false, false, false)?;
        validate_single_link_regular_file(&file)?;
        let mut file = file;
        read_bounded(&mut file, max_bytes)
    }

    /// 从已钉住根目录读取 owner-only 私有文件。
    pub(super) fn read_private_file_relative(
        root: &SecureDirectory,
        relative: &Path,
        max_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        let (parent_components, name) = split_relative(relative)?;
        let parent = open_directory_components(root, &parent_components, false, true, true)?;
        let file = open_file_at(&parent, &name, false, false, false, false)?;
        verify_private_file(&file)?;
        let mut file = file;
        read_bounded(&mut file, max_bytes)
    }

    /// 检查已钉住根目录下的相对目录项是否存在。
    fn path_entry_exists_relative_impl(
        root: &SecureDirectory,
        relative: &Path,
        private_parent: bool,
    ) -> io::Result<bool> {
        let (parent_components, name) = split_relative(relative)?;
        let parent =
            open_directory_components(root, &parent_components, false, private_parent, true)?;
        path_entry_exists_at(&parent, &name)
    }

    pub(super) fn path_entry_exists_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<bool> {
        path_entry_exists_relative_impl(root, relative, false)
    }

    /// 在已钉住根目录下检查私有相对目录项是否存在。
    pub(super) fn path_entry_exists_private_relative(
        root: &SecureDirectory,
        relative: &Path,
    ) -> io::Result<bool> {
        path_entry_exists_relative_impl(root, relative, true)
    }

    /// 在已钉住根目录下原子替换 owner-only 私有文件。
    pub(super) fn atomic_write_private_relative(
        root: &SecureDirectory,
        relative: &Path,
        content: &[u8],
    ) -> io::Result<()> {
        let (parent_components, name) = split_relative(relative)?;
        let parent = open_directory_components(root, &parent_components, false, true, true)?;
        reject_existing_destination(&parent, &name)?;
        let mut temporary = create_unique_temp_file(&parent)?;
        temporary.file.write_all(content)?;
        temporary.file.sync_all()?;
        verify_private_file(&temporary.file)?;
        atomic_replace_relative(&parent, &mut temporary, &name)
    }

    pub(super) fn set_current_dir_secure(path: &Path) -> io::Result<()> {
        let directory = open_directory_chain(path, false, false)?;
        set_current_dir_from_handle(&directory)
    }

    pub(super) fn set_current_dir_from_handle(directory: &SecureDirectory) -> io::Result<()> {
        let expected = file_id(&directory.handle)?;
        let final_path = final_path_from_handle(directory.handle.as_raw_handle())?;
        let reopened = open_directory_chain(&final_path, false, false)?;
        if expected != file_id(&reopened.handle)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows session cwd 的目录身份已变化",
            ));
        }
        let wide = final_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: wide 是有效的 NUL 终止 UTF-16 路径，目录身份已用句柄复核。
        if unsafe { SetCurrentDirectoryW(wide.as_ptr()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    fn final_path_from_handle(handle: Handle) -> io::Result<PathBuf> {
        // SAFETY: 第一次调用只查询长度。
        let needed = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, 0) };
        if needed == 0 {
            return Err(last_error());
        }
        let mut buffer = vec![0_u16; needed as usize + 1];
        // SAFETY: buffer 按系统返回长度分配，句柄有效。
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        };
        if written == 0 || (written as usize) >= buffer.len() {
            return Err(last_error());
        }
        buffer.truncate(written as usize);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    pub(super) fn file_id(file: &File) -> io::Result<[u8; 24]> {
        let mut info = FileIdInfo {
            volume_serial_number: 0,
            file_id: [0; 16],
        };
        // SAFETY: info 是可写结构，句柄有效。
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_INFO_BY_HANDLE_CLASS_ID,
                (&mut info as *mut FileIdInfo).cast(),
                size_of::<FileIdInfo>() as u32,
            )
        } == 0
        {
            return Err(last_error());
        }
        let mut id = [0_u8; 24];
        id[..8].copy_from_slice(&info.volume_serial_number.to_le_bytes());
        id[8..].copy_from_slice(&info.file_id);
        Ok(id)
    }

    pub(super) fn canonicalize_existing_path_prefix(path: &Path) -> io::Result<PathBuf> {
        validate_absolute_path(path)?;
        let mut existing = path.to_path_buf();
        let mut missing = Vec::<OsString>::new();
        loop {
            match std::fs::symlink_metadata(&existing) {
                Ok(_) => {
                    let _ = open_directory_chain(&existing, false, false)?;
                    let mut result = std::fs::canonicalize(&existing)?;
                    for component in missing.iter().rev() {
                        result.push(component);
                    }
                    return Ok(result);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let component = existing.file_name().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "路径没有可回溯的现有前缀")
                    })?;
                    missing.push(component.to_os_string());
                    if !existing.pop() {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::Path;

    fn test_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("efflab-agent-platform-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("创建 Windows 平台测试目录")
    }

    fn private_path(root: &Path, name: &str) -> std::path::PathBuf {
        root.join(name)
    }

    fn create_junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[test]
    fn list_directory_returns_sorted_direct_entries() {
        let temporary = test_tempdir();
        let directory = private_path(temporary.path(), "list");
        ensure_private_directory(&directory).expect("创建列表目录");
        fs::write(directory.join("zeta"), b"z").expect("创建 zeta");
        fs::create_dir(directory.join("nested")).expect("创建 nested");
        fs::write(directory.join("alpha"), b"a").expect("创建 alpha");

        assert_eq!(
            list_directory(&directory).expect("枚举目录"),
            vec![
                OsString::from("alpha"),
                OsString::from("nested"),
                OsString::from("zeta"),
            ]
        );
    }

    #[test]
    fn list_directory_fails_closed_on_reparse_entry() {
        let temporary = test_tempdir();
        let outside = private_path(temporary.path(), "outside");
        let directory = private_path(temporary.path(), "list");
        fs::create_dir(&outside).expect("创建目录外目标");
        ensure_private_directory(&directory).expect("创建列表目录");
        if !create_junction(&directory.join("linked"), &outside) {
            return;
        }

        assert!(list_directory(&directory).is_err());
    }

    #[test]
    fn remove_directory_deletes_only_verified_tree() {
        let temporary = test_tempdir();
        let directory = private_path(temporary.path(), "remove");
        ensure_private_directory(&directory).expect("创建删除目录");
        fs::create_dir(directory.join("nested")).expect("创建嵌套目录");
        fs::write(directory.join("nested").join("record"), b"record").expect("创建普通文件");

        remove_directory(&directory).expect("删除普通目录树");
        assert!(!directory.exists());
    }

    #[test]
    fn remove_directory_rejects_reparse_without_touching_tree() {
        let temporary = test_tempdir();
        let outside = private_path(temporary.path(), "outside");
        let directory = private_path(temporary.path(), "remove");
        fs::create_dir(&outside).expect("创建目录外目标");
        fs::write(outside.join("sentinel"), b"sentinel").expect("创建目录外哨兵");
        ensure_private_directory(&directory).expect("创建删除目录");
        fs::write(directory.join("ordinary"), b"ordinary").expect("创建普通文件");
        if !create_junction(&directory.join("linked"), &outside) {
            return;
        }

        assert!(remove_directory(&directory).is_err());
        assert!(directory.join("ordinary").exists());
        assert!(outside.join("sentinel").exists());
    }

    #[test]
    fn rename_directory_publishes_within_same_parent_only() {
        let temporary = test_tempdir();
        let parent = private_path(temporary.path(), "parent");
        let source = parent.join("temporary");
        let destination = parent.join("published");
        ensure_private_directory(&parent).expect("创建发布父目录");
        ensure_private_directory(&source).expect("创建临时目录");
        fs::write(source.join("record"), b"record").expect("创建发布内容");

        rename_directory(&source, &destination).expect("发布临时目录");
        assert!(!source.exists());
        assert!(destination.join("record").exists());
    }

    #[test]
    fn rename_directory_rejects_existing_or_cross_parent_destination() {
        let temporary = test_tempdir();
        let parent = private_path(temporary.path(), "parent");
        let other_parent = private_path(temporary.path(), "other");
        let source = parent.join("temporary");
        ensure_private_directory(&parent).expect("创建发布父目录");
        ensure_private_directory(&other_parent).expect("创建另一父目录");
        ensure_private_directory(&source).expect("创建临时目录");
        ensure_private_directory(&parent.join("existing")).expect("创建已存在目标");

        assert!(rename_directory(&source, &parent.join("existing")).is_err());
        assert!(source.exists());
        assert!(rename_directory(&source, &other_parent.join("published")).is_err());
        assert!(source.exists());
    }

    #[test]
    fn sync_directory_flushes_verified_directory() {
        let temporary = test_tempdir();
        let directory = private_path(temporary.path(), "sync");
        ensure_private_directory(&directory).expect("创建同步目录");

        sync_directory(&directory).expect("刷新目录句柄");
    }

    #[test]
    fn read_regular_file_is_bounded_and_rejects_hard_links() {
        let temporary = test_tempdir();
        let directory = private_path(temporary.path(), "read");
        let file = directory.join("legacy");
        fs::create_dir(&directory).expect("创建 legacy 读取目录");
        fs::write(&file, b"legacy-content").expect("创建 legacy 文件");

        assert_eq!(
            read_regular_file(&file, 64).expect("读取普通文件"),
            b"legacy-content"
        );
        assert!(read_regular_file(&file, 4).is_err());

        let hard_link = directory.join("legacy-link");
        if fs::hard_link(&file, &hard_link).is_ok() {
            assert!(read_regular_file(&file, 64).is_err());
        }
    }

    #[test]
    fn ensure_private_directory_can_walk_user_profile_temp() {
        // 简体中文注释：产品 sqlite / 模型目录位于用户 AppData。这里用同一棵
        // 用户配置文件树验证已有祖先只读打开，避免只在 D: 仓库临时目录里假绿。
        let path = std::env::temp_dir()
            .join("efflab-agent-platform-profile-walk")
            .join("home");
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
        ensure_private_directory(&path).unwrap_or_else(|error| {
            panic!("必须能在用户 AppData Temp 下创建私有目录，错误={error:?}")
        });
        verify_private_directory(&path).expect("校验用户配置文件树下的私有目录");
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn private_directory_and_atomic_file_are_owner_only() {
        let temporary = test_tempdir();
        let home = private_path(temporary.path(), "home");
        ensure_private_directory(&home)
            .unwrap_or_else(|error| panic!("创建私有 home 失败，路径={home:?}，错误={error:?}"));
        verify_private_directory(&home).expect("验证私有 home");
        let file = home.join("runtime-config.v1.toml");
        atomic_write_private(&file, b"schema_version = 1\n").expect("原子写私有文件");
        assert_eq!(
            read_private_file(&file, 1024).expect("读取私有文件"),
            b"schema_version = 1\n"
        );
    }

    #[test]
    fn startup_handles_pin_home_and_cwd() {
        let temporary = test_tempdir();
        let home = private_path(temporary.path(), "home");
        let cwd = private_path(temporary.path(), "cwd");
        ensure_private_directory(&home).expect("创建私有 home");
        ensure_private_directory(&cwd).expect("创建私有 cwd");
        let handles = open_startup_handles(&home, &cwd).expect("打开启动句柄");
        let lock = handles
            .open_or_create_private_lock()
            .expect("创建 home lock");
        assert!(lock.metadata().expect("读取 lock").is_file());
        assert!(
            !handles
                .path_entry_exists(OsStr::new("missing"))
                .expect("检查缺失目录项")
        );
    }

    #[test]
    fn pinned_relative_storage_stays_on_original_home_after_replacement() {
        let temporary = test_tempdir();
        let home = temporary.path().join("home");
        let cwd = temporary.path().join("cwd");
        ensure_private_directory(&home).expect("创建 pinned home");
        ensure_private_directory(&cwd).expect("创建 pinned cwd");
        let handles = open_startup_handles(&home, &cwd).expect("打开 pinned startup handles");
        let root = handles.home_directory().expect("克隆 pinned home");

        let moved_home = temporary.path().join("moved-home");
        fs::rename(&home, &moved_home).expect("移动 pinned home");
        ensure_private_directory(&home).expect("创建替换 home");

        ensure_private_directory_relative(&root, Path::new("efflab-sessions/v1"))
            .expect("创建 pinned v1 根");
        create_private_directory_relative(&root, Path::new("efflab-sessions/v1/temporary"))
            .expect("创建临时 session 目录");
        atomic_write_private_relative(
            &root,
            Path::new("efflab-sessions/v1/temporary/records.jsonl"),
            b"pinned\n",
        )
        .expect("写入 pinned records");
        assert_eq!(
            read_private_file_relative(
                &root,
                Path::new("efflab-sessions/v1/temporary/records.jsonl"),
                64,
            )
            .expect("读取 pinned records"),
            b"pinned\n"
        );
        assert!(
            path_entry_exists_relative(&root, Path::new("efflab-sessions/v1/temporary"))
                .expect("检查 pinned session")
        );
        assert_eq!(
            list_directory_relative(&root, Path::new("efflab-sessions/v1"))
                .expect("枚举 pinned v1 根"),
            vec![OsString::from("temporary")]
        );

        create_private_directory_relative(&root, Path::new("efflab-sessions/v1/published-tmp"))
            .expect("创建发布临时目录");
        rename_directory_relative(
            &root,
            Path::new("efflab-sessions/v1/published-tmp"),
            Path::new("efflab-sessions/v1/published"),
        )
        .expect("相对发布目录");
        sync_directory_relative(&root, Path::new("efflab-sessions/v1")).expect("刷新 pinned v1 根");
        remove_directory_relative(&root, Path::new("efflab-sessions/v1/published"))
            .expect("删除 pinned 发布目录");

        assert!(
            moved_home
                .join("efflab-sessions")
                .join("v1")
                .join("temporary")
                .join("records.jsonl")
                .exists(),
            "相对操作必须写入原 home"
        );
        assert!(
            !home
                .join("efflab-sessions")
                .join("v1")
                .join("temporary")
                .exists(),
            "替换后的同名 home 不得收到相对操作"
        );
    }

    #[test]
    fn junction_destination_is_rejected_without_touching_target() {
        let temporary = test_tempdir();
        let outside = temporary.path().join("outside");
        let home = temporary.path().join("home");
        fs::create_dir(&outside).expect("创建目录外目标");
        ensure_private_directory(&home).expect("创建私有 home");
        let link = home.join("linked");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("调用 mklink");
        if !status.success() {
            return;
        }
        assert!(verify_directory(&link).is_err());
        assert!(!outside.join("runtime-config.v1.toml").exists());
    }

    #[test]
    fn file_id_is_stable_across_handle_reopen() {
        let temporary = test_tempdir();
        let home = temporary.path().join("home");
        ensure_private_directory(&home).expect("创建私有 home");
        let first = open_existing_private_directory(&home).expect("首次打开 home");
        let second = open_existing_private_directory(&home).expect("再次打开 home");
        assert_eq!(
            file_id(&first).expect("读取首个 FileId"),
            file_id(&second).expect("读取第二个 FileId")
        );
    }

    #[test]
    fn path_entry_exists_handles_files_and_directories() {
        let temporary = test_tempdir();
        let home = private_path(temporary.path(), "home");
        let nested = home.join("nested");
        let file = home.join("record");
        ensure_private_directory(&home).expect("创建存在性测试 home");
        ensure_private_directory(&nested).expect("创建存在性测试目录");
        fs::write(&file, b"record").expect("创建存在性测试文件");

        assert!(path_entry_exists(&home).expect("检查 home 目录存在性"));
        assert!(path_entry_exists(&nested).expect("检查嵌套目录存在性"));
        assert!(path_entry_exists(&file).expect("检查普通文件存在性"));
        assert!(!path_entry_exists(&home.join("missing")).expect("检查缺失目录项"));
    }

    #[test]
    fn path_entry_exists_matches_windows_case_insensitive_names() {
        let temporary = test_tempdir();
        let home = private_path(temporary.path(), "home");
        let file = home.join("Record");
        ensure_private_directory(&home).expect("创建大小写测试 home");
        fs::write(&file, b"record").expect("创建大小写测试文件");

        assert!(path_entry_exists(&home.join("record")).expect("Windows 名称匹配必须不区分大小写"));
    }

    #[test]
    fn private_relative_path_rejects_non_private_intermediate_directory() {
        let temporary = test_tempdir();
        let home = private_path(temporary.path(), "home");
        ensure_private_directory(&home).expect("创建私有 home");
        let root = open_existing_private_directory(&home).expect("打开私有 home");
        let ordinary = home.join("ordinary");
        fs::create_dir(&ordinary).expect("创建普通中间目录");

        let result = ensure_private_directory_relative(&root, Path::new("ordinary/nested"));

        assert!(result.is_err());
        assert!(!ordinary.join("nested").exists());
    }

    #[test]
    fn private_append_file_can_be_created_and_reopened() {
        let temporary = test_tempdir();
        let home = private_path(temporary.path(), "home");
        let log = home.join("nested").join("sidecar.log");
        ensure_private_directory(&home).expect("创建私有 home");

        {
            let mut file = open_or_create_private_append(&log).expect("首次创建私有追加文件");
            file.write_all(b"first\n").expect("写入首次日志");
        }
        {
            let mut file = open_or_create_private_append(&log).expect("再次打开私有追加文件");
            file.write_all(b"second\n").expect("追加第二条日志");
        }

        assert_eq!(
            read_private_file(&log, 1024).expect("读取追加日志"),
            b"first\nsecond\n"
        );
    }

    #[test]
    fn private_append_file_accepts_existing_public_log_directory() {
        let temporary = test_tempdir();
        let log_dir = private_path(temporary.path(), "logs");
        fs::create_dir(&log_dir).expect("创建公共日志目录");
        let log = log_dir.join("sidecar.log");

        let mut file = open_or_create_private_append(&log)
            .expect("公共日志目录的 ACL 不应阻止私有 sidecar 日志文件");
        file.write_all(b"public-parent\n").expect("写入日志");
        file.seek(SeekFrom::Start(0))
            .expect("定位 sidecar 日志开头");
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .expect("读取私有 sidecar 日志");

        assert_eq!(content, b"public-parent\n");
    }
}
