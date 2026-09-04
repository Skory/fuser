//! FUSE kernel interface.
//!
//! Types and definitions used for communication between the kernel driver and the userspace
//! part of a FUSE filesystem. Since the kernel driver may be installed independently, the ABI
//! interface is versioned and capabilities are exchanged during the initialization (mounting)
//! of a filesystem.
//!
//! macfuse (macOS): <https://github.com/macfuse/library/blob/master/include/fuse_kernel.h>
//! - supports ABI 7.8 in OSXFUSE 2.x
//! - supports ABI 7.19 since OSXFUSE 3.0.0
//!
//! libfuse (Linux/BSD): <https://github.com/libfuse/libfuse/blob/master/include/fuse_kernel.h>
//! - supports ABI 7.8 since FUSE 2.6.0
//! - supports ABI 7.12 since FUSE 2.8.0
//! - supports ABI 7.18 since FUSE 2.9.0
//! - supports ABI 7.19 since FUSE 2.9.1
//! - supports ABI 7.26 since FUSE 3.0.0
//!
//! FreeBSD kernel headers: <https://github.com/freebsd/freebsd-src/blob/main/sys/fs/fuse/fuse_kernel.h>
//!
//! Items without a version annotation are valid with ABI 7.8 and later

#![warn(missing_debug_implementations)]
#![allow(missing_docs)]

use num_enum::TryFromPrimitive;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::ll::flags::fattr_flags::FattrFlags;
use crate::ll::request::Version;

pub(crate) const FUSE_KERNEL_VERSION: u32 = 7;

pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = if cfg!(target_os = "macos") {
    // macfuse headers declared the latest version as 19.
    // In theory, it is supposed to quietly handle a newer version, but
    // we are not sure, and it may break if the release new version.
    // So let's declare protocol version 19 to be safe.
    19
} else {
    // 7.44 is what `FUSE_NOTIFY_INC_EPOCH` needs. Everything 7.41 through 7.43 added is a
    // capability the kernel only acts on once negotiated, and all three are refused in
    // `UNSUPPORTED_CAPABILITIES`, so declaring this adds no obligation beyond the
    // notification itself
    44
};

#[repr(C)]
#[derive(Debug, IntoBytes, Clone, Copy, KnownLayout, Immutable)]
pub(crate) struct fuse_attr {
    pub(crate) ino: u64,
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_atime
    pub(crate) atime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_mtime
    pub(crate) mtime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_ctime
    pub(crate) ctime: i64,
    #[cfg(target_os = "macos")]
    pub(crate) crtime: u64,
    pub(crate) atimensec: u32,
    pub(crate) mtimensec: u32,
    pub(crate) ctimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) crtimensec: u32,
    pub(crate) mode: u32,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rdev: u32,
    #[cfg(target_os = "macos")]
    pub(crate) flags: u32, // see chflags(2)
    pub(crate) blksize: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_kstatfs {
    pub(crate) blocks: u64,  // Total blocks (in units of frsize)
    pub(crate) bfree: u64,   // Free blocks
    pub(crate) bavail: u64,  // Free blocks for unprivileged users
    pub(crate) files: u64,   // Total inodes
    pub(crate) ffree: u64,   // Free inodes
    pub(crate) bsize: u32,   // Filesystem block size
    pub(crate) namelen: u32, // Maximum filename length
    pub(crate) frsize: u32,  // Fundamental file system block size
    pub(crate) padding: u32,
    pub(crate) spare: [u32; 6],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_file_lock {
    pub(crate) start: u64,
    pub(crate) end: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) typ: i32,
    pub(crate) pid: u32,
}

pub mod consts {
    // Lock flags
    pub const FUSE_LK_FLOCK: u32 = 1 << 0;

    // IOCTL constant
    pub const FUSE_IOCTL_MAX_IOV: u32 = 256; // maximum of in_iovecs + out_iovecs

    // The read buffer is required to be at least 8k, but may be much larger
    pub const FUSE_MIN_READ_BUFFER: usize = 8192;
}

#[repr(u32)]
#[derive(Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub(crate) enum fuse_opcode {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2, // no reply
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,
    FUSE_SYNCFS = 50,
    FUSE_TMPFILE = 51,
    FUSE_STATX = 52,

    #[cfg(target_os = "macos")]
    FUSE_SETVOLNAME = 61,
    #[cfg(target_os = "macos")]
    FUSE_GETXTIMES = 62,
    #[cfg(target_os = "macos")]
    FUSE_EXCHANGE = 63,

    CUSE_INIT = 4096,
}

#[repr(u32)]
#[derive(Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub(crate) enum fuse_notify_code {
    FUSE_POLL = 1,
    FUSE_NOTIFY_INVAL_INODE = 2,
    FUSE_NOTIFY_INVAL_ENTRY = 3,
    FUSE_NOTIFY_STORE = 4,
    FUSE_NOTIFY_RETRIEVE = 5,
    FUSE_NOTIFY_DELETE = 6,
    FUSE_NOTIFY_RESEND = 7,
    FUSE_NOTIFY_INC_EPOCH = 8,
}

/// ABI version that added `FUSE_NOTIFY_INC_EPOCH`. An older kernel has no case for the
/// code and answers the write with `EINVAL`
pub(crate) const FUSE_NOTIFY_INC_EPOCH_VERSION: Version = Version(7, 44);

/// ABI version that added `FUSE_STATX`. An older kernel never sends the opcode, and answers
/// `statx(2)` out of what `FUSE_GETATTR` gives it, so nothing outside the tests has to ask -
/// and only the Linux ones, since `statx(2)` is Linux's
#[cfg(all(test, target_os = "linux"))]
pub(crate) const FUSE_STATX_VERSION: Version = Version(7, 38);

/// A timestamp as `struct statx` carries one, which unlike `fuse_attr`'s pair of fields is a
/// signed second count with its own padding
#[repr(C)]
#[derive(Debug, Default, IntoBytes, Clone, Copy, KnownLayout, Immutable)]
pub(crate) struct fuse_sx_time {
    pub(crate) tv_sec: i64,
    pub(crate) tv_nsec: u32,
    pub(crate) __reserved: i32,
}

/// The `struct statx` payload, laid out as the kernel's `fuse_statx`. Every field the caller
/// did not ask for is still sent, and `mask` is what says which of them mean anything
#[repr(C)]
#[derive(Debug, Default, IntoBytes, Clone, Copy, KnownLayout, Immutable)]
pub(crate) struct fuse_statx {
    pub(crate) mask: u32,
    pub(crate) blksize: u32,
    pub(crate) attributes: u64,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u16,
    pub(crate) __spare0: [u16; 1],
    pub(crate) ino: u64,
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    pub(crate) attributes_mask: u64,
    pub(crate) atime: fuse_sx_time,
    pub(crate) btime: fuse_sx_time,
    pub(crate) ctime: fuse_sx_time,
    pub(crate) mtime: fuse_sx_time,
    pub(crate) rdev_major: u32,
    pub(crate) rdev_minor: u32,
    pub(crate) dev_major: u32,
    pub(crate) dev_minor: u32,
    pub(crate) __spare2: [u64; 14],
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_statx_in {
    pub(crate) getattr_flags: u32,
    pub(crate) reserved: u32,
    pub(crate) fh: u64,
    pub(crate) sx_flags: u32,
    pub(crate) sx_mask: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_statx_out {
    pub(crate) attr_valid: u64,
    pub(crate) attr_valid_nsec: u32,
    pub(crate) flags: u32,
    pub(crate) spare: [u64; 2],
    pub(crate) stat: fuse_statx,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_entry_out {
    pub(crate) nodeid: u64,
    pub(crate) generation: u64,
    pub(crate) entry_valid: u64,
    pub(crate) attr_valid: u64,
    pub(crate) entry_valid_nsec: u32,
    pub(crate) attr_valid_nsec: u32,
    pub(crate) attr: fuse_attr,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_forget_in {
    pub(crate) nlookup: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_forget_one {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_batch_forget_in {
    pub(crate) count: u32,
    pub(crate) dummy: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getattr_in {
    pub(crate) getattr_flags: u32,
    pub(crate) dummy: u32,
    pub(crate) fh: u64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_attr_out {
    pub(crate) attr_valid: u64,
    pub(crate) attr_valid_nsec: u32,
    pub(crate) dummy: u32,
    pub(crate) attr: fuse_attr,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getxtimes_out {
    pub(crate) bkuptime: u64,
    pub(crate) crtime: u64,
    pub(crate) bkuptimensec: u32,
    pub(crate) crtimensec: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_mknod_in {
    pub(crate) mode: u32,
    pub(crate) rdev: u32,
    pub(crate) umask: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_mkdir_in {
    pub(crate) mode: u32,
    pub(crate) umask: u32,
}

/// macFUSE extends this struct with the `renamex_np(2)` flags. The kernel only sends the
/// extended layout once `FUSE_RENAME_SWAP`/`FUSE_RENAME_EXCL` were negotiated, which fuser
/// always does on macOS, so the layout is unconditional there.
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_rename_in {
    pub(crate) newdir: u64,
    #[cfg(target_os = "macos")]
    pub(crate) flags: u32,
    #[cfg(target_os = "macos")]
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_rename2_in {
    pub(crate) newdir: u64,
    pub(crate) flags: u32,
    pub(crate) padding: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_exchange_in {
    pub(crate) olddir: u64,
    pub(crate) newdir: u64,
    pub(crate) options: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_link_in {
    pub(crate) oldnodeid: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_setattr_in {
    pub(crate) valid: u32,
    pub(crate) padding: u32,
    pub(crate) fh: u64,
    pub(crate) size: u64,
    pub(crate) lock_owner: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_atime
    pub(crate) atime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_mtime
    pub(crate) mtime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_ctime
    pub(crate) ctime: i64, // Used since ABI 7.23.
    pub(crate) atimensec: u32,
    pub(crate) mtimensec: u32,
    pub(crate) ctimensec: u32, // Used since ABI 7.23.
    pub(crate) mode: u32,
    pub(crate) unused4: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) unused5: u32,
    #[cfg(target_os = "macos")]
    pub(crate) bkuptime: u64,
    #[cfg(target_os = "macos")]
    pub(crate) chgtime: u64,
    #[cfg(target_os = "macos")]
    pub(crate) crtime: u64,
    #[cfg(target_os = "macos")]
    pub(crate) bkuptimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) chgtimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) crtimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) flags: u32, // see chflags(2)
}

impl fuse_setattr_in {
    pub(crate) fn atime_now(&self) -> bool {
        FattrFlags::from_bits_retain(self.valid).contains(FattrFlags::FATTR_ATIME_NOW)
    }

    pub(crate) fn mtime_now(&self) -> bool {
        FattrFlags::from_bits_retain(self.valid).contains(FattrFlags::FATTR_MTIME_NOW)
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_open_in {
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's open method and this matches the open() syscall
    pub(crate) flags: i32,
    pub(crate) open_flags: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_create_in {
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's create method and this matches the open() syscall
    pub(crate) flags: i32,
    pub(crate) mode: u32,
    pub(crate) umask: u32,
    pub(crate) open_flags: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_create_out(pub(crate) fuse_entry_out, pub(crate) fuse_open_out);

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_open_out {
    pub(crate) fh: u64,
    pub(crate) open_flags: u32,
    pub(crate) backing_id: u32, // Used since ABI 7.40.
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_release_in {
    pub(crate) fh: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's read method
    pub(crate) flags: i32,
    pub(crate) release_flags: u32,
    pub(crate) lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_flush_in {
    pub(crate) fh: u64,
    pub(crate) unused: u32,
    pub(crate) padding: u32,
    pub(crate) lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_read_in {
    pub(crate) fh: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) read_flags: u32,
    pub(crate) lock_owner: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's read method
    pub(crate) flags: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_write_in {
    pub(crate) fh: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i64 when invoking the filesystem's write method
    pub(crate) offset: i64,
    pub(crate) size: u32,
    pub(crate) write_flags: u32,
    pub(crate) lock_owner: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's read method
    pub(crate) flags: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_write_out {
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_statfs_out {
    pub(crate) st: fuse_kstatfs,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_fsync_in {
    pub(crate) fh: u64,
    pub(crate) fsync_flags: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_setxattr_in {
    pub(crate) size: u32,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's setxattr method
    pub(crate) flags: i32,
    #[cfg(target_os = "macos")]
    pub(crate) position: u32,
    #[cfg(target_os = "macos")]
    pub(crate) padding: u32,
}

/// Tail of the extended `fuse_setxattr_in`, which the kernel appends to the layout above
/// once `FUSE_SETXATTR_EXT` has been negotiated. Never sent on macOS, where bit 29 means
/// `FUSE_CASE_INSENSITIVE` instead
#[cfg(not(target_os = "macos"))]
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_setxattr_in_ext {
    pub(crate) setxattr_flags: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getxattr_in {
    pub(crate) size: u32,
    pub(crate) padding: u32,
    #[cfg(target_os = "macos")]
    pub(crate) position: u32,
    #[cfg(target_os = "macos")]
    pub(crate) padding2: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getxattr_out {
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lk_in {
    pub(crate) fh: u64,
    pub(crate) owner: u64,
    pub(crate) lk: fuse_file_lock,
    pub(crate) lk_flags: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lk_out {
    pub(crate) lk: fuse_file_lock,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_access_in {
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's access method
    pub(crate) mask: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub(crate) struct fuse_init_in {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) max_readahead: u32,
    pub(crate) flags: u32,
    pub(crate) flags2: u32,
    pub(crate) unused: [u32; 11],
}

pub(crate) const FUSE_COMPAT_INIT_OUT_SIZE: usize = 8;
pub(crate) const FUSE_COMPAT_22_INIT_OUT_SIZE: usize = 24;

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_init_out {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) max_readahead: u32,
    pub(crate) flags: u32,
    pub(crate) max_background: u16,
    pub(crate) congestion_threshold: u16,
    pub(crate) max_write: u32,
    pub(crate) time_gran: u32,
    pub(crate) max_pages: u16,
    pub(crate) unused2: u16,
    pub(crate) flags2: u32,
    pub(crate) max_stack_depth: u32,
    pub(crate) reserved: [u32; 6],
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct cuse_init_in {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) unused: u32,
    pub(crate) flags: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable)]
pub(crate) struct cuse_init_out {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) unused: u32,
    pub(crate) flags: u32,
    pub(crate) max_read: u32,
    pub(crate) max_write: u32,
    pub(crate) dev_major: u32, // chardev major
    pub(crate) dev_minor: u32, // chardev minor
    pub(crate) spare: [u32; 10],
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_interrupt_in {
    pub(crate) unique: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_bmap_in {
    pub(crate) block: u64,
    pub(crate) blocksize: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_bmap_out {
    pub(crate) block: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_ioctl_in {
    pub(crate) fh: u64,
    pub(crate) flags: u32,
    pub(crate) cmd: u32,
    pub(crate) arg: u64,
    pub(crate) in_size: u32,
    pub(crate) out_size: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable)]
pub(crate) struct fuse_ioctl_iovec {
    pub(crate) base: u64,
    pub(crate) len: u64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_ioctl_out {
    pub(crate) result: i32,
    pub(crate) flags: u32,
    pub(crate) in_iovs: u32,
    pub(crate) out_iovs: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_poll_in {
    pub(crate) fh: u64,
    pub(crate) kh: u64,
    pub(crate) flags: u32,
    pub(crate) events: u32, // Used since ABI 7.21.
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_poll_out {
    pub(crate) revents: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_poll_wakeup_out {
    pub(crate) kh: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_fallocate_in {
    pub(crate) fh: u64,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) mode: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_in_header {
    pub(crate) len: u32,
    pub(crate) opcode: u32,
    pub(crate) unique: u64,
    pub(crate) nodeid: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) pid: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_out_header {
    pub(crate) len: u32,
    pub(crate) error: i32,
    pub(crate) unique: u64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_dirent {
    pub(crate) ino: u64,
    pub(crate) off: u64,
    pub(crate) namelen: u32,
    pub(crate) typ: u32,
    // followed by name of namelen bytes
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_direntplus {
    pub(crate) entry_out: fuse_entry_out,
    pub(crate) dirent: fuse_dirent,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_inval_inode_out {
    pub(crate) ino: u64,
    pub(crate) off: i64,
    pub(crate) len: i64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_inval_entry_out {
    pub(crate) parent: u64,
    pub(crate) namelen: u32,
    pub(crate) flags: u32,
}

/// Expire the entry rather than invalidating it: the kernel marks it for revalidation
/// on next use instead of forcibly detaching it, which would also detach any submounts
/// beneath it. Requires `FUSE_HAS_EXPIRE_ONLY`
pub(crate) const FUSE_EXPIRE_ONLY: u32 = 1 << 0;

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_delete_out {
    pub(crate) parent: u64,
    pub(crate) child: u64,
    pub(crate) namelen: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_store_out {
    pub(crate) nodeid: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_retrieve_out {
    pub(crate) notify_unique: u64,
    pub(crate) nodeid: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_retrieve_in {
    // matches the size of fuse_write_in
    pub(crate) dummy1: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) dummy2: u32,
    pub(crate) dummy3: u64,
    pub(crate) dummy4: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lseek_in {
    pub(crate) fh: u64,
    pub(crate) offset: i64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) whence: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lseek_out {
    pub(crate) offset: i64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_syncfs_in {
    pub(crate) padding: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_copy_file_range_in {
    pub(crate) fh_in: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) off_in: i64,
    pub(crate) nodeid_out: u64,
    pub(crate) fh_out: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) off_out: i64,
    pub(crate) len: u64,
    pub(crate) flags: u64,
}

/// Size of the `in_out` area of `fuse_uring_req_header`. Since ABI 7.42
pub(crate) const FUSE_URING_IN_OUT_HEADER_SZ: usize = 128;
/// Size of the `op_in` area of `fuse_uring_req_header`. Since ABI 7.42
pub(crate) const FUSE_URING_OP_IN_OUT_SZ: usize = 128;

/// Commands carried in `io_uring_sqe.cmd_op` for `IORING_OP_URING_CMD` on `/dev/fuse`.
/// Since ABI 7.42. 7.46 adds `ADD_QUEUE = 3` and `ADD_BUFPOOL = 4`, not declared here
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub(crate) enum fuse_uring_cmd {
    FUSE_IO_URING_CMD_INVALID = 0,
    FUSE_IO_URING_CMD_REGISTER = 1,
    FUSE_IO_URING_CMD_COMMIT_AND_FETCH = 2,
}

/// Trailer of `fuse_uring_req_header`, written by the kernel on fetch and by userspace on
/// commit. Since ABI 7.42. `padding` becomes `offset` in 7.46 and must be sent as zero
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_uring_ent_in_out {
    pub(crate) flags: u64,
    /// The request's `unique`, echoed in `fuse_uring_cmd_req.commit_id`
    pub(crate) commit_id: u64,
    /// Bytes valid in the payload buffer, in either direction
    pub(crate) payload_sz: u32,
    pub(crate) padding: u32,
    pub(crate) reserved: u64,
}

/// Per-entry header buffer, `iov[0]` of a REGISTER. Since ABI 7.42
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_uring_req_header {
    /// `fuse_in_header` on fetch, `fuse_out_header` on commit
    pub(crate) in_out: [u8; FUSE_URING_IN_OUT_HEADER_SZ],
    /// The fixed per-opcode in-struct (`in_args[0]`); unused on commit
    pub(crate) op_in: [u8; FUSE_URING_OP_IN_OUT_SZ],
    pub(crate) ring_ent_in_out: fuse_uring_ent_in_out,
}

/// The command data in the 80-byte area of an SQE128. Since ABI 7.42. 7.46 grows this to
/// 40 bytes with a trailing union; the rest of the 80-byte cmd area must be zero
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_uring_cmd_req {
    pub(crate) flags: u64,
    /// 0 for REGISTER
    pub(crate) commit_id: u64,
    pub(crate) qid: u16,
    pub(crate) padding: [u8; 6],
}

#[cfg(test)]
mod test {
    use std::mem::offset_of;

    use super::*;

    #[test]
    fn uring_ent_in_out_layout() {
        assert_eq!(size_of::<fuse_uring_ent_in_out>(), 32);
        assert_eq!(align_of::<fuse_uring_ent_in_out>(), align_of::<u64>());
        assert_eq!(offset_of!(fuse_uring_ent_in_out, flags), 0);
        assert_eq!(offset_of!(fuse_uring_ent_in_out, commit_id), 8);
        assert_eq!(offset_of!(fuse_uring_ent_in_out, payload_sz), 16);
        assert_eq!(offset_of!(fuse_uring_ent_in_out, padding), 20);
        assert_eq!(offset_of!(fuse_uring_ent_in_out, reserved), 24);
    }

    #[test]
    fn uring_req_header_layout() {
        assert_eq!(size_of::<fuse_uring_req_header>(), 288);
        assert_eq!(align_of::<fuse_uring_req_header>(), align_of::<u64>());
        assert_eq!(offset_of!(fuse_uring_req_header, in_out), 0);
        assert_eq!(offset_of!(fuse_uring_req_header, op_in), 128);
        assert_eq!(offset_of!(fuse_uring_req_header, ring_ent_in_out), 256);
    }

    #[test]
    fn uring_cmd_req_layout() {
        assert_eq!(size_of::<fuse_uring_cmd_req>(), 24);
        assert_eq!(align_of::<fuse_uring_cmd_req>(), align_of::<u64>());
        assert_eq!(offset_of!(fuse_uring_cmd_req, flags), 0);
        assert_eq!(offset_of!(fuse_uring_cmd_req, commit_id), 8);
        assert_eq!(offset_of!(fuse_uring_cmd_req, qid), 16);
        assert_eq!(offset_of!(fuse_uring_cmd_req, padding), 18);
    }

    #[test]
    fn uring_cmd_req_round_trip() {
        let req = fuse_uring_cmd_req {
            flags: 0x0102_0304_0506_0708,
            commit_id: 0x1112_1314_1516_1718,
            qid: 0x2122,
            padding: [0x31, 0x32, 0x33, 0x34, 0x35, 0x36],
        };
        let bytes = req.as_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[..8], &0x0102_0304_0506_0708u64.to_ne_bytes());
        assert_eq!(&bytes[8..16], &0x1112_1314_1516_1718u64.to_ne_bytes());
        assert_eq!(&bytes[16..18], &0x2122u16.to_ne_bytes());
        assert_eq!(&bytes[18..], &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        let back = fuse_uring_cmd_req::read_from_bytes(bytes).unwrap();
        assert_eq!(back.flags, req.flags);
        assert_eq!(back.commit_id, req.commit_id);
        assert_eq!(back.qid, req.qid);
        assert_eq!(back.padding, req.padding);
    }

    /// The direction the transport reads: a kernel-filled header buffer decodes into the
    /// `fuse_in_header` at the front and the trailer at 256
    #[test]
    fn uring_req_header_read() {
        let mut bytes = [0u8; 288];
        bytes[..4].copy_from_slice(&0x0000_0028u32.to_ne_bytes());
        bytes[4..8].copy_from_slice(&(fuse_opcode::FUSE_GETATTR as u32).to_ne_bytes());
        bytes[8..16].copy_from_slice(&0x4142_4344_4546_4748u64.to_ne_bytes());
        bytes[256..264].copy_from_slice(&0x0102_0304_0506_0708u64.to_ne_bytes());
        bytes[264..272].copy_from_slice(&0x1112_1314_1516_1718u64.to_ne_bytes());
        bytes[272..276].copy_from_slice(&0x2122_2324u32.to_ne_bytes());
        bytes[276..280].copy_from_slice(&0x3132_3334u32.to_ne_bytes());
        bytes[280..288].copy_from_slice(&0x5152_5354_5556_5758u64.to_ne_bytes());
        let hdr = fuse_uring_req_header::read_from_bytes(&bytes).unwrap();
        let (in_header, _) = fuse_in_header::read_from_prefix(&hdr.in_out).unwrap();
        assert_eq!(in_header.len, 0x28);
        assert_eq!(in_header.opcode, fuse_opcode::FUSE_GETATTR as u32);
        assert_eq!(in_header.unique, 0x4142_4344_4546_4748);
        assert_eq!(hdr.ring_ent_in_out.flags, 0x0102_0304_0506_0708);
        assert_eq!(hdr.ring_ent_in_out.commit_id, 0x1112_1314_1516_1718);
        assert_eq!(hdr.ring_ent_in_out.payload_sz, 0x2122_2324);
        assert_eq!(hdr.ring_ent_in_out.padding, 0x3132_3334);
        assert_eq!(hdr.ring_ent_in_out.reserved, 0x5152_5354_5556_5758);
        assert_eq!(hdr.as_bytes(), &bytes);
    }

    #[test]
    fn uring_cmd_values() {
        use fuse_uring_cmd::*;
        assert_eq!(size_of::<fuse_uring_cmd>(), 4);
        assert_eq!(align_of::<fuse_uring_cmd>(), 4);
        assert_eq!(FUSE_IO_URING_CMD_INVALID as u32, 0);
        assert_eq!(FUSE_IO_URING_CMD_REGISTER as u32, 1);
        assert_eq!(FUSE_IO_URING_CMD_COMMIT_AND_FETCH as u32, 2);
        assert_eq!(fuse_uring_cmd::try_from(0), Ok(FUSE_IO_URING_CMD_INVALID));
        assert_eq!(fuse_uring_cmd::try_from(1), Ok(FUSE_IO_URING_CMD_REGISTER));
        assert_eq!(
            fuse_uring_cmd::try_from(2),
            Ok(FUSE_IO_URING_CMD_COMMIT_AND_FETCH)
        );
        assert_eq!(fuse_uring_cmd::try_from(3).unwrap_err().number, 3);
        assert!(fuse_uring_cmd::try_from(u32::MAX).is_err());
    }

    /// The ring places each request's fixed in-struct at `op_in`, and the io_uring transport
    /// relies on every such struct being a whole number of `u64`s. Every new `*_in` struct
    /// parsed by `ll::request` belongs in this list
    #[test]
    fn fixed_in_structs_are_multiples_of_8() {
        assert!(size_of::<fuse_in_header>() <= FUSE_URING_IN_OUT_HEADER_SZ);
        assert!(size_of::<fuse_out_header>() <= FUSE_URING_IN_OUT_HEADER_SZ);
        let sizes = [
            ("fuse_in_header", size_of::<fuse_in_header>()),
            ("fuse_init_in", size_of::<fuse_init_in>()),
            ("fuse_forget_in", size_of::<fuse_forget_in>()),
            ("fuse_batch_forget_in", size_of::<fuse_batch_forget_in>()),
            ("fuse_getattr_in", size_of::<fuse_getattr_in>()),
            ("fuse_setattr_in", size_of::<fuse_setattr_in>()),
            ("fuse_mknod_in", size_of::<fuse_mknod_in>()),
            ("fuse_mkdir_in", size_of::<fuse_mkdir_in>()),
            ("fuse_rename_in", size_of::<fuse_rename_in>()),
            ("fuse_rename2_in", size_of::<fuse_rename2_in>()),
            ("fuse_link_in", size_of::<fuse_link_in>()),
            ("fuse_open_in", size_of::<fuse_open_in>()),
            ("fuse_create_in", size_of::<fuse_create_in>()),
            ("fuse_release_in", size_of::<fuse_release_in>()),
            ("fuse_flush_in", size_of::<fuse_flush_in>()),
            ("fuse_read_in", size_of::<fuse_read_in>()),
            ("fuse_write_in", size_of::<fuse_write_in>()),
            ("fuse_fsync_in", size_of::<fuse_fsync_in>()),
            ("fuse_setxattr_in", size_of::<fuse_setxattr_in>()),
            ("fuse_getxattr_in", size_of::<fuse_getxattr_in>()),
            ("fuse_lk_in", size_of::<fuse_lk_in>()),
            ("fuse_access_in", size_of::<fuse_access_in>()),
            ("fuse_interrupt_in", size_of::<fuse_interrupt_in>()),
            ("fuse_bmap_in", size_of::<fuse_bmap_in>()),
            ("fuse_ioctl_in", size_of::<fuse_ioctl_in>()),
            ("fuse_poll_in", size_of::<fuse_poll_in>()),
            ("fuse_fallocate_in", size_of::<fuse_fallocate_in>()),
            ("fuse_lseek_in", size_of::<fuse_lseek_in>()),
            (
                "fuse_copy_file_range_in",
                size_of::<fuse_copy_file_range_in>(),
            ),
            ("fuse_syncfs_in", size_of::<fuse_syncfs_in>()),
            ("fuse_statx_in", size_of::<fuse_statx_in>()),
            (
                "fuse_notify_retrieve_in",
                size_of::<fuse_notify_retrieve_in>(),
            ),
        ];
        for (name, size) in sizes {
            assert_eq!(size % 8, 0, "{name} is {size} bytes");
            assert!(size <= FUSE_URING_OP_IN_OUT_SZ, "{name} is {size} bytes");
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(size_of::<fuse_setxattr_in_ext>() % 8, 0);
    }
}
