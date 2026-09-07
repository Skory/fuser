//! An in-memory filesystem for measuring transport cost: a single sparse file `data` whose
//! reads and writes do no work beyond touching the payload. Attributes have a zero TTL and the
//! file is opened with `FOPEN_DIRECT_IO`, so every `stat` and `read` reaches the filesystem.
//! `fuser-tests transport-bench` mounts it over `/dev/fuse` and over io_uring.

mod common;

use std::ffi::OsStr;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use clap::Parser;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::FopenFlags;
use fuser::INodeNo;
use fuser::LockOwner;
use fuser::OpenFlags;
use fuser::ReplyAttr;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEntry;
use fuser::ReplyOpen;
use fuser::ReplyWrite;
use fuser::Request;
use fuser::WriteFlags;

use crate::common::args::CommonArgs;

#[derive(Parser)]
#[command(version, author = "Christopher Berner")]
struct Args {
    #[clap(flatten)]
    common_args: CommonArgs,
    /// Size of the `data` file in GiB
    #[clap(long, default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=1 << 33))]
    size_gib: u64,
    /// Serve reads with `reply.data()` from a heap buffer instead of `reply.fill()`
    #[clap(long)]
    reply_data: bool,
    /// Serve reads through the page cache instead of `FOPEN_DIRECT_IO` (for manual runs;
    /// `transport-bench` does not use it)
    #[clap(long)]
    cached: bool,
}

const TTL: Duration = Duration::ZERO;
const DATA_INO: INodeNo = INodeNo(2);
const DATA_NAME: &str = "data";
const FILL_BYTE: u8 = 0x5a;

const DIR_ATTR: FileAttr = FileAttr {
    ino: INodeNo::ROOT,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 0,
    gid: 0,
    rdev: 0,
    flags: 0,
    blksize: 4096,
};

fn data_attr(size: u64) -> FileAttr {
    FileAttr {
        ino: DATA_INO,
        size,
        blocks: size / 512,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o666,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
        blksize: 4096,
    }
}

struct BenchFs {
    data: FileAttr,
    reply_data: bool,
    cached: bool,
}

impl Filesystem for BenchFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == INodeNo::ROOT && name.to_str() == Some(DATA_NAME) {
            reply.entry(&TTL, &self.data, fuser::Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino {
            INodeNo::ROOT => reply.attr(&TTL, &DIR_ATTR),
            DATA_INO => reply.attr(&TTL, &self.data),
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn open(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        let flags = if self.cached {
            FopenFlags::empty()
        } else {
            FopenFlags::FOPEN_DIRECT_IO
        };
        reply.opened(FileHandle(1), flags);
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino != DATA_INO {
            return reply.error(Errno::ENOENT);
        }
        let n = self.data.size.saturating_sub(offset).min(u64::from(size)) as usize;
        if self.reply_data {
            let buf = vec![FILL_BYTE; n];
            reply.data(&buf);
        } else {
            reply.fill(n, |buf| {
                buf.fill(FILL_BYTE);
                Ok(n)
            });
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        reply.written(data.len() as u32);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != INodeNo::ROOT {
            return reply.error(Errno::ENOENT);
        }
        let entries = [
            (INodeNo::ROOT, FileType::Directory, "."),
            (INodeNo::ROOT, FileType::Directory, ".."),
            (DATA_INO, FileType::RegularFile, DATA_NAME),
        ];
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 is the offset of the next entry
            if reply.add(ino, (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let args = Args::parse();
    env_logger::init();

    let cfg = args.common_args.config();
    let fs = BenchFs {
        data: data_attr(args.size_gib << 30),
        reply_data: args.reply_data,
        cached: args.cached,
    };
    fuser::mount(fs, &args.common_args.mount_point, &cfg).unwrap();
}
