//! One ring: its entries, their state machine, the commit protocol and the ring thread's loop.
//!
//! Every SQE of a ring is pushed and submitted by the ring's own thread. Other threads reply by
//! writing the entry's buffers under the entry state machine, queueing the entry in
//! `Live::pending` and waking the ring thread through an eventfd. Lock order is an entry's
//! `state`, then `live`; neither is held while buffers are written or the io_uring is used.

use std::fmt;
use std::io;
use std::io::IoSlice;
use std::mem::ManuallyDrop;
use std::os::fd::AsRawFd;
use std::ptr;
use std::ptr::NonNull;
use std::slice;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::thread::ThreadId;

use io_uring::IoUring;
use io_uring::cqueue;
use io_uring::opcode;
use io_uring::squeue;
use io_uring::types;
use log::debug;
use log::error;
use log::warn;
use nix::sys::eventfd::EfdFlags;
use nix::sys::eventfd::EventFd;
use parking_lot::Mutex;
use smallvec::SmallVec;
use zerocopy::IntoBytes;

use crate::dev_fuse::DevFuse;
use crate::ll::Errno;
use crate::ll::fuse_abi as abi;
use crate::uring::mem::FLAGS_OFFSET;
use crate::uring::mem::HEADER_SZ;
use crate::uring::mem::PAYLOAD_SZ_OFFSET;
use crate::uring::mem::RingMemory;
use crate::uring::staging::StagingError;
use crate::uring::staging::stage_request;

/// `user_data` of the eventfd poll. Entry `user_data` is `qid << 32 | idx`, so it never gets here.
pub(crate) const WAKE: u64 = u64::MAX;
/// `io_uring_sqe.len` is a `u32` at this byte offset in the uapi layout.
const SQE_LEN_OFFSET: usize = 24;
const OUT_HEADER_SZ: usize = size_of::<abi::fuse_out_header>();
/// Largest SQ io_uring accepts; the CQ may be twice that.
pub(crate) const IORING_MAX_ENTRIES: usize = 32768;

/// Called once per fetched request with the commit handle and the contiguous request bytes.
/// The slice is valid only for the duration of the call.
pub(crate) trait FetchHandler: Send {
    fn handle(&mut self, commit: RingCommit, request: &[u8]);
}

impl<F: FnMut(RingCommit, &[u8]) + Send> FetchHandler for F {
    fn handle(&mut self, commit: RingCommit, request: &[u8]) {
        self(commit, request)
    }
}

/// Submission and completion queue sizes for a ring of `entries` entries. The kernel needs
/// `cq >= sq` when the CQ size is given explicitly.
pub(crate) fn ring_sizes(entries: usize) -> (u32, u32) {
    let sq = entries.next_power_of_two().clamp(8, IORING_MAX_ENTRIES);
    let cq = (2 * entries)
        .next_power_of_two()
        .clamp(sq, 2 * IORING_MAX_ENTRIES);
    if entries > IORING_MAX_ENTRIES {
        warn!(
            "io_uring: {entries} entries per ring exceed the completion queue; overflow handling \
             will be used"
        );
    }
    (sq as u32, cq as u32)
}

/// The io_uring instance, owned by the ring thread alone; nothing else may touch it.
pub(crate) struct RingIo {
    io: IoUring<squeue::Entry128, cqueue::Entry>,
    #[cfg(test)]
    hooks: test::IoHooks,
}

impl RingIo {
    /// `io_uring_setup`; `EPERM` and `ENOSYS` here mean the environment forbids io_uring,
    /// `EINVAL` a kernel before 6.1 that lacks the setup flags.
    pub(crate) fn open(sq_entries: u32, cq_entries: u32) -> io::Result<Self> {
        let io = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .dontfork()
            .setup_submit_all()
            .setup_cqsize(cq_entries)
            .setup_single_issuer()
            .setup_defer_taskrun()
            .setup_r_disabled()
            .build(sq_entries)?;
        Ok(Self {
            io,
            #[cfg(test)]
            hooks: test::IoHooks::default(),
        })
    }

    /// Enables the ring and binds the calling thread as its issuer; every later
    /// `io_uring_enter` must come from that thread.
    fn enable(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.before_enable()?;
        self.io.submitter().register_enable_rings()
    }

    fn submit(&mut self) -> io::Result<usize> {
        #[cfg(test)]
        self.hooks.before_submit()?;
        self.io.submit()
    }

    /// Submits the queue and waits for one CQE; `timed` bounds the wait to 10 ms.
    fn submit_and_wait(&mut self, timed: bool) -> io::Result<usize> {
        if timed {
            let ts = types::Timespec::new().nsec(10_000_000);
            let args = types::SubmitArgs::new().timespec(&ts);
            self.io.submitter().submit_with_args(1, &args)
        } else {
            self.io.submit_and_wait(1)
        }
    }

    /// Pushes one SQE, making room with a `submit` when the queue is full. `Err` means the
    /// SQE was not pushed.
    fn push_or_submit(&mut self, sqe: &squeue::Entry128) -> io::Result<()> {
        // SAFETY: every buffer an SQE names lives in `Ring::mem`, which stays mapped while a
        // command is pending (`Drop for Ring`), or in a `RingEntry::iov` that lives as long.
        if unsafe { self.io.submission().push(sqe) }.is_ok() {
            return Ok(());
        }
        self.submit()?;
        // SAFETY: as above.
        unsafe { self.io.submission().push(sqe) }
            .map_err(|_| io::Error::other("submission queue still full after submit"))
    }
}

/// State shared between the ring thread and every `RingCommit`.
pub(crate) struct Ring {
    index: usize,
    /// Whether an unmount will end the connection when the session is dropped without
    /// running; `Session::from_fd` sessions have nothing that will.
    mounted: bool,
    /// The `/dev/fuse` descriptor named in every SQE.
    device: Arc<DevFuse>,
    /// Set at the top of `thread_main`; commits from that thread skip the eventfd because the
    /// thread drains `pending` itself before waiting.
    ring_thread: OnceLock<ThreadId>,
    wake: EventFd,
    live: Mutex<Live>,
    entries: Box<[RingEntry]>,
    /// Dropped only when `live.in_kernel` is zero; otherwise leaked, see `Drop`.
    mem: ManuallyDrop<RingMemory>,
    #[cfg(test)]
    hooks: test::RingHooks,
}

/// Exit decision, in-kernel accounting and the commit queue, under one lock.
struct Live {
    /// Entries whose command is pending in the kernel or queued in `pending` to become so.
    in_kernel: usize,
    /// Entries fetched and not yet handed back: `Dispatching`, `Deferred`, `Dispatched` or
    /// `Committing`. Their kernel requests would hang if the ring left while they are held.
    outstanding: usize,
    /// Entries in state `Pending`, waiting for the ring thread to push their COMMIT_AND_FETCH.
    pending: Vec<u32>,
    /// An `-ENOTCONN` or `-ECONNABORTED` CQE was seen.
    conn_dead: bool,
    /// First unexpected CQE error or submit failure.
    fatal: Option<io::Error>,
    /// The session is tearing down. The kernel posts no CQE at unmount for an entry held in
    /// userspace, so a ring whose entries are all held would otherwise never see `conn_dead`.
    shutdown: bool,
    /// The session failed before it could serve, so the thread returns instead of draining.
    abandon: bool,
    /// Set in the same critical section that decides to exit, so a commit either finds it or
    /// is counted in `in_kernel` before the decision.
    exited: bool,
}

/// Decrements a `Live` count; a count already at zero means the accounting is wrong, which is
/// logged rather than wrapped so `Drop for Ring` keeps erring towards leaking.
fn dec(count: &mut usize, e: &RingEntry, what: &str) {
    match count.checked_sub(1) {
        Some(n) => *count = n,
        None => error!(
            "io_uring: qid {} entry {} left the {what} count while it was zero",
            e.qid, e.idx
        ),
    }
}

impl Live {
    /// Moves `state` to `Dead`, keeping `outstanding` in step with the state it leaves.
    fn kill(&mut self, e: &RingEntry, state: &mut EntryState) {
        if state.is_outstanding() {
            dec(&mut self.outstanding, e, "outstanding");
        }
        *state = EntryState::Dead;
    }
}

/// `libc::iovec` holds `*mut c_void`, so this newtype carries the `Send + Sync` impls.
/// Invariant: both iovecs point into `Ring::mem`, which outlives every SQE that names them.
struct EntryIov([libc::iovec; 2]);
// SAFETY: see the invariant above; the pointers are never dereferenced through this type.
unsafe impl Send for EntryIov {}
unsafe impl Sync for EntryIov {}

/// Start of an entry's stride in `Ring::mem`.
struct EntryPtr(NonNull<u8>);
// SAFETY: the pointee is plain memory in `Ring::mem`, accessed only under the entry state
// machine, which serializes writers.
unsafe impl Send for EntryPtr {}
unsafe impl Sync for EntryPtr {}

pub(crate) struct RingEntry {
    idx: u32,
    qid: u16,
    base: EntryPtr,
    gap: usize,
    payload_cap: usize,
    iov: EntryIov,
    state: Mutex<EntryState>,
}

#[derive(Debug)]
enum EntryState {
    /// A REGISTER (`last == 0`) or COMMIT_AND_FETCH for `last` is pending in the kernel.
    InKernel { last: u64 },
    /// The handler is running; `direct_ok` means the request has no payload, so a reply may
    /// be written while the request slice is live.
    Dispatching {
        direct_ok: bool,
        reply_taken: bool,
        commit_id: u64,
    },
    /// A reply arrived during dispatch while the payload was borrowed; written after dispatch.
    Deferred { bytes: ReplyBytes, commit_id: u64 },
    /// Dispatch returned, reply still to come.
    Dispatched { commit_id: u64 },
    /// Buffers being written by exactly one thread.
    Committing,
    /// Buffers written, `idx` is in `live.pending`, awaiting the ring thread's push.
    Pending { commit_id: u64 },
    /// Not in the kernel and not coming back: before REGISTER, after ENOTCONN, a fatal
    /// error, or ring exit.
    Dead,
}

impl EntryState {
    /// Fetched and held by userspace, counted in `Live::outstanding`.
    fn is_outstanding(&self) -> bool {
        matches!(
            self,
            Self::Dispatching { .. }
                | Self::Deferred { .. }
                | Self::Dispatched { .. }
                | Self::Committing
        )
    }
}

/// A stashed reply; `Debug` prints only its length because the bytes are file data.
struct ReplyBytes(Vec<u8>);

impl fmt::Debug for ReplyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.0.len())
    }
}

/// The ring variant of a reply sender. `Clone` so the usual owned reply objects can be
/// handed out; a second commit for the same fetch is rejected by the state machine, never
/// written.
#[derive(Clone)]
pub(crate) struct RingCommit {
    ring: Arc<Ring>,
    idx: u32,
    commit_id: u64,
}

impl fmt::Debug for RingCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingCommit")
            .field("ring", &self.ring.index)
            .field("idx", &self.idx)
            .field("commit_id", &self.commit_id)
            .finish()
    }
}

/// Outcome of `RingCommit::begin`.
enum Begun {
    /// The entry is `Committing`; write the buffers and hand off.
    Direct,
    /// The reply was stored in the entry for the ring thread to write after dispatch.
    Deferred,
    /// The ring exited; nothing to do.
    Dropped,
}

impl RingCommit {
    fn entry(&self) -> &RingEntry {
        &self.ring.entries[self.idx as usize]
    }

    /// The `/dev/fuse` descriptor of the connection, for passthrough ioctls.
    pub(crate) fn device(&self) -> &Arc<DevFuse> {
        &self.ring.device
    }

    /// `live` is released before the reply is copied; `hand_off` re-checks `exited` under both
    /// locks. A refused commit is `NotConnected` when the connection ended (expected after
    /// unmount) and `Other` for a duplicate (a filesystem bug).
    fn begin(&self, iov: &[IoSlice<'_>]) -> io::Result<Begun> {
        let e = self.entry();
        let mut state = e.state.lock();
        let (exited, conn_dead) = {
            let live = self.ring.live.lock();
            (live.exited, live.conn_dead)
        };
        if exited {
            self.ring.live.lock().kill(e, &mut state);
            drop(state);
            debug!(
                "io_uring: dropping reply for unique {} after ring {} exited",
                self.commit_id, self.ring.index
            );
            return Ok(Begun::Dropped);
        }
        match &*state {
            EntryState::Dispatching {
                direct_ok: true,
                commit_id,
                ..
            }
            | EntryState::Dispatched { commit_id }
                if *commit_id == self.commit_id =>
            {
                *state = EntryState::Committing;
                Ok(Begun::Direct)
            }
            EntryState::Dispatching {
                direct_ok: false,
                commit_id,
                ..
            } if *commit_id == self.commit_id => {
                let mut bytes = Vec::with_capacity(iov.iter().map(|s| s.len()).sum());
                iov.iter().for_each(|s| bytes.extend_from_slice(s));
                *state = EntryState::Deferred {
                    bytes: ReplyBytes(bytes),
                    commit_id: self.commit_id,
                };
                Ok(Begun::Deferred)
            }
            _ if conn_dead => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "reply after the connection ended",
            )),
            _ => Err(io::Error::other("duplicate reply")),
        }
    }

    /// Commits a reply; `iov[0]` is the `fuse_out_header`, the rest the payload. Anything else
    /// in `iov[0]` is answered with `EINVAL`, whichever path the reply takes.
    pub(crate) fn commit(&self, iov: &[IoSlice<'_>]) -> io::Result<()> {
        if iov.first().is_none_or(|h| h.len() != OUT_HEADER_SZ) {
            error!(
                "io_uring: reply for unique {} does not start with a fuse_out_header; replying \
                 EINVAL",
                self.commit_id
            );
            let header = errno_header(self.commit_id, Errno::EINVAL);
            return self.commit(&[IoSlice::new(header.as_bytes())]);
        }
        if let Begun::Direct = self.begin(iov)? {
            // SAFETY: `Committing` makes this thread the only writer; a request slice can
            // only be live if the request had no payload, and it never covers the header
            // or the payload area.
            unsafe { self.entry().write_reply(self.commit_id, iov) };
            self.ring.hand_off(self.entry(), self.commit_id);
        }
        Ok(())
    }

    /// Commits an errno reply. Only valid while the entry is `Dispatching` or `Dispatched`;
    /// anything else is logged and ignored.
    pub(crate) fn commit_errno(&self, errno: Errno) {
        let header = errno_header(self.commit_id, errno);
        match self.commit(&[IoSlice::new(header.as_bytes())]) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                debug!("io_uring: {err} for unique {}", self.commit_id)
            }
            Err(err) => error!(
                "io_uring: {err} for unique {} on qid {}",
                self.commit_id,
                self.entry().qid
            ),
        }
    }

    /// Errno reply for an entry that is already `Committing`.
    #[cfg(test)]
    fn write_errno_and_hand_off(&self, errno: Errno) {
        // SAFETY: the caller made the entry `Committing`, so this thread is its only writer.
        unsafe { self.entry().write_errno(self.commit_id, errno) };
        self.ring.hand_off(self.entry(), self.commit_id);
    }

    /// Records that a reply object exists for this fetch, so the ring thread does not answer
    /// with an empty reply when dispatch returns without one.
    pub(crate) fn reply_created(&self) {
        if let EntryState::Dispatching {
            reply_taken,
            commit_id,
            ..
        } = &mut *self.entry().state.lock()
        {
            if *commit_id == self.commit_id {
                *reply_taken = true;
            }
        }
    }
}

fn errno_header(unique: u64, errno: Errno) -> abi::fuse_out_header {
    abi::fuse_out_header {
        len: OUT_HEADER_SZ as u32,
        error: -errno.code(),
        unique,
    }
}

impl RingEntry {
    /// Writes a reply: header into `[0, 16)`, payload into `[gap, ..)`, then the trailer. A
    /// payload larger than the buffer, or `iov[0]` that is not a `fuse_out_header`, becomes an
    /// `EINVAL` reply, as `/dev/fuse` would make an oversized one.
    ///
    /// # Safety
    ///
    /// The caller is the entry's only writer (state `Committing`, or the ring thread right
    /// after a CQE) and no reference into the header or payload area is live.
    unsafe fn write_reply(&self, commit_id: u64, iov: &[IoSlice<'_>]) {
        let payload_len: usize = iov.iter().skip(1).map(|s| s.len()).sum();
        let header = iov.first().filter(|h| h.len() == OUT_HEADER_SZ);
        let payload_sz = u32::try_from(payload_len)
            .ok()
            .filter(|_| payload_len <= self.payload_cap);
        // `commit` already answered a malformed header, so only the payload can fail here
        let (Some(header), Some(payload_sz)) = (header, payload_sz) else {
            error!(
                "io_uring: reply of {payload_len} bytes exceeds the {} byte payload buffer; \
                 replying EINVAL",
                self.payload_cap
            );
            // SAFETY: the caller's guarantee.
            unsafe { self.write_errno(commit_id, Errno::EINVAL) };
            return;
        };
        let base = self.base.0.as_ptr();
        // SAFETY: the header fits in `in_out` and the payload fits in `payload_cap`; both
        // ranges lie inside the stride.
        unsafe {
            ptr::copy_nonoverlapping(header.as_ptr(), base, OUT_HEADER_SZ);
            let mut off = self.gap;
            for chunk in iov.iter().skip(1) {
                ptr::copy_nonoverlapping(chunk.as_ptr(), base.add(off), chunk.len());
                off += chunk.len();
            }
            ptr::write_unaligned(base.add(FLAGS_OFFSET).cast::<u64>(), 0);
            ptr::write_unaligned(base.add(PAYLOAD_SZ_OFFSET).cast::<u32>(), payload_sz);
        }
    }

    /// # Safety
    ///
    /// As for `write_reply`.
    unsafe fn write_errno(&self, commit_id: u64, errno: Errno) {
        let header = errno_header(commit_id, errno);
        // SAFETY: the caller's guarantee; a header-only iov always passes the size checks.
        unsafe { self.write_reply(commit_id, &[IoSlice::new(header.as_bytes())]) };
    }
}

/// `fuse_uring_cmd_req` at the front of the 80-byte area, the rest zero for 7.46.
fn cmd_bytes(qid: u16, commit_id: u64) -> [u8; 80] {
    let req = abi::fuse_uring_cmd_req {
        flags: 0,
        commit_id,
        qid,
        padding: [0; 6],
    };
    let mut cmd = [0u8; 80];
    cmd[..size_of::<abi::fuse_uring_cmd_req>()].copy_from_slice(req.as_bytes());
    cmd
}

/// `(qid, entry index)` to `user_data`; the index is the position in `Ring::entries`.
fn user_data(qid: u16, idx: u32) -> u64 {
    (u64::from(qid) << 32) | u64::from(idx)
}

fn decode(ud: u64) -> (u16, u32) {
    ((ud >> 32) as u16, ud as u32)
}

/// `opcode::UringCmd80` has no `len` setter, and REGISTER needs `len == 2` (the iovec count).
fn set_sqe_len(sqe: squeue::Entry128, len: u32) -> squeue::Entry128 {
    // SAFETY: Entry128 is repr(C), 128 bytes, and every bit pattern of its integer fields is
    // valid, so a round trip through a byte array to patch one field is sound.
    let mut raw: [u8; 128] = unsafe { std::mem::transmute(sqe) };
    raw[SQE_LEN_OFFSET..SQE_LEN_OFFSET + 4].copy_from_slice(&len.to_ne_bytes());
    // SAFETY: as above.
    unsafe { std::mem::transmute(raw) }
}

/// `io_uring_enter` errors that mean the ring itself is unusable, as opposed to one SQE.
fn is_ring_failure(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EBADF | libc::ENXIO | libc::EFAULT)
    )
}

impl Ring {
    /// Reserves the buffers and the wake eventfd for `depth` entries on each of `qids`.
    pub(crate) fn new(
        index: usize,
        mounted: bool,
        device: Arc<DevFuse>,
        qids: &[u16],
        depth: u32,
        payload_cap: usize,
    ) -> io::Result<Arc<Ring>> {
        let n = qids
            .len()
            .checked_mul(depth as usize)
            .filter(|n| *n > 0 && u32::try_from(*n).is_ok())
            .ok_or_else(|| io::Error::other("io_uring: invalid entry count"))?;
        let mem = RingMemory::new(n, payload_cap)?;
        let wake = EventFd::from_value_and_flags(0, EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK)
            .map_err(|err| io::Error::other(format!("creating the wake eventfd failed ({err})")))?;
        let entries = qids
            .iter()
            .flat_map(|&qid| std::iter::repeat_n(qid, depth as usize))
            .enumerate()
            .map(|(idx, qid)| {
                let base = mem.entry(idx);
                let iov = [
                    libc::iovec {
                        iov_base: base.as_ptr().cast(),
                        iov_len: HEADER_SZ,
                    },
                    libc::iovec {
                        // SAFETY: gap < stride, inside the entry's stride.
                        iov_base: unsafe { base.add(mem.gap()) }.as_ptr().cast(),
                        iov_len: mem.payload_cap(),
                    },
                ];
                RingEntry {
                    idx: idx as u32,
                    qid,
                    base: EntryPtr(base),
                    gap: mem.gap(),
                    payload_cap: mem.payload_cap(),
                    iov: EntryIov(iov),
                    state: Mutex::new(EntryState::Dead),
                }
            })
            .collect();
        Ok(Arc::new(Ring {
            index,
            mounted,
            device,
            ring_thread: OnceLock::new(),
            wake,
            live: Mutex::new(Live {
                in_kernel: 0,
                outstanding: 0,
                pending: Vec::new(),
                conn_dead: false,
                fatal: None,
                shutdown: false,
                abandon: false,
                exited: false,
            }),
            entries,
            mem: ManuallyDrop::new(mem),
            #[cfg(test)]
            hooks: test::RingHooks::default(),
        }))
    }

    /// Address space reserved for the entry buffers.
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.mem.len()
    }

    /// Tells the ring thread to leave once nothing is pending in the kernel, even while
    /// requests are still held by userspace; call after the connection ended.
    pub(crate) fn shutdown(&self) {
        self.live.lock().shutdown = true;
        if let Err(err) = self.wake.write(1) {
            error!("io_uring: eventfd write failed: {err}");
        }
    }

    /// Makes a thread still waiting for its handler return, as a dropped `from_fd` session's
    /// does, instead of serving until the connection ends. For a session that failed to start,
    /// mounted or not: a caller blocked in the mount keeps its unmount from ending the
    /// connection, so the registered commands must be cancelled for it to abort.
    pub(crate) fn abandon(&self) {
        self.live.lock().abandon = true;
    }

    fn register_sqe(&self, e: &RingEntry) -> squeue::Entry128 {
        let sqe = opcode::UringCmd80::new(
            types::Fd(self.device.as_raw_fd()),
            abi::fuse_uring_cmd::FUSE_IO_URING_CMD_REGISTER as u32,
        )
        .cmd(cmd_bytes(e.qid, 0))
        .addr(Some(e.iov.0.as_ptr() as u64))
        .build()
        .user_data(user_data(e.qid, e.idx));
        set_sqe_len(sqe, 2)
    }

    fn commit_sqe(&self, e: &RingEntry, commit_id: u64) -> squeue::Entry128 {
        opcode::UringCmd80::new(
            types::Fd(self.device.as_raw_fd()),
            abi::fuse_uring_cmd::FUSE_IO_URING_CMD_COMMIT_AND_FETCH as u32,
        )
        .cmd(cmd_bytes(e.qid, commit_id))
        .build()
        .user_data(user_data(e.qid, e.idx))
    }

    fn wake_sqe(&self) -> squeue::Entry128 {
        opcode::PollAdd::new(types::Fd(self.wake.as_raw_fd()), libc::POLLIN as u32)
            .multi(true)
            .build()
            .user_data(WAKE)
            .into()
    }

    /// Body of `fuser-ring-{r}`. `go` is released once the INIT reply was written,
    /// `registered` reports the REGISTER submit result back, `handler_rx` delivers the
    /// handler once the session runs.
    pub(crate) fn thread_main(
        self: Arc<Ring>,
        mut io: RingIo,
        go: mpsc::Receiver<()>,
        registered: mpsc::Sender<io::Result<()>>,
        handler_rx: mpsc::Receiver<Box<dyn FetchHandler>>,
    ) -> io::Result<()> {
        self.ring_thread.set(thread::current().id()).ok();
        if go.recv().is_err() {
            // Nothing was registered, so `in_kernel` is 0 and `Drop` unmaps
            return Ok(());
        }
        let reg = io.enable().and_then(|()| self.register_all(&mut io));
        let ok = reg.is_ok();
        let _ = registered.send(reg);
        if !ok {
            // The session fails and its unmount completes whatever earlier batches submitted
            return Ok(());
        }
        debug!(
            "io_uring: ring {} registered {} entries",
            self.index,
            self.entries.len()
        );
        // Early fetches are deferred task work until the first io_uring_enter in `serve`
        let mut handler: Box<dyn FetchHandler> = match handler_rx.recv() {
            Ok(h) => h,
            Err(_) if self.live.lock().abandon => {
                debug!(
                    "io_uring: ring {} abandoning {} registered commands; the session failed \
                     to start",
                    self.index,
                    self.live.lock().in_kernel
                );
                return Ok(());
            }
            Err(_) if self.mounted => {
                error!(
                    "io_uring: ring {} serving EIO until the connection ends; the session was \
                     dropped before it was run",
                    self.index
                );
                Box::new(|c: RingCommit, _: &[u8]| c.commit_errno(Errno::EIO))
            }
            Err(_) => {
                // Returning closes the ring fd, which cancels the commands and releases their
                // /dev/fuse references so the connection aborts as it does without a ring
                error!(
                    "io_uring: ring {} abandoning {} registered commands; the from_fd session \
                     was dropped before it was run",
                    self.index,
                    self.live.lock().in_kernel
                );
                return Ok(());
            }
        };
        debug!("io_uring: ring {} serving", self.index);
        let outcome = self.serve(&mut io, &mut *handler);
        let mut live = self.live.lock();
        if outcome.is_err() {
            live.exited = true;
        }
        debug!(
            "io_uring: ring {} exited, in_kernel={} outstanding={}",
            self.index, live.in_kernel, live.outstanding
        );
        match outcome {
            Err(e) => Err(e),
            Ok(()) => live.fatal.take().map_or(Ok(()), Err),
        }
    }

    /// Pushes one REGISTER per entry plus the eventfd poll and submits once.
    fn register_all(&self, io: &mut RingIo) -> io::Result<()> {
        self.live.lock().in_kernel = self.entries.len();
        for e in &self.entries {
            *e.state.lock() = EntryState::InKernel { last: 0 };
            io.push_or_submit(&self.register_sqe(e))?;
        }
        self.arm_wake(io)?;
        io.submit()?;
        Ok(())
    }

    fn arm_wake(&self, io: &mut RingIo) -> io::Result<()> {
        io.push_or_submit(&self.wake_sqe())
    }

    fn drain_eventfd(&self) {
        match self.wake.read() {
            Ok(_) | Err(nix::errno::Errno::EAGAIN) => {}
            Err(err) => debug!("io_uring: ring {} eventfd read failed: {err}", self.index),
        }
    }

    /// Pushes the COMMIT_AND_FETCH of every `Pending` entry. `Err` only for a ring-level
    /// failure; a per-entry failure retires the entry and continues.
    fn flush_pending(&self, io: &mut RingIo) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.inject(io)?;
        let pending = std::mem::take(&mut self.live.lock().pending);
        for idx in pending {
            let e = &self.entries[idx as usize];
            let commit_id = {
                let mut state = e.state.lock();
                match *state {
                    EntryState::Pending { commit_id } => {
                        *state = EntryState::InKernel { last: commit_id };
                        commit_id
                    }
                    ref other => panic!(
                        "io_uring: entry {idx} queued in pending is {other:?}; every queued index \
                         is Pending (the ring thread stops; the mapping is leaked if any command \
                         is still counted)"
                    ),
                }
            };
            if let Err(err) = io.push_or_submit(&self.commit_sqe(e, commit_id)) {
                if is_ring_failure(&err) {
                    return Err(err);
                }
                error!(
                    "io_uring: could not submit commit for unique {commit_id} on qid {}: {err}; \
                     the kernel request will not complete",
                    e.qid
                );
                self.retire(e, Some(err));
                continue;
            }
            #[cfg(test)]
            self.hooks.flushed(idx);
        }
        Ok(())
    }

    /// The command an `InKernel` entry has pending: `Some(0)` for REGISTER, else the
    /// commit id; `None` when the entry is not in the kernel, so its CQE is not ours to count.
    fn last_command(e: &RingEntry) -> Option<u64> {
        match *e.state.lock() {
            EntryState::InKernel { last } => Some(last),
            ref other => {
                error!(
                    "io_uring: CQE for qid {} entry {} which is {other:?}, not in the kernel",
                    e.qid, e.idx
                );
                None
            }
        }
    }

    /// Re-pushes the last command of an entry after `-EAGAIN` or `-EINTR`.
    fn resubmit(&self, io: &mut RingIo, e: &RingEntry, last: u64) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.resubmitted.lock().push((e.idx, last));
        let sqe = match last {
            0 => self.register_sqe(e),
            commit_id => self.commit_sqe(e, commit_id),
        };
        io.push_or_submit(&sqe)
    }

    /// The entry leaves the kernel for good.
    fn retire(&self, e: &RingEntry, err: Option<io::Error>) {
        let mut state = e.state.lock();
        let mut live = self.live.lock();
        live.kill(e, &mut state);
        dec(&mut live.in_kernel, e, "in-kernel");
        if let Some(err) = err {
            live.fatal.get_or_insert(err);
        }
    }

    /// The buffers are written; queues the entry for the ring thread.
    fn hand_off(&self, e: &RingEntry, commit_id: u64) {
        {
            let mut state = e.state.lock();
            let mut live = self.live.lock();
            if live.exited {
                live.kill(e, &mut state);
                drop(live);
                drop(state);
                debug!(
                    "io_uring: dropping reply for unique {commit_id} after ring {} exited",
                    self.index
                );
                return;
            }
            dec(&mut live.outstanding, e, "outstanding");
            *state = EntryState::Pending { commit_id };
            live.in_kernel += 1;
            live.pending.push(e.idx);
        }
        if self.ring_thread.get() != Some(&thread::current().id()) {
            if let Err(err) = self.wake.write(1) {
                // The commit stays queued; the next CQE-driven pass picks it up
                error!("io_uring: eventfd write failed: {err}");
            }
        }
    }

    /// Returns `Ok` on a clean drain with `live.exited` set, `Err` when the ring is unusable.
    ///
    /// The ring leaves once nothing is pending in the kernel and either the connection ended
    /// or the session shut down (requests still held by userspace are stranded by the kernel
    /// anyway), or a fatal error was recorded and no fetched request is still held, since
    /// leaving earlier would drop the replies of those requests and hang the applications
    /// behind them.
    fn serve(self: &Arc<Self>, io: &mut RingIo, handler: &mut dyn FetchHandler) -> io::Result<()> {
        let (mut wake_retried, mut wake_dead) = (false, false);
        loop {
            self.flush_pending(io)?;
            {
                let mut live = self.live.lock();
                let drained = live.conn_dead
                    || live.shutdown
                    || (live.fatal.is_some() && live.outstanding == 0);
                if live.in_kernel == 0 && drained {
                    live.exited = true;
                    return Ok(());
                }
            }
            #[cfg(test)]
            self.hooks
                .exit_checks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Once the eventfd poll is dead foreign commits cannot wake this thread, so the
            // wait is bounded and flush_pending runs on every pass
            match io.submit_and_wait(wake_dead) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) if wake_dead && e.raw_os_error() == Some(libc::ETIME) => continue,
                // The SQ was not consumed; reap what the CQ holds so it can be retried, and
                // give the kernel a moment since the CQ is usually empty on EAGAIN
                Err(e) if matches!(e.raw_os_error(), Some(libc::EBUSY | libc::EAGAIN)) => {
                    debug!("io_uring: ring {} enter failed ({e}); retrying", self.index);
                    thread::yield_now();
                }
                Err(e) => return Err(e),
            }
            let cqes: SmallVec<[(u64, i32, u32); 64]> = io
                .io
                .completion()
                .map(|c| (c.user_data(), c.result(), c.flags()))
                .collect();
            for (ud, res, flags) in cqes {
                if ud == WAKE {
                    let failed = if res < 0 {
                        #[cfg(test)]
                        self.hooks
                            .poll_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let err = io::Error::from_raw_os_error(-res);
                        if !wake_retried && self.arm_wake(io).is_ok() {
                            wake_retried = true;
                            warn!(
                                "io_uring: ring {} eventfd poll failed ({err}); re-armed once",
                                self.index
                            );
                            None
                        } else {
                            Some(err)
                        }
                    } else {
                        self.drain_eventfd();
                        if cqueue::more(flags) {
                            None
                        } else {
                            // The multishot poll ended; a failed re-arm degrades like a
                            // failed poll rather than ending the ring
                            match self.arm_wake(io) {
                                Ok(()) => None,
                                Err(e) if is_ring_failure(&e) => return Err(e),
                                Err(e) => Some(e),
                            }
                        }
                    };
                    if let Some(err) = failed {
                        error!(
                            "io_uring: ring {} eventfd poll failed ({err}); polling pending \
                             commits every 10 ms until the ring exits",
                            self.index
                        );
                        self.live.lock().fatal.get_or_insert(err);
                        wake_dead = true;
                    }
                    continue;
                }
                let (qid, idx) = decode(ud);
                let Some(e) = self.entries.get(idx as usize).filter(|e| e.qid == qid) else {
                    error!("io_uring: CQE for unknown entry qid={qid} idx={idx}");
                    #[cfg(test)]
                    self.hooks
                        .ignored
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                };
                let Some(last) = Self::last_command(e) else {
                    #[cfg(test)]
                    self.hooks
                        .ignored
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                };
                match res {
                    0 => self.handle_fetch(e, handler),
                    r if r == -libc::EAGAIN || r == -libc::EINTR => {
                        thread::yield_now();
                        if let Err(err) = self.resubmit(io, e, last) {
                            if is_ring_failure(&err) {
                                return Err(err);
                            }
                            self.retire(e, Some(err));
                        }
                    }
                    r if r == -libc::ENOTCONN || r == -libc::ECONNABORTED => {
                        self.live.lock().conn_dead = true;
                        self.retire(e, None);
                    }
                    r => self.fail_entry(e, r, last),
                }
            }
        }
    }

    /// A CQE that ends the entry: log what it means and retire it as fatal. `last` is the
    /// command that failed, 0 for REGISTER.
    fn fail_entry(&self, e: &RingEntry, res: i32, last: u64) {
        let err = if res > 0 {
            io::Error::other(format!("unexpected result {res}"))
        } else {
            io::Error::from_raw_os_error(-res)
        };
        match -res {
            libc::ENOENT => error!(
                "io_uring: commit for unknown commit_id {last} on qid {}; that queue has \
                 permanently lost one kernel entry",
                e.qid
            ),
            libc::ECANCELED => error!(
                "io_uring: qid {} entry {} cancelled; its submitting thread exited",
                e.qid, e.idx
            ),
            _ => error!("io_uring: qid {} entry {} failed: {err}", e.qid, e.idx),
        }
        let register_rejected =
            last == 0 && matches!(-res, libc::EINVAL | libc::EOPNOTSUPP | libc::EFAULT);
        if register_rejected && self.live.lock().fatal.is_none() {
            error!(
                "io_uring: the kernel rejected the registration of ring {} ({err}); the \
                 session ends once the ring's entries are back",
                self.index
            );
        }
        self.retire(e, Some(err));
    }

    /// A CQE with `res == 0`: stage, dispatch, and finish whatever dispatch left behind.
    fn handle_fetch(self: &Arc<Self>, e: &RingEntry, handler: &mut dyn FetchHandler) {
        // SAFETY: the CQE for this entry just arrived, so the kernel is done writing the
        // stride and no reference into it exists.
        let staged = match unsafe { stage_request(e.base.0, e.gap, e.payload_cap) } {
            Ok(staged) => staged,
            Err(StagingError::ZeroCommitId) => {
                error!("io_uring: fetched entry with commit_id 0 on qid {}", e.qid);
                self.retire(e, Some(io::Error::other("fetched entry with commit_id 0")));
                return;
            }
            Err(StagingError::Malformed {
                commit_id,
                in_len,
                payload_sz,
            }) => {
                error!(
                    "io_uring: malformed fetch on qid {} (len {in_len}, payload_sz {payload_sz}); \
                     replying EIO",
                    e.qid
                );
                // SAFETY: as above, the ring thread is the entry's only writer right now.
                unsafe { e.write_errno(commit_id, Errno::EIO) };
                // The entry stays counted in `in_kernel`; it goes straight back
                *e.state.lock() = EntryState::Pending { commit_id };
                self.live.lock().pending.push(e.idx);
                return;
            }
        };
        let commit_id = staged.commit_id;
        {
            let mut state = e.state.lock();
            *state = EntryState::Dispatching {
                direct_ok: staged.payload_sz == 0,
                reply_taken: false,
                commit_id,
            };
            let mut live = self.live.lock();
            dec(&mut live.in_kernel, e, "in-kernel");
            live.outstanding += 1;
        }
        {
            // SAFETY: `stage_request` made `[req, req + len)` one contiguous request inside
            // the stride; the slice ends with this block, before the entry is touched again.
            let request = unsafe { slice::from_raw_parts(staged.req.as_ptr(), staged.len) };
            let commit = RingCommit {
                ring: Arc::clone(self),
                idx: e.idx,
                commit_id,
            };
            handler.handle(commit, request);
        }
        let reply: Option<(Vec<u8>, u64)> = {
            let mut state = e.state.lock();
            match &mut *state {
                EntryState::Deferred { bytes, commit_id } => {
                    let reply = (std::mem::take(&mut bytes.0), *commit_id);
                    *state = EntryState::Committing;
                    Some(reply)
                }
                EntryState::Dispatching {
                    reply_taken: false, ..
                } => {
                    *state = EntryState::Committing;
                    let header = abi::fuse_out_header {
                        len: OUT_HEADER_SZ as u32,
                        error: 0,
                        unique: commit_id,
                    };
                    Some((header.as_bytes().to_vec(), commit_id))
                }
                EntryState::Dispatching {
                    reply_taken: true, ..
                } => {
                    *state = EntryState::Dispatched { commit_id };
                    None
                }
                // A reply already happened, or another thread is writing one right now
                EntryState::Pending { .. } | EntryState::Committing => None,
                other @ (EntryState::InKernel { .. }
                | EntryState::Dispatched { .. }
                | EntryState::Dead) => panic!(
                    "io_uring: entry {} is {other:?} right after dispatch; only the ring thread \
                     pushes SQEs, marks entries dispatched and marks them dead (the ring thread \
                     stops; the mapping is leaked if any command is still counted)",
                    e.idx
                ),
            }
        };
        if let Some((bytes, commit_id)) = reply {
            let (header, payload) = bytes.split_at(bytes.len().min(OUT_HEADER_SZ));
            // SAFETY: `Committing`, and the request slice is gone.
            unsafe { e.write_reply(commit_id, &[IoSlice::new(header), IoSlice::new(payload)]) };
            self.hand_off(e, commit_id);
        }
    }
}

impl Drop for Ring {
    /// Unmapping memory the kernel may still write into would corrupt whatever the allocator
    /// places there, so the mapping is only released once every command has completed.
    fn drop(&mut self) {
        let in_kernel = self.live.get_mut().in_kernel;
        if in_kernel == 0 {
            // SAFETY: dropped exactly once, here, and never used afterwards.
            unsafe { ManuallyDrop::drop(&mut self.mem) };
        } else {
            error!(
                "io_uring: leaking {} bytes of ring buffers because {in_kernel} commands are \
                 still pending in the kernel",
                self.mem.len()
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::fs::File;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::Sender;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;
    use crate::ll::AnyRequest;
    use crate::ll::Operation;
    use crate::ll::fuse_abi::fuse_opcode;
    use crate::uring::mem::COMMIT_ID_OFFSET;
    use crate::uring::mem::OP_IN_OFFSET;
    use crate::uring::mem::test::UNMAP_CHECK;
    use crate::uring::mem::test::is_mapped;
    use crate::uring::staging::test::in_header;

    /// Test-only observation and fault injection on the io_uring.
    #[derive(Default)]
    pub(super) struct IoHooks {
        /// Errno the next `submit` fails with instead of entering the kernel.
        fail_submit: Option<i32>,
        submits: usize,
        /// Errno `enable` fails with instead of enabling the ring.
        fail_enable: Option<i32>,
    }

    impl IoHooks {
        pub(super) fn before_submit(&mut self) -> io::Result<()> {
            self.submits += 1;
            match self.fail_submit.take() {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(()),
            }
        }

        pub(super) fn before_enable(&mut self) -> io::Result<()> {
            self.fail_enable
                .take()
                .map_or(Ok(()), |errno| Err(io::Error::from_raw_os_error(errno)))
        }
    }

    /// Test-only hooks into the ring thread's loop.
    #[derive(Default)]
    pub(super) struct RingHooks {
        /// Receives the index of every entry whose COMMIT_AND_FETCH `flush_pending` pushed.
        flushed: Mutex<Option<Sender<u32>>>,
        /// SQEs the ring thread pushes at the top of its next pass.
        inject: Mutex<Vec<squeue::Entry128>>,
        /// `WAKE` CQEs with a negative result seen so far.
        pub(super) poll_failed: AtomicUsize,
        /// `(idx, last command)` of every `resubmit`.
        pub(super) resubmitted: Mutex<Vec<(u32, u64)>>,
        /// CQEs dropped because they named no counted command.
        pub(super) ignored: AtomicUsize,
        /// Passes of `serve` that evaluated the exit test and stayed.
        pub(super) exit_checks: AtomicUsize,
    }

    impl RingHooks {
        pub(super) fn flushed(&self, idx: u32) {
            if let Some(tx) = &*self.flushed.lock() {
                tx.send(idx).unwrap();
            }
        }

        pub(super) fn inject(&self, io: &mut RingIo) -> io::Result<()> {
            for sqe in std::mem::take(&mut *self.inject.lock()) {
                io.push_or_submit(&sqe)?;
            }
            Ok(())
        }
    }

    fn sqe_bytes(sqe: squeue::Entry128) -> [u8; 128] {
        // SAFETY: as in `set_sqe_len`.
        unsafe { std::mem::transmute(sqe) }
    }

    fn sqe_from_bytes(raw: [u8; 128]) -> squeue::Entry128 {
        // SAFETY: as in `set_sqe_len`.
        unsafe { std::mem::transmute(raw) }
    }

    fn u16_at(b: &[u8], off: usize) -> u16 {
        u16::from_ne_bytes(b[off..off + 2].try_into().unwrap())
    }

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
    }

    fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// A device without a `uring_cmd` operation, so every command fails with `-EOPNOTSUPP`.
    /// Not `/dev/null`: since Linux 7.0 it answers `uring_cmd` with 0
    const NOT_FUSE: &str = "/dev/zero";

    fn not_fuse() -> Arc<DevFuse> {
        Arc::new(DevFuse(File::open(NOT_FUSE).unwrap()))
    }

    /// A ring of `n` entries on a non-FUSE device, one queue per entry
    fn fake_ring(n: u16, mounted: bool) -> Arc<Ring> {
        let qids: Vec<u16> = (0..n).collect();
        Ring::new(7, mounted, not_fuse(), &qids, 1, 8192).unwrap()
    }

    /// For tests that assert the mapping is gone after drop: a 1 GiB stride keeps the small
    /// mappings of other tests away from `base`. `None` when the host refuses the reservation
    fn big_ring(n: u16, mounted: bool) -> Option<Arc<Ring>> {
        let qids: Vec<u16> = (0..n).collect();
        match Ring::new(7, mounted, not_fuse(), &qids, 1, 1 << 30) {
            Ok(ring) => Some(ring),
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                eprintln!("skipping: cannot reserve {n} GiB of address space: {e}");
                None
            }
            Err(e) => panic!("Ring::new: {e}"),
        }
    }

    /// `None` when the environment forbids io_uring or the kernel predates the setup flags
    fn try_ring_io(sq: u32, cq: u32) -> Option<RingIo> {
        match RingIo::open(sq, cq) {
            Ok(io) => Some(io),
            Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)) => {
                eprintln!("skipping: io_uring_setup failed with {e}");
                None
            }
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) && flags_unsupported() => {
                eprintln!(
                    "skipping: io_uring_setup failed with {e}; SINGLE_ISSUER and DEFER_TASKRUN \
                     need Linux 6.1"
                );
                None
            }
            Err(e) => panic!("io_uring_setup: {e}"),
        }
    }

    /// Whether `io_uring_setup` refuses known-good sizes too, which tells a kernel without the
    /// setup flags apart from an `EINVAL` for the sizes under test
    fn flags_unsupported() -> bool {
        static PROBE: OnceLock<bool> = OnceLock::new();
        *PROBE.get_or_init(
            || matches!(RingIo::open(8, 16), Err(e) if e.raw_os_error() == Some(libc::EINVAL)),
        )
    }

    fn state_name(e: &RingEntry) -> &'static str {
        match &*e.state.lock() {
            EntryState::InKernel { .. } => "InKernel",
            EntryState::Dispatching { .. } => "Dispatching",
            EntryState::Deferred { .. } => "Deferred",
            EntryState::Dispatched { .. } => "Dispatched",
            EntryState::Committing => "Committing",
            EntryState::Pending { .. } => "Pending",
            EntryState::Dead => "Dead",
        }
    }

    fn last_command(e: &RingEntry) -> Option<u64> {
        match *e.state.lock() {
            EntryState::InKernel { last } => Some(last),
            _ => None,
        }
    }

    fn errno_of(err: &io::Error) -> Option<i32> {
        err.raw_os_error()
    }

    /// What `uring_cmd` on a file without that operation returns; kernels differ
    fn is_rejection(err: &io::Error) -> bool {
        matches!(
            errno_of(err),
            Some(libc::EOPNOTSUPP | libc::EINVAL | libc::ENOTTY)
        )
    }

    fn header_bytes(e: &RingEntry) -> [u8; HEADER_SZ] {
        // SAFETY: test-owned entry with no command pending.
        unsafe { ptr::read_unaligned(e.base.0.as_ptr().cast()) }
    }

    /// Writes what the kernel writes on fetch into a real entry
    fn fake_fetch(e: &RingEntry, unique: u64, opcode: fuse_opcode, op_in: &[u8], payload: &[u8]) {
        let len = (40 + op_in.len() + payload.len()) as u32;
        let header = in_header(len, opcode as u32, unique);
        let base = e.base.0.as_ptr();
        // SAFETY: test-owned entry with no command pending and no reference live.
        unsafe {
            ptr::copy_nonoverlapping(header.as_ptr(), base, header.len());
            ptr::copy_nonoverlapping(op_in.as_ptr(), base.add(OP_IN_OFFSET), op_in.len());
            ptr::write_unaligned(base.add(COMMIT_ID_OFFSET).cast::<u64>(), unique);
            ptr::write_unaligned(
                base.add(PAYLOAD_SZ_OFFSET).cast::<u32>(),
                payload.len() as u32,
            );
            ptr::copy_nonoverlapping(payload.as_ptr(), base.add(e.gap), payload.len());
        }
    }

    fn set_in_kernel(ring: &Ring, idx: usize, last: u64) {
        *ring.entries[idx].state.lock() = EntryState::InKernel { last };
        ring.live.lock().in_kernel += 1;
    }

    fn fake_dispatched(ring: &Arc<Ring>, idx: usize, commit_id: u64) -> RingCommit {
        *ring.entries[idx].state.lock() = EntryState::Dispatched { commit_id };
        ring.live.lock().outstanding += 1;
        RingCommit {
            ring: Arc::clone(ring),
            idx: idx as u32,
            commit_id,
        }
    }

    fn ok_header(unique: u64) -> abi::fuse_out_header {
        abi::fuse_out_header {
            len: 16,
            error: 0,
            unique,
        }
    }

    /// A handle whose commit is refused: `NotConnected` when `conn_dead`, else a duplicate
    pub(crate) fn refused_commit(conn_dead: bool) -> RingCommit {
        let ring = fake_ring(1, true);
        ring.live.lock().conn_dead = conn_dead;
        RingCommit {
            ring,
            idx: 0,
            commit_id: 7,
        }
    }

    /// A `Nop` whose CQE carries `res` (`IORING_NOP_INJECT_RESULT`, Linux 6.10+): `nop_flags`
    /// at byte 28, the result in `len` at byte 24. Older kernels ignore both fields
    fn nop_with_result(user_data: u64, res: i32) -> squeue::Entry128 {
        let nop: squeue::Entry128 = opcode::Nop::new().build().user_data(user_data).into();
        let mut raw = sqe_bytes(nop);
        raw[24..28].copy_from_slice(&(res as u32).to_ne_bytes());
        raw[28..32].copy_from_slice(&1u32.to_ne_bytes());
        sqe_from_bytes(raw)
    }

    /// Whether this kernel honours `IORING_NOP_INJECT_RESULT`; before 6.10 the Nop completes
    /// with 0 as if the flag were not there
    fn nop_results_supported(io: &mut RingIo) -> bool {
        io.push_or_submit(&nop_with_result(WAKE - 1, -42)).unwrap();
        io.io.submit_and_wait(1).unwrap();
        let res = io.io.completion().next().unwrap().result();
        match res {
            -42 => true,
            0 => {
                eprintln!("skipping: the kernel does not support IORING_NOP_INJECT_RESULT");
                false
            }
            r => panic!("nop result {r}"),
        }
    }

    /// Spawns `thread_main` on `ring` and drives it to the registered state
    struct Started {
        thread: thread::JoinHandle<io::Result<()>>,
        handler_tx: mpsc::Sender<Box<dyn FetchHandler>>,
        registered: mpsc::Receiver<io::Result<()>>,
        go: mpsc::Sender<()>,
    }

    fn start(ring: &Arc<Ring>, io: RingIo) -> Started {
        let (go, go_rx) = mpsc::channel();
        let (reg_tx, registered) = mpsc::channel();
        let (handler_tx, handler_rx) = mpsc::channel::<Box<dyn FetchHandler>>();
        let thread = {
            let ring = Arc::clone(ring);
            thread::spawn(move || ring.thread_main(io, go_rx, reg_tx, handler_rx))
        };
        Started {
            thread,
            handler_tx,
            registered,
            go,
        }
    }

    impl Started {
        fn registered(&self) {
            self.go.send(()).unwrap();
            self.registered
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn entry128_layout_and_len_patch() {
        assert_eq!(size_of::<squeue::Entry128>(), 128);
        let sqe = opcode::UringCmd80::new(types::Fd(5), 1)
            .cmd([0xAB; 80])
            .addr(Some(0x1122_3344_5566_7788))
            .build()
            .user_data(0x0102_0304_0506_0708);
        let before = sqe_bytes(sqe.clone());
        assert_eq!(u32_at(&before, SQE_LEN_OFFSET), 0);
        let after = sqe_bytes(set_sqe_len(sqe, 2));
        assert_eq!(u32_at(&after, SQE_LEN_OFFSET), 2);
        for (i, (a, b)) in before.iter().zip(after.iter()).enumerate() {
            if !(SQE_LEN_OFFSET..SQE_LEN_OFFSET + 4).contains(&i) {
                assert_eq!(a, b, "byte {i}");
            }
        }
        assert_eq!(after[0], 46, "IORING_OP_URING_CMD");
        assert_eq!(u32_at(&after, 4), 5, "fd");
        assert_eq!(u32_at(&after, 8), 1, "cmd_op");
        assert_eq!(u64_at(&after, 16), 0x1122_3344_5566_7788, "addr");
        assert_eq!(u64_at(&after, 32), 0x0102_0304_0506_0708, "user_data");
        assert_eq!(&after[48..128], &[0xAB; 80][..], "cmd");
    }

    #[test]
    fn user_data_round_trips_and_never_collides_with_wake() {
        for (qid, idx) in [(0, 0), (447, 3583), (u16::MAX, u32::MAX), (1, u32::MAX)] {
            let ud = user_data(qid, idx);
            assert_eq!(decode(ud), (qid, idx));
            assert_ne!(ud, WAKE);
        }
    }

    #[test]
    fn register_and_commit_sqe_encoding() {
        let ring = fake_ring(3, true);
        let e = &ring.entries[2];
        assert_eq!((e.qid, e.idx), (2, 2));
        let fd = ring.device.as_raw_fd() as u32;

        let reg = sqe_bytes(ring.register_sqe(e));
        assert_eq!(reg[0], 46);
        assert_eq!(reg[1], 0, "no IOSQE flags");
        assert_eq!(u32_at(&reg, 4), fd);
        assert_eq!(u32_at(&reg, 8), 1, "REGISTER");
        assert_eq!(u64_at(&reg, 16), e.iov.0.as_ptr() as u64);
        assert_eq!(u32_at(&reg, 24), 2, "len is the iovec count");
        assert_eq!(u64_at(&reg, 32), user_data(2, 2));
        // cmd: fuse_uring_cmd_req { flags 0, commit_id 0, qid 2 }, rest zero
        assert_eq!(u64_at(&reg, 48), 0);
        assert_eq!(u64_at(&reg, 56), 0);
        assert_eq!(u16_at(&reg, 64), 2);
        assert!(reg[66..128].iter().all(|b| *b == 0));
        assert_eq!(e.iov.0[0].iov_base, e.base.0.as_ptr().cast());
        assert_eq!(e.iov.0[0].iov_len, 288);
        assert_eq!(
            e.iov.0[1].iov_base as usize,
            e.base.0.as_ptr() as usize + e.gap
        );
        assert_eq!(e.iov.0[1].iov_len, ring.mem.payload_cap());
        assert!(ring.mem.payload_cap() >= 8192);
        assert_eq!(e.gap, page_size::get());
        assert_eq!(ring.reserved_bytes(), ring.mem.len());

        let commit = sqe_bytes(ring.commit_sqe(e, 0xDEAD_BEEF_0000_0042));
        assert_eq!(commit[0], 46);
        assert_eq!(u32_at(&commit, 4), fd);
        assert_eq!(u32_at(&commit, 8), 2, "COMMIT_AND_FETCH");
        assert_eq!(u64_at(&commit, 16), 0, "no addr");
        assert_eq!(u32_at(&commit, 24), 0, "no len");
        assert_eq!(u64_at(&commit, 32), user_data(2, 2));
        assert_eq!(u64_at(&commit, 48), 0);
        assert_eq!(u64_at(&commit, 56), 0xDEAD_BEEF_0000_0042);
        assert_eq!(u16_at(&commit, 64), 2);
        assert!(commit[66..128].iter().all(|b| *b == 0));

        let wake = sqe_bytes(ring.wake_sqe());
        assert_eq!(wake[0], 6, "IORING_OP_POLL_ADD");
        assert_eq!(u32_at(&wake, 4), ring.wake.as_raw_fd() as u32);
        assert_eq!(u32_at(&wake, 24) & 1, 1, "IORING_POLL_ADD_MULTI");
        assert_eq!(u32_at(&wake, 28), libc::POLLIN as u32, "poll32_events");
        assert_eq!(u64_at(&wake, 32), WAKE);
    }

    #[test]
    fn ring_new_rejects_empty_and_oversized_rings() {
        assert!(Ring::new(0, true, not_fuse(), &[], 1, 8192).is_err());
        assert!(Ring::new(0, true, not_fuse(), &[0, 1], 0, 8192).is_err());
        let all: Vec<u16> = (0..=u16::MAX).collect();
        assert!(Ring::new(0, true, not_fuse(), &all, u32::MAX, 8192).is_err());
    }

    #[test]
    fn sizes_follow_the_kernel_limits() {
        for entries in [1, 2, 3, 8, 9, 3584, 32768, 40_000, 100_000] {
            let (sq, cq) = ring_sizes(entries);
            assert!(sq.is_power_of_two(), "{entries}");
            assert!((8..=32768).contains(&sq), "{entries}");
            assert!(cq >= sq, "{entries}: cq {cq} < sq {sq}");
            assert!(cq <= 65536, "{entries}");
            assert!(cq as usize >= (2 * entries).min(65536), "{entries}");
        }
        assert_eq!(ring_sizes(2), (8, 8));
        assert_eq!(ring_sizes(3584), (4096, 8192));
        assert_eq!(ring_sizes(100_000), (32768, 65536));
    }

    /// The one test that fails rather than skips when io_uring is unavailable
    #[test]
    fn io_uring_is_available() {
        RingIo::open(8, 16).expect(
            "io_uring_setup failed (needs Linux 6.1 and no seccomp/sysctl ban); the other ring \
             tests are skipping",
        );
    }

    #[test]
    fn small_rings_open() {
        for entries in [1, 2, 3] {
            let (sq, cq) = ring_sizes(entries);
            if try_ring_io(sq, cq).is_none() {
                return;
            }
        }
    }

    #[test]
    fn enabled_ring_submits_only_for_the_enabling_thread() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        io.enable().unwrap();
        let (err, mut io) = thread::spawn(move || {
            let nop: squeue::Entry128 = opcode::Nop::new().build().user_data(WAKE - 1).into();
            io.push_or_submit(&nop).unwrap();
            (io.io.submit().unwrap_err(), io)
        })
        .join()
        .unwrap();
        assert_eq!(errno_of(&err), Some(libc::EEXIST), "{err}");
        assert_eq!(io.io.submit_and_wait(1).unwrap(), 1);
        let cqe = io.io.completion().next().unwrap();
        assert_eq!((cqe.user_data(), cqe.result()), (WAKE - 1, 0));
    }

    #[test]
    fn ring_rejects_submission_until_enabled() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        let nop: squeue::Entry128 = opcode::Nop::new().build().user_data(WAKE - 1).into();
        io.push_or_submit(&nop).unwrap();
        let err = io.io.submit().unwrap_err();
        assert_eq!(errno_of(&err), Some(libc::EBADFD), "{err}");
    }

    #[test]
    fn ring_mechanics_against_a_non_fuse_device() {
        let _serial = UNMAP_CHECK.lock();
        let Some(io) = try_ring_io(8, 16) else { return };
        let Some(ring) = big_ring(2, true) else {
            return;
        };
        let base = ring.mem.entry(0).as_ptr() as usize;
        let started = start(&ring, io);
        started.registered();
        started
            .handler_tx
            .send(Box::new(|_: RingCommit, _: &[u8]| {
                panic!("nothing is fetched from {NOT_FUSE}")
            }))
            .unwrap();
        let err = started.thread.join().unwrap().unwrap_err();
        assert!(is_rejection(&err), "{err}");
        let live = ring.live.lock();
        assert!(live.exited);
        assert_eq!(live.in_kernel, 0);
        assert_eq!(live.outstanding, 0);
        assert!(live.pending.is_empty());
        assert!(live.fatal.is_none(), "taken by thread_main");
        assert!(!live.conn_dead);
        drop(live);
        for e in &ring.entries {
            assert_eq!(state_name(e), "Dead");
        }
        assert!(ring.ring_thread.get().is_some());
        assert!(is_mapped(base));
        drop(ring);
        assert!(!is_mapped(base));
    }

    #[test]
    fn dropped_go_registers_nothing() {
        let _serial = UNMAP_CHECK.lock();
        let Some(io) = try_ring_io(8, 16) else { return };
        let Some(ring) = big_ring(2, true) else {
            return;
        };
        let base = ring.mem.entry(0).as_ptr() as usize;
        let started = start(&ring, io);
        drop(started.go);
        started.thread.join().unwrap().unwrap();
        assert!(
            started.registered.try_recv().is_err(),
            "nothing was registered"
        );
        assert_eq!(ring.live.lock().in_kernel, 0);
        drop(ring);
        assert!(!is_mapped(base));
    }

    #[test]
    fn failed_enable_registers_nothing() {
        let _serial = UNMAP_CHECK.lock();
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        let Some(ring) = big_ring(2, true) else {
            return;
        };
        let base = ring.mem.entry(0).as_ptr() as usize;
        io.hooks.fail_enable = Some(libc::EBADFD);
        let started = start(&ring, io);
        started.go.send(()).unwrap();
        let err = started
            .registered
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        assert_eq!(errno_of(&err), Some(libc::EBADFD));
        started.thread.join().unwrap().unwrap();
        assert_eq!(ring.live.lock().in_kernel, 0);
        for e in &ring.entries {
            assert_eq!(state_name(e), "Dead", "register_all never ran");
        }
        drop(ring);
        assert!(!is_mapped(base));
    }

    /// The commands stay counted, so the mapping is leaked on purpose
    #[test]
    fn dropped_from_fd_session_abandons_the_ring() {
        let Some(io) = try_ring_io(8, 16) else { return };
        let ring = fake_ring(2, false);
        let base = ring.mem.entry(0).as_ptr() as usize;
        let started = start(&ring, io);
        started.registered();
        drop(started.handler_tx);
        started.thread.join().unwrap().unwrap();
        assert_eq!(ring.live.lock().in_kernel, 2);
        drop(ring);
        assert!(is_mapped(base), "leaked on purpose");
    }

    /// The commands stay counted, so the mapping is leaked on purpose
    #[test]
    fn failed_start_abandons_a_registered_ring() {
        let Some(io) = try_ring_io(8, 16) else { return };
        let ring = fake_ring(2, true);
        let base = ring.mem.entry(0).as_ptr() as usize;
        let started = start(&ring, io);
        started.registered();
        ring.abandon();
        drop(started.handler_tx);
        started.thread.join().unwrap().unwrap();
        assert!(!ring.live.lock().exited, "serve never ran");
        assert_eq!(ring.live.lock().in_kernel, 2);
        drop(ring);
        assert!(is_mapped(base), "leaked on purpose");
    }

    /// A `Session::new` session dropped before `run` serves EIO until the connection ends
    #[test]
    fn dropped_mounted_session_drains() {
        let Some(io) = try_ring_io(8, 16) else { return };
        let ring = fake_ring(2, true);
        let started = start(&ring, io);
        started.registered();
        drop(started.handler_tx);
        let err = started.thread.join().unwrap().unwrap_err();
        assert!(is_rejection(&err), "{err}");
        assert!(ring.live.lock().exited);
        assert_eq!(ring.live.lock().in_kernel, 0);
    }

    #[test]
    fn push_or_submit_batches_when_the_queue_is_full() {
        let Some(mut io) = try_ring_io(8, 64) else {
            return;
        };
        io.enable().unwrap();
        let ring = fake_ring(20, true);
        ring.register_all(&mut io).unwrap();
        // 20 REGISTERs and the poll: the queue fills after 8 and 16, then the final submit
        assert_eq!(io.hooks.submits, 3);
        assert_eq!(io.io.submission().len(), 0);
        assert_eq!(ring.live.lock().in_kernel, 20);
        for e in &ring.entries {
            assert_eq!(last_command(e), Some(0));
        }
    }

    /// Runs `serve` on its own thread with `in_kernel` inflated by one so the ring never
    /// exits on its own; the test ends it by zeroing the count and waking the thread
    struct Served {
        ring: Arc<Ring>,
        thread: thread::JoinHandle<(io::Result<()>, RingIo)>,
        flushed: mpsc::Receiver<u32>,
    }

    impl Served {
        fn start(mut io: RingIo, ring: Arc<Ring>, poll_multishot: bool) -> Self {
            let (tx, flushed) = mpsc::channel();
            *ring.hooks.flushed.lock() = Some(tx);
            ring.live.lock().in_kernel = 1;
            let sqe: squeue::Entry128 =
                opcode::PollAdd::new(types::Fd(ring.wake.as_raw_fd()), libc::POLLIN as u32)
                    .multi(poll_multishot)
                    .build()
                    .user_data(WAKE)
                    .into();
            io.push_or_submit(&sqe).unwrap();
            let thread = {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    ring.ring_thread.set(thread::current().id()).ok();
                    io.enable().unwrap();
                    let mut handler = |_: RingCommit, _: &[u8]| panic!("nothing is fetched");
                    let outcome = ring.serve(&mut io, &mut handler);
                    (outcome, io)
                })
            };
            Self {
                ring,
                thread,
                flushed,
            }
        }

        /// Commits from a foreign thread and waits for the ring thread to flush it
        fn foreign_commit(&self, commit: RingCommit) {
            let header = ok_header(commit.commit_id);
            let expected = commit.idx;
            thread::spawn(move || commit.commit(&[IoSlice::new(header.as_bytes())]))
                .join()
                .unwrap()
                .unwrap();
            let idx = self.flushed.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(idx, expected);
        }

        fn wait_retired(&self, idx: usize) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while state_name(&self.ring.entries[idx]) != "Dead" {
                assert!(Instant::now() < deadline, "entry {idx} never retired");
                thread::sleep(Duration::from_millis(1));
            }
        }

        fn wake(&self) {
            self.ring.wake.write(1).unwrap();
        }

        fn finish(self) -> (io::Result<()>, RingIo) {
            {
                let mut live = self.ring.live.lock();
                live.in_kernel = 0;
                live.fatal.get_or_insert(io::Error::other("test over"));
            }
            self.wake();
            let (outcome, io) = self.thread.join().unwrap();
            assert!(self.ring.live.lock().exited);
            assert!(self.ring.live.lock().pending.is_empty());
            (outcome, io)
        }
    }

    #[test]
    fn eventfd_wakes_the_ring_thread() {
        let Some(io) = try_ring_io(8, 16) else { return };
        let ring = fake_ring(3, true);
        // A one-shot poll: its CQE lacks IORING_CQE_F_MORE, so the loop must re-arm
        let served = Served::start(io, ring, false);

        served.foreign_commit(fake_dispatched(&served.ring, 0, 41));
        assert!(
            served.flushed.try_recv().is_err(),
            "exactly one commit pushed"
        );
        served.wait_retired(0);
        // The commit went to a non-FUSE device, so it was rejected and the count is back to one
        assert_eq!(served.ring.live.lock().in_kernel, 1);
        assert_eq!(served.ring.live.lock().outstanding, 0);
        assert!(is_rejection(
            served.ring.live.lock().fatal.as_ref().unwrap()
        ));

        // The poll was re-armed (now multishot): a second foreign commit still wakes it
        served.foreign_commit(fake_dispatched(&served.ring, 1, 42));
        served.wait_retired(1);

        let bytes = header_bytes(&served.ring.entries[1]);
        assert_eq!(u32_at(&bytes, 0), 16);
        assert_eq!(u32_at(&bytes, 4), 0);
        assert_eq!(u64_at(&bytes, 8), 42);
        assert_eq!(u64_at(&bytes, FLAGS_OFFSET), 0);
        assert_eq!(u32_at(&bytes, PAYLOAD_SZ_OFFSET), 0);

        let (outcome, mut io) = served.finish();
        outcome.unwrap();
        assert!(io.io.submission().is_empty());
    }

    #[test]
    fn cancelled_wake_poll_degrades_to_timed_waits() {
        let Some(io) = try_ring_io(8, 16) else { return };
        let ring = fake_ring(3, true);
        let served = Served::start(io, ring, true);
        // The cancel's own CQE must not look like an entry
        let cancel = || -> squeue::Entry128 {
            opcode::AsyncCancel::new(WAKE)
                .build()
                .user_data(user_data(u16::MAX, u32::MAX - 1))
                .into()
        };
        let poll_failures = |n: usize| {
            let deadline = Instant::now() + Duration::from_secs(2);
            while served.ring.hooks.poll_failed.load(Ordering::Relaxed) < n {
                assert!(Instant::now() < deadline, "poll failure {n} never arrived");
                thread::sleep(Duration::from_millis(1));
            }
        };

        // The poll is re-armed once; a foreign commit still wakes
        served.ring.hooks.inject.lock().push(cancel());
        served.wake();
        poll_failures(1);
        assert!(
            served.ring.live.lock().fatal.is_none(),
            "one re-arm is not fatal"
        );
        served.foreign_commit(fake_dispatched(&served.ring, 0, 51));
        served.wait_retired(0);

        // The poll is now dead; the wait is timed and commits still flush
        served.ring.hooks.inject.lock().push(cancel());
        served.wake();
        poll_failures(2);
        served.foreign_commit(fake_dispatched(&served.ring, 1, 52));
        served.wait_retired(1);

        let (outcome, _io) = served.finish();
        outcome.unwrap();
    }

    /// Leaving earlier would drop the held reply
    #[test]
    fn fatal_does_not_exit_while_a_request_is_outstanding() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        let ring = fake_ring(1, true);
        let commit = fake_dispatched(&ring, 0, 61);
        ring.live.lock().fatal = Some(io::Error::other("preset"));
        io.push_or_submit(&ring.wake_sqe()).unwrap();
        let (tx, flushed) = mpsc::channel();
        *ring.hooks.flushed.lock() = Some(tx);
        let server = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                ring.ring_thread.set(thread::current().id()).ok();
                io.enable().unwrap();
                let mut handler = |_: RingCommit, _: &[u8]| {};
                ring.serve(&mut io, &mut handler)
            })
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while ring.hooks.exit_checks.load(Ordering::Relaxed) == 0 {
            assert!(
                Instant::now() < deadline,
                "serve never reached the exit test"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!server.is_finished(), "exited with a request outstanding");
        assert!(!ring.live.lock().exited);

        let header = ok_header(61);
        commit.commit(&[IoSlice::new(header.as_bytes())]).unwrap();
        assert_eq!(flushed.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        server.join().unwrap().unwrap();
        let live = ring.live.lock();
        assert!(live.exited);
        assert_eq!((live.in_kernel, live.outstanding), (0, 0));
        drop(live);
        assert_eq!(state_name(&ring.entries[0]), "Dead");
    }

    /// With every entry held by userspace nothing in the kernel can ever complete
    #[test]
    fn shutdown_ends_a_ring_whose_entries_are_all_held() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        let ring = fake_ring(2, true);
        let held = [fake_dispatched(&ring, 0, 61), fake_dispatched(&ring, 1, 62)];
        io.push_or_submit(&ring.wake_sqe()).unwrap();
        let server = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                ring.ring_thread.set(thread::current().id()).ok();
                io.enable().unwrap();
                let mut handler = |_: RingCommit, _: &[u8]| {};
                ring.serve(&mut io, &mut handler)
            })
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while ring.hooks.exit_checks.load(Ordering::Relaxed) == 0 {
            assert!(
                Instant::now() < deadline,
                "serve never reached the exit test"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!server.is_finished(), "exited with requests outstanding");

        let asked = Instant::now();
        ring.shutdown();
        while !server.is_finished() {
            assert!(
                asked.elapsed() < Duration::from_secs(2),
                "exit was not prompt"
            );
            thread::sleep(Duration::from_millis(1));
        }
        server.join().unwrap().unwrap();
        let live = ring.live.lock();
        assert!(live.exited && live.shutdown && !live.conn_dead);
        assert_eq!((live.in_kernel, live.outstanding), (0, 2));
        drop(live);
        // Late replies to the stranded requests are dropped without touching the buffers
        for commit in &held {
            let header = ok_header(commit.commit_id);
            commit.commit(&[IoSlice::new(header.as_bytes())]).unwrap();
        }
        assert_eq!(ring.live.lock().outstanding, 0);
        assert!(ring.live.lock().pending.is_empty());
        for e in &ring.entries {
            assert_eq!(state_name(e), "Dead");
            assert!(header_bytes(e).iter().all(|b| *b == 0));
        }
    }

    /// CQE results injected with `IORING_NOP_INJECT_RESULT`
    #[test]
    fn cqe_classification() {
        let Some(mut io) = try_ring_io(16, 32) else {
            return;
        };
        io.enable().unwrap();
        if !nop_results_supported(&mut io) {
            return;
        }
        let ring = fake_ring(6, true);
        for (idx, last) in [(0, 0), (1, 5), (2, 0), (3, 9), (4, 0), (5, 0)] {
            set_in_kernel(&ring, idx, last);
        }
        // Entries 0 and 5 hold a parseable request, so a wrongly accepted unknown CQE with
        // `res == 0` would reach the panicking handler instead of failing to stage
        fake_fetch(
            &ring.entries[0],
            100,
            fuse_opcode::FUSE_GETATTR,
            &[0; 16],
            &[],
        );
        fake_fetch(
            &ring.entries[5],
            105,
            fuse_opcode::FUSE_GETATTR,
            &[0; 16],
            &[],
        );
        io.push_or_submit(&ring.wake_sqe()).unwrap();
        let cqes = [
            (user_data(0, 0), -libc::EAGAIN),
            (user_data(1, 1), -libc::EINTR),
            (user_data(2, 2), -libc::ENOENT),
            (user_data(3, 3), -libc::ECANCELED),
            (user_data(4, 4), 7),
            // Unknown entries: index out of range, and valid indexes under the wrong qid
            (user_data(0, 6), 0),
            (user_data(u16::MAX, 0), 0),
            (user_data(0, 5), 0),
            (user_data(5, 5), -libc::ECONNABORTED),
        ];
        for (ud, res) in cqes {
            io.push_or_submit(&nop_with_result(ud, res)).unwrap();
        }
        let mut handler = |_: RingCommit, _: &[u8]| panic!("no entry was fetched");
        ring.ring_thread.set(thread::current().id()).ok();
        ring.serve(&mut io, &mut handler).unwrap();
        let live = ring.live.lock();
        assert!(live.exited);
        assert!(live.conn_dead);
        assert_eq!((live.in_kernel, live.outstanding), (0, 0));
        let fatal = live.fatal.as_ref().unwrap();
        assert!(
            is_rejection(fatal)
                || matches!(errno_of(fatal), Some(libc::ENOENT | libc::ECANCELED))
                || fatal.to_string() == "unexpected result 7",
            "{fatal}"
        );
        drop(live);
        for e in &ring.entries {
            assert_eq!(state_name(e), "Dead");
        }
        let mut resubmitted = ring.hooks.resubmitted.lock().clone();
        resubmitted.sort_unstable();
        assert_eq!(
            resubmitted,
            [(0, 0), (1, 5)],
            "REGISTER for 0, COMMIT_AND_FETCH for 1"
        );
        assert_eq!(
            ring.hooks.ignored.load(Ordering::Relaxed),
            3,
            "unknown CQEs dropped"
        );
    }

    #[test]
    fn cqe_for_an_entry_not_in_the_kernel_is_ignored() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        io.enable().unwrap();
        if !nop_results_supported(&mut io) {
            return;
        }
        let ring = fake_ring(2, true);
        set_in_kernel(&ring, 1, 0);
        // Entry 0 is Dispatched (held by the filesystem), with a parseable request in place
        let _held = fake_dispatched(&ring, 0, 200);
        fake_fetch(
            &ring.entries[0],
            200,
            fuse_opcode::FUSE_GETATTR,
            &[0; 16],
            &[],
        );
        io.push_or_submit(&ring.wake_sqe()).unwrap();
        io.push_or_submit(&nop_with_result(user_data(0, 0), 0))
            .unwrap();
        io.push_or_submit(&nop_with_result(user_data(0, 0), -libc::ENOENT))
            .unwrap();
        io.push_or_submit(&nop_with_result(user_data(1, 1), -libc::ENOTCONN))
            .unwrap();
        let mut handler = |_: RingCommit, _: &[u8]| panic!("no counted entry was fetched");
        ring.ring_thread.set(thread::current().id()).ok();
        ring.serve(&mut io, &mut handler).unwrap();
        let live = ring.live.lock();
        assert!(live.exited && live.conn_dead);
        assert_eq!((live.in_kernel, live.outstanding), (0, 1));
        assert!(live.fatal.is_none(), "the stray ENOENT was not classified");
        drop(live);
        assert_eq!(state_name(&ring.entries[0]), "Dispatched");
        assert_eq!(ring.hooks.ignored.load(Ordering::Relaxed), 2);
        ring.live.lock().outstanding = 0;
    }

    #[test]
    fn enotconn_is_a_clean_end() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        io.enable().unwrap();
        if !nop_results_supported(&mut io) {
            return;
        }
        let ring = fake_ring(2, true);
        set_in_kernel(&ring, 0, 0);
        set_in_kernel(&ring, 1, 3);
        io.push_or_submit(&ring.wake_sqe()).unwrap();
        io.push_or_submit(&nop_with_result(user_data(0, 0), -libc::ENOTCONN))
            .unwrap();
        io.push_or_submit(&nop_with_result(user_data(1, 1), -libc::ENOTCONN))
            .unwrap();
        let mut handler = |_: RingCommit, _: &[u8]| panic!("no entry was fetched");
        ring.ring_thread.set(thread::current().id()).ok();
        ring.serve(&mut io, &mut handler).unwrap();
        let live = ring.live.lock();
        assert!(live.exited && live.conn_dead);
        assert!(live.fatal.is_none());
        assert_eq!(live.in_kernel, 0);
    }

    #[test]
    fn fail_entry_keeps_the_first_error() {
        let ring = fake_ring(4, true);
        for idx in 0..4 {
            set_in_kernel(&ring, idx, 0);
        }
        ring.fail_entry(&ring.entries[0], -libc::ENOENT, 0);
        assert_eq!(state_name(&ring.entries[0]), "Dead");
        assert_eq!(ring.live.lock().in_kernel, 3);
        assert_eq!(
            errno_of(ring.live.lock().fatal.as_ref().unwrap()),
            Some(libc::ENOENT)
        );
        ring.fail_entry(&ring.entries[1], -libc::ECANCELED, 0);
        ring.fail_entry(&ring.entries[2], -libc::EINVAL, 0);
        ring.fail_entry(&ring.entries[3], 12, 0);
        assert_eq!(ring.live.lock().in_kernel, 0);
        assert_eq!(
            errno_of(ring.live.lock().fatal.as_ref().unwrap()),
            Some(libc::ENOENT)
        );
        for e in &ring.entries {
            assert_eq!(state_name(e), "Dead");
        }
        let ring = fake_ring(1, true);
        set_in_kernel(&ring, 0, 0);
        ring.fail_entry(&ring.entries[0], 12, 4);
        assert_eq!(
            ring.live.lock().fatal.as_ref().unwrap().to_string(),
            "unexpected result 12"
        );
        // A CQE for an entry that is not counted does not underflow the count
        ring.retire(&ring.entries[0], None);
        assert_eq!(ring.live.lock().in_kernel, 0);
    }

    /// The commit from inside the handler must not self-deadlock
    #[test]
    fn deferred_reply_is_written_after_dispatch() {
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let ring = fake_ring(1, true);
            ring.ring_thread.set(thread::current().id()).ok();
            let e = &ring.entries[0];
            fake_fetch(e, 9, fuse_opcode::FUSE_LOOKUP, &[], b"hello\0");
            set_in_kernel(&ring, 0, 0);

            let mut handler = |commit: RingCommit, request: &[u8]| {
                let req = AnyRequest::try_from(request).unwrap();
                assert_eq!(req.unique().0, 9);
                match req.operation().unwrap() {
                    Operation::Lookup(l) => assert_eq!(l.name().to_str().unwrap(), "hello"),
                    other => panic!("{other:?}"),
                }
                // Dispatching { direct_ok: false } while the name is borrowed
                assert_eq!(state_name(&commit.ring.entries[0]), "Dispatching");
                assert_eq!(commit.ring.live.lock().in_kernel, 0);
                assert_eq!(commit.ring.live.lock().outstanding, 1);
                let header = abi::fuse_out_header {
                    len: 16 + 8,
                    error: 0,
                    unique: 9,
                };
                commit
                    .commit(&[
                        IoSlice::new(header.as_bytes()),
                        IoSlice::new(b"abcd"),
                        IoSlice::new(b"efgh"),
                    ])
                    .unwrap();
                assert_eq!(state_name(&commit.ring.entries[0]), "Deferred");
                // Nothing was written yet: the request bytes are intact
                assert_eq!(&request[40..], b"hello\0");
            };
            ring.handle_fetch(e, &mut handler);

            assert_eq!(state_name(e), "Pending");
            let live = ring.live.lock();
            assert_eq!((live.in_kernel, live.outstanding), (1, 0));
            assert_eq!(live.pending, [0]);
            drop(live);
            let bytes = header_bytes(e);
            assert_eq!(u32_at(&bytes, 0), 24);
            assert_eq!(u32_at(&bytes, 4), 0);
            assert_eq!(u64_at(&bytes, 8), 9);
            assert_eq!(u32_at(&bytes, PAYLOAD_SZ_OFFSET), 8);
            // SAFETY: test-owned entry, no command pending.
            let payload = unsafe { slice::from_raw_parts(e.base.0.as_ptr().add(e.gap), 8) };
            assert_eq!(payload, b"abcdefgh");
            ring.live.lock().in_kernel = 0;
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("handle_fetch deadlocked or panicked");
    }

    #[test]
    fn direct_reply_and_reply_taken() {
        let ring = fake_ring(2, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let getattr_in = [0u8; 16];

        let e = &ring.entries[0];
        fake_fetch(e, 21, fuse_opcode::FUSE_GETATTR, &getattr_in, &[]);
        set_in_kernel(&ring, 0, 0);
        set_in_kernel(&ring, 1, 0);
        let mut handler = |commit: RingCommit, _: &[u8]| {
            let header = ok_header(21);
            commit.commit(&[IoSlice::new(header.as_bytes())]).unwrap();
            assert_eq!(state_name(&commit.ring.entries[0]), "Pending");
            // A second reply for the same fetch is refused
            let err = commit
                .commit(&[IoSlice::new(header.as_bytes())])
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Other);
            // A reply object for a fetch that is over changes nothing
            commit.reply_created();
            assert_eq!(state_name(&commit.ring.entries[0]), "Pending");
        };
        ring.handle_fetch(e, &mut handler);
        assert_eq!(state_name(e), "Pending");
        assert_eq!(ring.live.lock().pending, [0]);
        assert_eq!(ring.live.lock().in_kernel, 2);
        assert_eq!(ring.live.lock().outstanding, 0);
        // The ring thread's own commit did not touch the eventfd
        assert_eq!(ring.wake.read(), Err(nix::errno::Errno::EAGAIN));

        let e = &ring.entries[1];
        fake_fetch(e, 22, fuse_opcode::FUSE_GETATTR, &getattr_in, &[]);
        let (tx, rx) = mpsc::channel();
        let mut handler = |commit: RingCommit, _: &[u8]| {
            // A stale handle for an earlier fetch of this entry must not flip reply_taken
            RingCommit {
                ring: Arc::clone(&commit.ring),
                idx: commit.idx,
                commit_id: 2,
            }
            .reply_created();
            assert!(matches!(
                *commit.ring.entries[1].state.lock(),
                EntryState::Dispatching {
                    reply_taken: false,
                    ..
                }
            ));
            commit.reply_created();
            tx.send(commit).unwrap();
        };
        ring.handle_fetch(e, &mut handler);
        assert_eq!(state_name(e), "Dispatched");
        assert_eq!(ring.live.lock().in_kernel, 1);
        assert_eq!(ring.live.lock().outstanding, 1);
        // The retained reply object commits later, directly, from a foreign thread
        let commit = rx.recv().unwrap();
        thread::spawn(move || {
            let header = abi::fuse_out_header {
                len: 16,
                error: -5,
                unique: 22,
            };
            commit.commit(&[IoSlice::new(header.as_bytes())]).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(state_name(e), "Pending");
        assert_eq!(ring.live.lock().pending, [0, 1]);
        assert_eq!(ring.live.lock().in_kernel, 2);
        assert_eq!(ring.live.lock().outstanding, 0);
        assert_eq!(
            ring.wake.read(),
            Ok(1),
            "a foreign commit wakes the ring thread"
        );

        // Without a reply object the ring thread answers with an empty OK
        let e = &ring.entries[0];
        fake_fetch(e, 23, fuse_opcode::FUSE_GETATTR, &getattr_in, &[]);
        *e.state.lock() = EntryState::InKernel { last: 21 };
        ring.live.lock().pending.clear();
        let mut handler = |_: RingCommit, _: &[u8]| {};
        ring.handle_fetch(e, &mut handler);
        assert_eq!(state_name(e), "Pending");
        let bytes = header_bytes(e);
        assert_eq!(
            (u32_at(&bytes, 0), u32_at(&bytes, 4), u64_at(&bytes, 8)),
            (16, 0, 23)
        );
        ring.live.lock().in_kernel = 0;
    }

    #[test]
    fn committing_entry_is_left_to_its_committer() {
        let ring = fake_ring(1, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let e = &ring.entries[0];
        fake_fetch(e, 71, fuse_opcode::FUSE_GETATTR, &[0; 16], &[]);
        set_in_kernel(&ring, 0, 0);
        let mut handler = |commit: RingCommit, _: &[u8]| {
            *commit.ring.entries[0].state.lock() = EntryState::Committing;
        };
        ring.handle_fetch(e, &mut handler);
        assert_eq!(state_name(e), "Committing");
        let live = ring.live.lock();
        assert!(live.pending.is_empty());
        assert_eq!((live.in_kernel, live.outstanding), (0, 1));
        drop(live);
        // The header still holds the request, not a reply
        assert_eq!(u64_at(&header_bytes(e), 8), 71);
        ring.live.lock().outstanding = 0;
    }

    #[test]
    #[should_panic(expected = "right after dispatch")]
    fn dead_entry_after_dispatch_is_a_bug() {
        let ring = fake_ring(1, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let e = &ring.entries[0];
        fake_fetch(e, 72, fuse_opcode::FUSE_GETATTR, &[0; 16], &[]);
        set_in_kernel(&ring, 0, 0);
        let mut handler = |commit: RingCommit, _: &[u8]| {
            *commit.ring.entries[0].state.lock() = EntryState::Dead;
        };
        ring.handle_fetch(e, &mut handler);
    }

    #[test]
    fn oversized_or_malformed_reply_becomes_einval() {
        let ring = fake_ring(1, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let e = &ring.entries[0];
        let commit = fake_dispatched(&ring, 0, 31);
        let too_big = vec![1u8; e.payload_cap + 1];
        let header = abi::fuse_out_header {
            len: 16 + too_big.len() as u32,
            error: 0,
            unique: 31,
        };
        commit
            .commit(&[IoSlice::new(header.as_bytes()), IoSlice::new(&too_big)])
            .unwrap();
        let bytes = header_bytes(e);
        assert_eq!(u32_at(&bytes, 4) as i32, -libc::EINVAL);
        assert_eq!(u64_at(&bytes, 8), 31);
        assert_eq!(u32_at(&bytes, PAYLOAD_SZ_OFFSET), 0);
        assert_eq!(state_name(e), "Pending");

        // iov[0] that is not a fuse_out_header, direct
        let commit = fake_dispatched(&ring, 0, 32);
        commit.commit(&[IoSlice::new(b"short")]).unwrap();
        let bytes = header_bytes(e);
        assert_eq!(u32_at(&bytes, 4) as i32, -libc::EINVAL);
        assert_eq!(u64_at(&bytes, 8), 32);

        // The same during dispatch of a payload-bearing request: stashed as EINVAL, not as
        // sixteen bytes of header plus payload
        *e.state.lock() = EntryState::Dispatching {
            direct_ok: false,
            reply_taken: true,
            commit_id: 33,
        };
        let commit = RingCommit {
            ring: Arc::clone(&ring),
            idx: 0,
            commit_id: 33,
        };
        commit
            .commit(&[IoSlice::new(b"short"), IoSlice::new(&[0; 64])])
            .unwrap();
        match &*e.state.lock() {
            EntryState::Deferred {
                bytes,
                commit_id: 33,
            } => {
                assert_eq!(bytes.0.len(), 16);
                assert_eq!(bytes.0, errno_header(33, Errno::EINVAL).as_bytes());
            }
            other => panic!("{other:?}"),
        }
        *e.state.lock() = EntryState::Dead;
        ring.live.lock().in_kernel = 0;
    }

    #[test]
    fn malformed_fetch_is_answered_with_eio() {
        let ring = fake_ring(1, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let e = &ring.entries[0];
        // op_in_len 12 is not a multiple of 8
        fake_fetch(e, 61, fuse_opcode::FUSE_GETATTR, &[0; 12], &[]);
        set_in_kernel(&ring, 0, 0);
        let mut handler = |_: RingCommit, _: &[u8]| panic!("malformed requests are not dispatched");
        ring.handle_fetch(e, &mut handler);
        assert_eq!(state_name(e), "Pending");
        assert_eq!(ring.live.lock().in_kernel, 1, "stays counted");
        assert_eq!(ring.live.lock().pending, [0]);
        let bytes = header_bytes(e);
        assert_eq!(u32_at(&bytes, 4) as i32, -libc::EIO);
        assert_eq!(u64_at(&bytes, 8), 61);

        // commit_id 0 retires the entry instead
        fake_fetch(e, 0, fuse_opcode::FUSE_GETATTR, &[0; 16], &[]);
        *e.state.lock() = EntryState::InKernel { last: 0 };
        ring.handle_fetch(e, &mut handler);
        assert_eq!(state_name(e), "Dead");
        assert_eq!(ring.live.lock().in_kernel, 0);
        assert!(ring.live.lock().fatal.is_some());
    }

    #[test]
    fn late_commit_after_exit_is_dropped() {
        let Some(io) = try_ring_io(8, 16) else { return };
        let ring = fake_ring(2, true);
        let retained = RingCommit {
            ring: Arc::clone(&ring),
            idx: 0,
            commit_id: 99,
        };
        let started = start(&ring, io);
        started.registered();
        started
            .handler_tx
            .send(Box::new(|_: RingCommit, _: &[u8]| {}))
            .unwrap();
        assert!(started.thread.join().unwrap().is_err());
        assert!(ring.live.lock().exited);

        let header = ok_header(99);
        retained.commit(&[IoSlice::new(header.as_bytes())]).unwrap();
        retained.commit_errno(Errno::EIO);
        let live = ring.live.lock();
        assert!(live.pending.is_empty());
        assert_eq!((live.in_kernel, live.outstanding), (0, 0));
        drop(live);
        assert_eq!(state_name(&ring.entries[0]), "Dead");
        // The buffers were not touched
        assert!(header_bytes(&ring.entries[0]).iter().all(|b| *b == 0));
    }

    /// `live` is held, not `state`, because `live` is the lock the exit decision takes
    #[test]
    fn commit_racing_the_exit_is_never_lost() {
        let mut landed = 0;
        for round in 0..20 {
            let Some(mut io) = try_ring_io(8, 16) else {
                return;
            };
            let ring = fake_ring(1, true);
            let commit = fake_dispatched(&ring, 0, 70);
            ring.live.lock().conn_dead = true;
            io.push_or_submit(&ring.wake_sqe()).unwrap();
            let (tx, flushed) = mpsc::channel();
            *ring.hooks.flushed.lock() = Some(tx);
            let held = ring.live.lock();
            let server = {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    ring.ring_thread.set(thread::current().id()).ok();
                    io.enable().unwrap();
                    let mut handler = |_: RingCommit, _: &[u8]| {};
                    ring.serve(&mut io, &mut handler)
                })
            };
            let committer = thread::spawn(move || {
                let header = ok_header(70);
                commit.commit(&[IoSlice::new(header.as_bytes())])
            });
            // Both threads now block on `live`; whichever wins, the outcome is the same
            thread::sleep(Duration::from_millis(if round % 2 == 0 { 5 } else { 0 }));
            drop(held);
            committer.join().unwrap().unwrap();
            server.join().unwrap().unwrap();
            let live = ring.live.lock();
            assert!(live.exited);
            assert_eq!((live.in_kernel, live.outstanding), (0, 0), "round {round}");
            assert!(live.pending.is_empty(), "round {round}");
            drop(live);
            assert_eq!(state_name(&ring.entries[0]), "Dead", "round {round}");
            if flushed.try_recv().is_ok() {
                landed += 1;
            }
        }
        eprintln!("commit landed before the exit in {landed} of 20 rounds");
    }

    #[test]
    fn flush_pending_failures() {
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        let ring = fake_ring(2, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let fill_queue = |io: &mut RingIo| {
            let nop: squeue::Entry128 = opcode::Nop::new().build().user_data(WAKE - 1).into();
            // SAFETY: a Nop names no buffers.
            while unsafe { io.io.submission().push(&nop) }.is_ok() {}
            assert!(io.io.submission().is_full());
        };
        let queue = |idx: u32, commit_id: u64| {
            *ring.entries[idx as usize].state.lock() = EntryState::Pending { commit_id };
            let mut live = ring.live.lock();
            live.pending.push(idx);
            live.in_kernel += 1;
        };

        // The room-making submit fails per entry: retired, counted out, first error kept
        fill_queue(&mut io);
        queue(0, 81);
        io.hooks.fail_submit = Some(libc::EBUSY);
        ring.flush_pending(&mut io).unwrap();
        assert_eq!(state_name(&ring.entries[0]), "Dead");
        let live = ring.live.lock();
        assert_eq!(live.in_kernel, 0);
        assert!(live.pending.is_empty());
        assert_eq!(errno_of(live.fatal.as_ref().unwrap()), Some(libc::EBUSY));
        drop(live);
        assert!(io.io.submission().is_full(), "the SQE was never pushed");

        // A ring-level errno from the room-making submit ends the loop with the entry neither
        // pushed nor retired, which is why the mapping is then leaked
        queue(1, 82);
        io.hooks.fail_submit = Some(libc::EBADF);
        let err = ring.flush_pending(&mut io).unwrap_err();
        assert_eq!(errno_of(&err), Some(libc::EBADF));
        let live = ring.live.lock();
        assert_eq!(live.in_kernel, 1);
        assert!(live.pending.is_empty());
        drop(live);
        assert_eq!(last_command(&ring.entries[1]), Some(82));

        // With room in the queue no submit happens at all: the SQE waits for the next wait
        let Some(mut io) = try_ring_io(8, 16) else {
            return;
        };
        let ring = fake_ring(1, true);
        *ring.entries[0].state.lock() = EntryState::Pending { commit_id: 83 };
        ring.live.lock().pending.push(0);
        ring.live.lock().in_kernel = 1;
        io.hooks.fail_submit = Some(libc::EBUSY);
        ring.flush_pending(&mut io).unwrap();
        assert_eq!(last_command(&ring.entries[0]), Some(83));
        assert_eq!(io.io.submission().len(), 1);
        assert_eq!(
            io.hooks.fail_submit,
            Some(libc::EBUSY),
            "no submit was attempted"
        );
        assert_eq!(ring.live.lock().in_kernel, 1);
        ring.live.lock().in_kernel = 0;
    }

    #[test]
    fn drop_unmaps_only_when_nothing_is_in_the_kernel() {
        let _serial = UNMAP_CHECK.lock();
        let Some(ring) = big_ring(2, true) else {
            return;
        };
        let base = ring.mem.entry(0).as_ptr() as usize;
        ring.live.lock().in_kernel = 1;
        drop(ring);
        assert!(is_mapped(base), "leaked while pending");

        let Some(ring) = big_ring(2, true) else {
            return;
        };
        let base = ring.mem.entry(0).as_ptr() as usize;
        assert!(is_mapped(base));
        drop(ring);
        assert!(!is_mapped(base));
    }

    #[test]
    fn write_errno_and_hand_off_then_duplicate_commit_errno() {
        let ring = fake_ring(1, true);
        ring.ring_thread.set(thread::current().id()).ok();
        let e = &ring.entries[0];
        *e.state.lock() = EntryState::Committing;
        ring.live.lock().outstanding = 1;
        let commit = RingCommit {
            ring: Arc::clone(&ring),
            idx: 0,
            commit_id: 91,
        };
        commit.write_errno_and_hand_off(Errno::EIO);
        let bytes = header_bytes(e);
        assert_eq!(u32_at(&bytes, 0), 16);
        assert_eq!(u32_at(&bytes, 4) as i32, -libc::EIO);
        assert_eq!(u64_at(&bytes, 8), 91);
        assert_eq!(u32_at(&bytes, PAYLOAD_SZ_OFFSET), 0);
        assert_eq!(state_name(e), "Pending");
        assert_eq!(ring.live.lock().pending, [0]);
        let live = ring.live.lock();
        assert_eq!((live.in_kernel, live.outstanding), (1, 0));
        drop(live);

        // A second errno reply is refused without touching anything
        commit.commit_errno(Errno::ENOENT);
        assert_eq!(header_bytes(e), bytes);
        assert_eq!(state_name(e), "Pending");
        assert_eq!(ring.live.lock().pending, [0]);
        assert_eq!(ring.live.lock().in_kernel, 1);
        let header = ok_header(91);
        let err = commit
            .commit(&[IoSlice::new(header.as_bytes())])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "duplicate reply");
        // Once the connection is gone the same refusal is a late reply
        ring.live.lock().conn_dead = true;
        let err = commit
            .commit(&[IoSlice::new(header.as_bytes())])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        ring.live.lock().conn_dead = false;

        // commit_errno from Dispatched writes the header
        *e.state.lock() = EntryState::Dispatched { commit_id: 91 };
        ring.live.lock().outstanding = 1;
        ring.live.lock().pending.clear();
        commit.commit_errno(Errno::ENOENT);
        assert_eq!(u32_at(&header_bytes(e), 4) as i32, -libc::ENOENT);
        assert_eq!(state_name(e), "Pending");
        assert_eq!(ring.live.lock().in_kernel, 2);
        // A stale handle for an earlier fetch of the same entry is refused too
        *e.state.lock() = EntryState::Dispatched { commit_id: 92 };
        commit.commit_errno(Errno::ENOENT);
        assert_eq!(state_name(e), "Dispatched");
        *e.state.lock() = EntryState::Dead;
        ring.live.lock().in_kernel = 0;
    }

    #[test]
    fn debug_output_names_states_without_payloads() {
        let ring = fake_ring(1, true);
        let commit = RingCommit {
            ring,
            idx: 0,
            commit_id: 5,
        };
        assert_eq!(
            format!("{commit:?}"),
            "RingCommit { ring: 7, idx: 0, commit_id: 5 }"
        );
        let deferred = EntryState::Deferred {
            bytes: ReplyBytes(vec![0xAB; 4096]),
            commit_id: 8,
        };
        assert_eq!(
            format!("{deferred:?}"),
            "Deferred { bytes: 4096 bytes, commit_id: 8 }"
        );
        assert_eq!(
            format!("{:?}", EntryState::InKernel { last: 0 }),
            "InKernel { last: 0 }"
        );
    }
}
