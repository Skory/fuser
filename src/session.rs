//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::thread::{self};

use log::debug;
use log::error;
use log::info;
use log::warn;
use nix::unistd::Uid;
use nix::unistd::geteuid;
use parking_lot::Mutex;

use crate::Errno;
use crate::Filesystem;
use crate::KernelConfig;
use crate::MountOption;
use crate::ReplyEmpty;
use crate::Request;
use crate::channel::Channel;
use crate::channel::ChannelSender;
use crate::dev_fuse::DevFuse;
use crate::ll;
use crate::ll::Operation;
use crate::ll::ResponseErrno;
use crate::ll::Version;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi as abi;
use crate::ll::reply::Response;
use crate::mnt::Mount;
use crate::mnt::mount_options::Config;
use crate::mnt::mount_options::check_option_conflicts;
use crate::notify::Notifier;
use crate::read_buf::FuseReadBuf;
use crate::reply::Reply;
use crate::reply::ReplyRaw;
use crate::reply::ReplySender;
use crate::request::RequestWithSender;
#[cfg(all(feature = "io-uring", target_os = "linux"))]
use crate::uring::RingSet;
#[cfg(all(feature = "io-uring", target_os = "linux"))]
use crate::uring::ring::RingCommit;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub(crate) const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// The minimum write size the kernel will honor: process_init_reply() in the
/// kernel's fs/fuse/inode.c clamps a smaller negotiated max_write up to 4096,
/// so advertising less would not stop larger write requests from arriving.
pub(crate) const MIN_WRITE_SIZE: usize = 4096;

/// The error `run` ends with when a session thread panicked.
const THREAD_PANICKED: &str = "event loop thread panicked";

#[derive(Default, Debug, Eq, PartialEq, Clone, Copy)]
/// How requests should be filtered based on the calling UID.
pub enum SessionACL {
    /// Allow requests from any user. Corresponds to the `allow_other` mount option.
    All,
    /// Allow requests from root. Corresponds to the `allow_root` mount option.
    RootAndOwner,
    /// Allow requests from the owning UID. This is FUSE's default mode of operation.
    #[default]
    Owner,
}

impl SessionACL {
    /// Returns the mount option string for kernel/fusermount/libfuse paths.
    /// Both `All` and `RootAndOwner` map to `allow_other` - the kernel only
    /// understands `allow_other`, and fuser enforces the root-only restriction internally.
    #[allow(dead_code)]
    pub(crate) fn to_mount_option(self) -> Option<&'static str> {
        match self {
            SessionACL::All | SessionACL::RootAndOwner => Some("allow_other"),
            SessionACL::Owner => None,
        }
    }
}

/// Calls `destroy` on drop.
#[derive(Debug)]
pub(crate) struct FilesystemHolder<FS: Filesystem> {
    pub(crate) fs: Option<FS>,
}

impl<FS: Filesystem> FilesystemHolder<FS> {
    fn destroy(&mut self) {
        if let Some(mut fs) = self.fs.take() {
            fs.destroy();
        }
    }
}

impl<FS: Filesystem> Drop for FilesystemHolder<FS> {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[derive(Debug)]
struct UmountOnDrop {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl UmountOnDrop {
    fn umount(&self) -> io::Result<()> {
        if let Some(mount) = self.mount.lock().take() {
            mount.umount()?;
        }
        Ok(())
    }
}

impl Drop for UmountOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.umount() {
            warn!("Failed to umount filesystem: {}", e);
        }
    }
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations. None after `destroy` called.
    pub(crate) filesystem: FilesystemHolder<FS>,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: UmountOnDrop,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement `allow_root` and `auto_unmount`
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: Uid,
    /// FUSE protocol version, as reported by the kernel.
    /// The field is set to `Some` when the init message is received.
    pub(crate) proto_version: Option<Version>,
    /// Capabilities agreed with the kernel during init. Some request layouts depend on
    /// them, so the event loops need them to parse correctly
    pub(crate) negotiated: InitFlags,
    /// Everything the kernel advertised during init, whether or not it was requested.
    /// Some operations are honoured by the kernel without being negotiated, so this,
    /// not `negotiated`, says whether the kernel can perform them
    pub(crate) kernel_capabilities: InitFlags,
    pub(crate) config: Config,
    /// The io_uring rings, when the kernel serves this session over them. Declared after
    /// `mount` so that the unmount, which completes their kernel commands, happens first.
    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    ring: Option<RingSet>,
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    /// # Errors
    /// Returns an error if the options are incorrect, or if the fuse device can't be mounted.
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &Config,
    ) -> io::Result<Session<FS>> {
        check_option_conflicts(options)?;
        validate_transport(options)?;

        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther, return an error
        // because fusermount needs allow_root or allow_other to handle the auto_unmount option
        if options.mount_options.contains(&MountOption::AutoUnmount)
            && options.acl == SessionACL::Owner
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("auto_unmount requires acl != Owner, got: {:?}", options.acl),
            ));
        }
        let (file, mount) = Mount::new(mountpoint, &options.mount_options, options.acl)?;

        let ch = Channel::new(file);

        let mut session = Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch,
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(Some(mount))),
            },
            allowed: options.acl,
            session_owner: geteuid(),
            proto_version: None,
            negotiated: InitFlags::empty(),
            kernel_capabilities: InitFlags::empty(),
            config: options.clone(),
            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            ring: None,
        };

        session.handshake()?;

        Ok(session)
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(
        filesystem: FS,
        fd: OwnedFd,
        acl: SessionACL,
        config: Config,
    ) -> io::Result<Self> {
        validate_transport(&config)?;
        let ch = Channel::new(Arc::new(DevFuse(File::from(fd))));
        let mut session = Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch,
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(None)),
            },
            allowed: acl,
            session_owner: geteuid(),
            proto_version: None,
            negotiated: InitFlags::empty(),
            kernel_capabilities: InitFlags::empty(),
            config,
            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            ring: None,
        };

        session.handshake()?;

        Ok(session)
    }

    /// Run the session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the session is waited for, so that
    /// `Filesystem::destroy` has run when drop returns - except in the cases documented
    /// on [`BackgroundSession`], where the session thread is detached instead.
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        let sender = self.ch.sender();
        let fuse_device = self.ch.device();
        let kernel_capabilities = self.kernel_capabilities;
        let kernel_abi = self.proto_version;
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *self.mount.mount.lock());
        let guard = thread::Builder::new()
            .name("fuser-bg".to_string())
            .spawn(move || self.run())?;
        Ok(BackgroundSession {
            guard: Some(guard),
            sender,
            fuse_device,
            mount,
            kernel_capabilities,
            kernel_abi,
        })
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    /// # Errors
    /// Returns any final error when the session comes to an end.
    pub fn run(self) -> io::Result<()> {
        let Session {
            filesystem,
            ch,
            mount: _do_not_umount_yet,
            allowed,
            session_owner,
            proto_version,
            negotiated,
            kernel_capabilities,
            config,
            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            ring,
        } = self;

        let mut filesystem = Arc::new(filesystem);
        let event_loop = |thread_name: String, ch: Channel| SessionEventLoop {
            thread_name,
            filesystem: filesystem.clone(),
            ch,
            allowed,
            session_owner,
            negotiated,
            kernel_capabilities,
            kernel_abi: proto_version,
        };

        #[cfg(all(feature = "io-uring", target_os = "linux"))]
        let reply = match ring {
            Some(ring) => serve_ring(ring, ch, &config, event_loop),
            None => serve_channels(ch, &config, event_loop),
        };
        #[cfg(not(all(feature = "io-uring", target_os = "linux")))]
        let reply = serve_channels(ch, &config, event_loop);

        let Some(filesystem) = Arc::get_mut(&mut filesystem) else {
            // Only a panic ends the join early; the threads still running hold references
            // and destroy runs when the last of them exits
            reply?;
            return Err(io::Error::other(
                "BUG: must have one refcount for filesystem",
            ));
        };

        filesystem.destroy();

        reply
    }

    fn handshake(&mut self) -> io::Result<()> {
        let mut buf = FuseReadBuf::new();
        let buf = buf.as_mut();

        loop {
            // Read the init request from the kernel
            let size = match self.ch.receive_retrying(buf) {
                Ok(size) => size,
                Err(nix::errno::Errno::ENODEV | nix::errno::Errno::ECONNABORTED) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "FUSE device disconnected during handshake",
                    ));
                }
                Err(err) => return Err(err.into()),
            };

            // Parse the request
            let request = match ll::AnyRequest::try_from(&buf[..size]) {
                Ok(request) => request,
                Err(err) => {
                    error!("{err}");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()));
                }
            };

            // Extract the init operation
            let op = match request.operation() {
                Ok(op) => op,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to parse FUSE operation",
                    ));
                }
            };

            let init = match op {
                ll::Operation::Init(init) => init,
                _ => {
                    error!("Received non-init FUSE operation before init: {}", request);
                    // Send error response and return error - non-init during handshake is invalid
                    <ReplyRaw as Reply>::new(
                        request.unique(),
                        ReplySender::Channel(self.ch.sender()),
                    )
                    .send_ll(&ResponseErrno(ll::Errno::EIO));
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Received non-init FUSE operation during handshake",
                    ));
                }
            };

            let v = init.version();
            if v.0 > abi::FUSE_KERNEL_VERSION {
                // Kernel has a newer major version than we support.
                // Send our version and wait for a second INIT request with a compatible version.
                debug!(
                    "INIT: Kernel version {} > our version {}, sending our version and waiting for next init",
                    v.0,
                    abi::FUSE_KERNEL_VERSION
                );
                let response = init.reply_version_only();
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&response);
                continue;
            }

            // We don't support ABI versions before 7.6
            if v < Version(7, 6) {
                error!("Unsupported FUSE ABI version {v}");
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&ResponseErrno(ll::Errno::EPROTO));
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Unsupported FUSE ABI version {v}"),
                ));
            }

            let mut config = KernelConfig::new(
                init.capabilities(),
                init.max_readahead(),
                v,
                self.config
                    .mount_options
                    .contains(&MountOption::DefaultPermissions),
                self.allowed,
            );

            // Call filesystem init method and give it a chance to return an error
            let Some(filesystem) = &mut self.filesystem.fs else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Bug: filesystem must be initialized during handshake",
                ));
            };
            let res = filesystem.init(Request::ref_cast(request.header()), &mut config);
            if let Err(error) = res {
                let errno = Errno::from_i32(error.raw_os_error().unwrap_or(0));
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&ResponseErrno(errno));
                return Err(error);
            }

            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            if self.config.io_uring {
                if init.capabilities().contains(InitFlags::FUSE_OVER_IO_URING) {
                    match self.create_rings(&config) {
                        Ok(ring) => {
                            config.enable_io_uring();
                            self.ring = Some(ring);
                        }
                        Err(err) => warn!("io_uring requested but {err}; using /dev/fuse"),
                    }
                } else {
                    warn!(
                        "io_uring requested but the kernel did not advertise FUSE_OVER_IO_URING \
                         (fuse.enable_uring=N or kernel < 6.14); using /dev/fuse"
                    );
                }
            }

            // Remember the ABI version supported by kernel and mark the session initialized.
            self.proto_version = Some(v);
            self.negotiated = init.capabilities() & config.requested;
            self.kernel_capabilities = init.capabilities();

            // Log capability status for debugging
            for bit in 0..64 {
                let bitflags = InitFlags::from_bits_retain(1 << bit);
                if bitflags == InitFlags::FUSE_INIT_EXT {
                    continue;
                }
                let bitflag_is_known = InitFlags::all().contains(bitflags);
                let kernel_supports = init.capabilities().contains(bitflags);
                let we_requested = config.requested.contains(bitflags);
                // On macOS, there's a clash between linux and macOS constants,
                // so we pick macOS ones (last).
                let name = if let Some((name, _)) = bitflags.iter_names().last() {
                    Cow::Borrowed(name)
                } else {
                    Cow::Owned(format!("(1 << {bit})"))
                };
                if we_requested && kernel_supports {
                    debug!("capability {name} enabled")
                } else if we_requested {
                    debug!("capability {name} not supported by kernel")
                } else if kernel_supports {
                    debug!("capability {name} not requested by client")
                } else if bitflag_is_known {
                    debug!("capability {name} not supported nor requested")
                }
            }

            // Reply with our desired version and settings.
            debug!(
                "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                abi::FUSE_KERNEL_VERSION,
                abi::FUSE_KERNEL_MINOR_VERSION,
                init.capabilities() & config.requested,
                config.max_readahead,
                config.max_write
            );

            let response = init.reply(&config);
            let sent = response.with_iovec(request.unique(), |iov| self.ch.sender().send(iov));
            if let Err(err) = sent {
                // A reply that echoed the flag but never arrived leaves nothing to register
                // against, so the session cannot go on; a /dev/fuse session is only failed
                // by its event loop
                #[cfg(all(feature = "io-uring", target_os = "linux"))]
                if self.ring.is_some() {
                    return Err(err);
                }
                error!("Failed to send FUSE reply: {err}");
            }

            // From here every request on the mount waits for the queues to be registered, so
            // the ring threads register now and the session is handed over ready
            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            if let Some(ring) = &mut self.ring {
                ring.start()?;
            }

            return Ok(());
        }
    }

    /// The rings of this session, from the negotiated buffer sizes: the kernel's REGISTER
    /// requires a payload of `max(8192, max_write, max_pages * PAGE_SIZE)` bytes per entry.
    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    fn create_rings(&self, config: &KernelConfig) -> io::Result<RingSet> {
        let payload_cap = (config.max_write as usize)
            .max(usize::from(config.max_pages()) * page_size::get())
            .max(8192);
        RingSet::new(
            self.ch.device(),
            self.mount.mount.lock().is_some(),
            self.config.n_threads.unwrap_or(1),
            self.config.io_uring_queue_depth,
            payload_cap,
        )
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        self.mount.umount()
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(
            self.ch.sender(),
            self.kernel_capabilities,
            self.proto_version,
        )
    }
}

/// Rejects a thread count or transport choice this build or target cannot honor, before
/// anything is mounted.
fn validate_transport(config: &Config) -> io::Result<()> {
    if config.n_threads == Some(0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "n_threads must be at least 1",
        ));
    }
    if !config.io_uring {
        return Ok(());
    }
    if !cfg!(target_os = "linux") {
        return Err(io::Error::other(
            "io_uring transport is only supported on Linux",
        ));
    }
    if !cfg!(feature = "io-uring") {
        return Err(io::Error::other(
            "io_uring transport requires the io-uring cargo feature",
        ));
    }
    if config.io_uring_queue_depth == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "io_uring_queue_depth must be at least 1",
        ));
    }
    Ok(())
}

/// Serves the session over `/dev/fuse` alone, with `n_threads` readers, until the
/// connection ends.
fn serve_channels<FS: Filesystem>(
    ch: Channel,
    config: &Config,
    event_loop: impl Fn(String, Channel) -> SessionEventLoop<FS>,
) -> io::Result<()> {
    let n_threads = config.n_threads.unwrap_or(1);

    if !cfg!(target_os = "linux") && n_threads != 1 {
        // TODO: check whether it works on macOS/FreeBSD and enable if it works.
        return Err(io::Error::other(
            "n_threads != 1 is only supported on Linux",
        ));
    }

    let Some(n_threads_minus_one) = n_threads.checked_sub(1) else {
        return Err(io::Error::other("n_threads"));
    };

    let mut channels = Vec::with_capacity(n_threads);

    for _ in 0..n_threads_minus_one {
        if config.clone_fd {
            #[cfg(target_os = "linux")]
            {
                channels.push(ch.clone_fd()?);
                continue;
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(io::Error::other("clone_fd is only supported on Linux"));
            }
        } else {
            channels.push(ch.clone());
        }
    }
    channels.push(ch);

    let threads = spawn_named(channels.into_iter().enumerate().map(|(i, ch)| {
        let thread_name = format!("fuser-{i}");
        let event_loop = event_loop(thread_name.clone(), ch);
        (thread_name, move || event_loop.event_loop())
    }))?;

    join_all(threads)
}

/// What a thread of a ring session tells `serve_ring`.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
enum Event {
    /// The thread at this index of `serve_ring`'s list is done, panicked or not.
    Exited(usize),
    /// A filesystem callback on a ring thread panicked; the reply it owed went out as EIO
    /// during the unwind.
    Panicked,
}

/// Sends `Event::Exited` when dropped, which the owning thread does as its last act.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
struct ExitNotice {
    events: std::sync::mpsc::Sender<Event>,
    thread: usize,
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl Drop for ExitNotice {
    fn drop(&mut self) {
        let _ = self.events.send(Event::Exited(self.thread));
    }
}

/// The `FetchHandler` of one ring thread; it lives exactly as long as the thread serves.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
struct RingHandler<FS: Filesystem> {
    ctx: SessionEventLoop<FS>,
    exit: ExitNotice,
    /// A callback panicked on this ring: it no longer enters the filesystem, as a `/dev/fuse`
    /// reader that died does not either; other rings and the reader are unaffected
    panicked: bool,
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl<FS: Filesystem> crate::uring::ring::FetchHandler for RingHandler<FS> {
    fn handle(&mut self, commit: RingCommit, request: &[u8]) {
        if self.panicked {
            return commit.commit_errno(Errno::EIO);
        }
        // A ring thread must outlive its panicking callback: only it can submit the EIO the
        // unwind committed, and its kernel commands hold the mount's queues
        let ctx = &self.ctx;
        let dispatch = std::panic::AssertUnwindSafe(|| ctx.handle_fetch(commit, request));
        if std::panic::catch_unwind(dispatch).is_err() {
            self.panicked = true;
            let _ = self.exit.events.send(Event::Panicked);
        }
    }
}

/// Serves the session over its rings, with one `/dev/fuse` reader for the requests the kernel
/// never sends over a ring, until the connection ends or a thread fails.
///
/// The ring threads have no way to learn that the connection ended while every entry they
/// own is held by userspace, so they are told to leave once the `/dev/fuse` reader has seen
/// the end of the connection, and joined only then. A panic or error on any thread ends the
/// session at once, as `join_all` does for `/dev/fuse` sessions; the other threads are left
/// to exit with the connection, which is still alive at that point and is not told to shut
/// down: `Session::run` callers end it by dropping the mount, a `Session::spawn` session
/// keeps it, answering EIO, until the `BackgroundSession` is dropped.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn serve_ring<FS: Filesystem>(
    mut ring: RingSet,
    ch: Channel,
    config: &Config,
    event_loop: impl Fn(String, Channel) -> SessionEventLoop<FS>,
) -> io::Result<()> {
    const DEV: usize = 0;
    if config.clone_fd {
        debug!("clone_fd has no effect with io_uring");
    }
    let (events_tx, events) = std::sync::mpsc::channel();
    ring.serve(|index| {
        Box::new(RingHandler {
            ctx: event_loop(format!("fuser-ring-{index}"), ch.clone()),
            exit: ExitNotice {
                events: events_tx.clone(),
                thread: index + 1,
            },
            panicked: false,
        })
    })?;
    let dev = spawn_named([("fuser-dev".to_string(), {
        let event_loop = event_loop("fuser-dev".to_string(), ch);
        let exit = ExitNotice {
            events: events_tx,
            thread: DEV,
        };
        move || {
            let _exit = exit;
            event_loop.event_loop()
        }
    })])?;
    let mut threads: Vec<Option<JoinHandle<io::Result<()>>>> = dev
        .into_iter()
        .chain(ring.take_threads())
        .map(Some)
        .collect();
    loop {
        let event = events
            .recv()
            .map_err(|_| io::Error::other("BUG: every session thread exited unnoticed"))?;
        match event {
            Event::Panicked => return Err(io::Error::other(THREAD_PANICKED)),
            Event::Exited(DEV) => {
                join_all(threads[DEV].take())?;
                ring.shutdown();
                return join_all(threads.into_iter().flatten());
            }
            // A ring leaving cleanly before the reader means the connection is ending
            Event::Exited(thread) => join_all(threads[thread].take())?,
        }
    }
}

/// A spawn failure returns at once; the threads spawned before it keep running detached.
pub(crate) fn spawn_named<F>(
    threads: impl IntoIterator<Item = (String, F)>,
) -> io::Result<Vec<JoinHandle<io::Result<()>>>>
where
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    threads
        .into_iter()
        .map(|(name, body)| thread::Builder::new().name(name).spawn(body))
        .collect()
}

/// First error wins. A panicked thread ends the join at once, leaving later threads detached.
fn join_all(threads: impl IntoIterator<Item = JoinHandle<io::Result<()>>>) -> io::Result<()> {
    let mut reply: io::Result<()> = Ok(());
    for thread in threads {
        let res = match thread.join() {
            Ok(res) => res,
            Err(_) => {
                return Err(io::Error::other(THREAD_PANICKED));
            }
        };
        if let Err(e) = res {
            if reply.is_ok() {
                reply = Err(e);
            }
        }
    }
    reply
}

#[derive(Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        if let Some(mount) = std::mem::take(&mut *self.mount.lock()) {
            mount.umount()?;
        }
        Ok(())
    }
}

pub(crate) struct SessionEventLoop<FS: Filesystem> {
    /// Cache thread name for faster `debug!`.
    pub(crate) thread_name: String,
    pub(crate) ch: Channel,
    pub(crate) filesystem: Arc<FilesystemHolder<FS>>,
    pub(crate) allowed: SessionACL,
    pub(crate) session_owner: Uid,
    pub(crate) negotiated: InitFlags,
    pub(crate) kernel_capabilities: InitFlags,
    pub(crate) kernel_abi: Option<Version>,
}

impl<FS: Filesystem> SessionEventLoop<FS> {
    fn event_loop(&self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buf = FuseReadBuf::new();
        let buf = buf.as_mut();
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive_retrying(buf) {
                Ok(size) => {
                    let sender = ReplySender::Channel(self.ch.sender());
                    match RequestWithSender::new(sender, &buf[..size], self.negotiated) {
                        // Dispatch request
                        Some(req) => {
                            if let Ok(Operation::Destroy(_)) = req.request.operation() {
                                req.reply::<ReplyEmpty>().ok();
                                return Ok(());
                            } else {
                                req.dispatch(self)
                            }
                        }
                        // Quit loop on illegal request
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid request",
                            ));
                        }
                    }
                }
                // The kernel returns ENODEV when the filesystem was unmounted, or
                // ECONNABORTED when the connection was aborted with FUSE_ABORT_ERROR
                // negotiated. Either way the connection is gone: a normal end of the
                // session, not an operation failure (issue #212)
                Err(nix::errno::Errno::ENODEV | nix::errno::Errno::ECONNABORTED) => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Dispatches one request fetched over a ring; the ring thread answers a request the
    /// filesystem was not given a reply object for.
    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    fn handle_fetch(&self, commit: RingCommit, request: &[u8]) {
        let request = match ll::AnyRequest::try_from(request) {
            Ok(request) => request,
            // Unlike a `/dev/fuse` stream, one unparsable request leaves the ring usable
            Err(err) => {
                error!("{err}");
                return commit.commit_errno(Errno::EIO);
            }
        };
        let req =
            RequestWithSender::from_request(ReplySender::Ring(commit), request, self.negotiated);
        if let Ok(Operation::Destroy(_)) = req.request.operation() {
            req.reply::<ReplyEmpty>().ok();
        } else {
            req.dispatch(self)
        }
    }
}

/// The background session data structure
///
/// Dropping this unmounts the filesystem and blocks until the session has ended,
/// which guarantees that `Filesystem::destroy` has run when drop returns. Because
/// of that, it must not be dropped from within a filesystem callback, which runs
/// on the session thread being waited for. For a session created via
/// `Session::from_fd` there is no mount to remove, so dropping cannot end the
/// session and leaves its thread detached; end the session externally and use
/// `join` to wait for it instead. The thread is likewise left detached, with a
/// warning, rather than waiting for a session that may never end when the
/// unmount fails, or when the kernel connection is still alive a few seconds
/// after a successful unmount request (e.g. a lazily unmounted filesystem that
/// is still in use, or an unmount helper that failed without reporting it).
#[derive(Debug)]
pub struct BackgroundSession {
    /// Thread guard of the background session. None once joined.
    guard: Option<JoinHandle<io::Result<()>>>,
    /// Object for creating Notifiers for client use
    sender: ChannelSender,
    /// The FUSE device fd of the session's kernel connection
    fuse_device: Arc<DevFuse>,
    /// Ensures the filesystem is unmounted when the session ends
    mount: Option<Mount>,
    /// Everything the kernel advertised during init, for notifications whose support
    /// depends on it
    kernel_capabilities: InitFlags,
    /// The ABI version agreed during init, for notifications with no capability bit
    kernel_abi: Option<Version>,
}

/// How long teardown waits for the kernel connection to end after a successful
/// unmount request, before giving up on joining the session thread. The
/// connection can end asynchronously (auto_unmount, kernel teardown), but a few
/// seconds only pass without it ending when the session cannot be waited for,
/// e.g. a lazily unmounted filesystem still in use
const UNMOUNT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

impl BackgroundSession {
    /// Unmount the filesystem and join the background thread, returning the
    /// session result. `Filesystem::destroy` has run when this returns.
    pub fn umount_and_join(mut self) -> io::Result<()> {
        if let Some(mount) = self.mount.take() {
            if let Err(err) = mount.umount() {
                // The filesystem is still mounted and the session still running,
                // so joining would block indefinitely; leave the thread detached,
                // as before
                self.guard.take();
                return Err(err);
            }
        }
        self.join_impl()
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(
            self.sender.clone(),
            self.kernel_capabilities,
            self.kernel_abi,
        )
    }

    /// Join the filesystem thread without unmounting first: blocks until
    /// something else ends the session, e.g. an external unmount.
    pub fn join(mut self) -> io::Result<()> {
        self.join_impl()
    }

    fn join_impl(&mut self) -> io::Result<()> {
        let Some(guard) = self.guard.take() else {
            return Ok(());
        };
        guard
            .join()
            .map_err(|_panic: Box<dyn std::any::Any + Send>| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "filesystem background thread panicked",
                )
            })?
    }
}

impl Drop for BackgroundSession {
    fn drop(&mut self) {
        // Unmount and wait for the session to end, so that Filesystem::destroy
        // has run by the time drop returns (issues #239 and #411). Without the
        // join, the process could exit before the detached session thread got
        // around to calling destroy
        let Some(mount) = self.mount.take() else {
            // No mount to remove (Session::from_fd): nothing here can end the
            // session, so joining could block forever; leave the thread detached
            return;
        };
        if let Err(err) = mount.umount() {
            // Still mounted, so the session is still running and joining would
            // block indefinitely
            warn!("Failed to unmount filesystem during drop: {err}");
            return;
        }
        // The connection can end asynchronously (e.g. auto_unmount), and some
        // unmount helpers cannot report failures. Wait boundedly, and if the
        // session lives on, detach rather than block indefinitely
        if !crate::mnt::connection_ended(&self.fuse_device, UNMOUNT_WAIT) {
            warn!("FUSE connection still alive after unmount; detaching session thread");
            return;
        }
        if let Err(err) = self.join_impl() {
            warn!("Session ended with an error during drop: {err}");
        }
    }
}

#[cfg(test)]
mod thread_test {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::*;

    /// Distinct closures have distinct types, so a mixed list needs boxing
    type Body = Box<dyn FnOnce() -> io::Result<()> + Send>;

    #[test]
    fn join_all_reports_the_first_error_after_joining_every_thread() {
        let done = Arc::new(AtomicUsize::new(0));
        let body = |result: io::Result<()>, delay: u64| -> Body {
            let done = done.clone();
            Box::new(move || {
                thread::sleep(Duration::from_millis(delay));
                done.fetch_add(1, Ordering::SeqCst);
                result
            })
        };
        let mut threads = spawn_named([
            ("a".to_string(), body(Err(io::Error::other("first")), 0)),
            ("b".to_string(), body(Err(io::Error::other("second")), 50)),
            ("c".to_string(), body(Ok(()), 0)),
        ])
        .unwrap();
        threads.push(thread::spawn(body(
            Err(io::Error::other("pre-spawned")),
            100,
        )));

        let err = join_all(threads).unwrap_err();
        assert_eq!(err.to_string(), "first");
        assert_eq!(
            done.load(Ordering::SeqCst),
            4,
            "every thread must be joined"
        );
    }

    #[test]
    fn join_all_reports_a_panic() {
        let threads = spawn_named([("p".to_string(), || -> io::Result<()> {
            panic!("deliberate panic from a test thread")
        })])
        .unwrap();
        let err = join_all(threads).unwrap_err();
        assert_eq!(err.to_string(), "event loop thread panicked");
    }

    #[test]
    fn spawn_named_names_the_threads() {
        let threads = spawn_named([("fuser-99".to_string(), || {
            if thread::current().name() == Some("fuser-99") {
                Ok(())
            } else {
                Err(io::Error::other("wrong thread name"))
            }
        })])
        .unwrap();
        join_all(threads).unwrap();
    }
}

// The abort test uses fusectl, which only exists on Linux; on other targets the
// whole module would be dead code
#[cfg(all(test, target_os = "linux"))]
mod test {
    use std::io::Write;
    use std::mem::ManuallyDrop;

    use super::*;
    use crate::Config;
    use crate::InitFlags;
    use crate::KernelConfig;
    use crate::Request;

    /// A filesystem that requests FUSE_ABORT_ERROR during init, so that after an
    /// abort the FUSE device fails reads with ECONNABORTED instead of ENODEV.
    struct AbortErrorFs;

    impl Filesystem for AbortErrorFs {
        fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
            // Ignore the error: on kernels without FUSE_ABORT_ERROR an abort
            // yields ENODEV, which ends the session cleanly anyway
            let _ = config.add_capabilities(InitFlags::FUSE_ABORT_ERROR);
            Ok(())
        }
    }

    /// Aborting the connection (via fusectl) with FUSE_ABORT_ERROR negotiated makes
    /// the FUSE device return ECONNABORTED. The session loop must treat that as a
    /// normal end of the session, so that umount_and_join() reports success rather
    /// than an error for an administratively aborted filesystem (issue #212).
    #[test]
    fn session_ends_cleanly_after_abort() {
        let Some(_fusectl) = Fusectl::ensure() else {
            eprintln!("skipping session_ends_cleanly_after_abort: fusectl not available");
            return;
        };
        // Leak the directory on failure: it may still be a (dead) mountpoint
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        // The mount table lists the canonical path; resolve while it is a plain dir
        let mountpoint = tmp.path().canonicalize().unwrap();

        let session = Session::new(AbortErrorFs, &mountpoint, &Config::default()).unwrap();
        let bg = session.spawn().unwrap();

        // Wait until the handshake completed: the kernel forwards filesystem
        // requests only after the init reply was processed, so a completed
        // operation (the errno does not matter) proves the loop is past it
        let _ = std::fs::metadata(&mountpoint);

        let abort_path = fusectl_abort_path(&mountpoint).expect("fusectl is mounted");
        std::fs::OpenOptions::new()
            .write(true)
            .open(abort_path)
            .unwrap()
            .write_all(b"1")
            .unwrap();

        bg.umount_and_join()
            .expect("session must end cleanly after the connection was aborted");

        // Teardown intentionally leaves the dead mount in the mount table (the
        // same as libfuse); detach it so the tempdir can be removed
        let _ = nix::mount::umount2(&mountpoint, nix::mount::MntFlags::MNT_DETACH);
        for fusermount in ["fusermount3", "fusermount"] {
            let _ = std::process::Command::new(fusermount)
                .args(["-u", "-q", "-z", "--"])
                .arg(&mountpoint)
                .status();
        }
        ManuallyDrop::into_inner(tmp);
    }

    #[test]
    fn zero_threads_are_refused_before_mounting() {
        let config = Config {
            n_threads: Some(0),
            ..Config::default()
        };
        let err = validate_transport(&config).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "n_threads must be at least 1");
        let tmp = tempfile::tempdir().unwrap();
        let err = Session::new(AbortErrorFs, tmp.path(), &config)
            .err()
            .expect("n_threads == 0 must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        assert!(!mounts.contains(tmp.path().to_str().unwrap()));
        let fd = OwnedFd::from(File::open("/dev/null").unwrap());
        let err = Session::from_fd(AbortErrorFs, fd, SessionACL::Owner, config)
            .err()
            .expect("n_threads == 0 must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[cfg(not(feature = "io-uring"))]
    fn io_uring_without_the_feature_is_refused() {
        let config = Config {
            io_uring: true,
            ..Config::default()
        };
        assert!(validate_transport(&Config::default()).is_ok());
        let err = validate_transport(&config).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(
            err.to_string(),
            "io_uring transport requires the io-uring cargo feature"
        );

        let tmp = tempfile::tempdir().unwrap();
        let err = Session::new(AbortErrorFs, tmp.path(), &config)
            .err()
            .expect("io_uring without the feature must be refused");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        assert!(!mounts.contains(tmp.path().to_str().unwrap()));
        let fd = OwnedFd::from(File::open("/dev/null").unwrap());
        let err = Session::from_fd(AbortErrorFs, fd, SessionACL::Owner, config)
            .err()
            .expect("io_uring without the feature must be refused");
        assert_eq!(
            err.to_string(),
            "io_uring transport requires the io-uring cargo feature"
        );
    }

    /// A panic in init() must reach the caller with the filesystem unmounted. The
    /// handshake used to run inside the session loop, so with spawn() the caller was
    /// handed a live BackgroundSession while the kernel waited forever for an init
    /// reply that would never come, hanging every process that touched the mountpoint
    /// (issue #271). Running the handshake in Session::new() makes the panic unwind
    /// through it, unmounting on the way out.
    #[test]
    fn panic_in_init_leaves_nothing_mounted() {
        struct PanicInInit;
        impl Filesystem for PanicInInit {
            fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
                panic!("deliberate panic from a test filesystem's init()");
            }
        }

        // Leak the directory on failure: it may still be a mountpoint nothing serves
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        // The mount table lists the canonical path
        let mountpoint = tmp.path().canonicalize().unwrap();

        let session = std::panic::catch_unwind(|| {
            Session::new(PanicInInit, &mountpoint, &Config::default()).and_then(Session::spawn)
        });
        assert!(
            session.is_err(),
            "the panic must reach the caller, rather than a session thread it cannot see"
        );

        // Anything left mounted here has nothing serving it, so every access to the
        // mountpoint would block indefinitely
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        assert!(
            !mounts
                .lines()
                .any(|line| line.split(' ').nth(1) == mountpoint.to_str()),
            "the filesystem must not be left mounted with nothing serving it:\n{mounts}"
        );
        ManuallyDrop::into_inner(tmp);
    }

    /// A rename is given an owner only when it creates an inode to own, which is a rename with
    /// `RENAME_WHITEOUT` and no other. Off an idmapped mount every request carries ids, so the
    /// flags have to decide this rather than the ids do.
    #[test]
    #[cfg(target_os = "linux")]
    fn rename_names_an_owner_only_for_a_whiteout() {
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;
        use std::time::SystemTime;

        use crate::FileAttr;
        use crate::FileType;
        use crate::INodeNo;
        use crate::RenameFlags;

        /// Each rename's flags, and whether it was given an owner
        static SEEN: StdMutex<Vec<(RenameFlags, bool)>> = StdMutex::new(Vec::new());

        struct RenameFs;
        impl Filesystem for RenameFs {
            fn lookup(
                &self,
                _req: &Request,
                _parent: INodeNo,
                name: &std::ffi::OsStr,
                reply: crate::ReplyEntry,
            ) {
                if name == "src" {
                    reply.entry(
                        &Duration::from_secs(0),
                        &FileAttr {
                            ino: INodeNo(2),
                            size: 0,
                            blocks: 0,
                            atime: SystemTime::UNIX_EPOCH,
                            mtime: SystemTime::UNIX_EPOCH,
                            ctime: SystemTime::UNIX_EPOCH,
                            crtime: SystemTime::UNIX_EPOCH,
                            kind: FileType::RegularFile,
                            perm: 0o644,
                            nlink: 1,
                            uid: 0,
                            gid: 0,
                            rdev: 0,
                            blksize: 512,
                            flags: 0,
                        },
                        crate::Generation(0),
                    );
                } else {
                    reply.error(Errno::ENOENT);
                }
            }
            fn getattr(
                &self,
                _req: &Request,
                ino: INodeNo,
                _fh: Option<crate::FileHandle>,
                reply: crate::ReplyAttr,
            ) {
                reply.attr(
                    &Duration::from_secs(0),
                    &FileAttr {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: SystemTime::UNIX_EPOCH,
                        mtime: SystemTime::UNIX_EPOCH,
                        ctime: SystemTime::UNIX_EPOCH,
                        crtime: SystemTime::UNIX_EPOCH,
                        kind: FileType::Directory,
                        perm: 0o777,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 512,
                        flags: 0,
                    },
                );
            }
            fn rename(
                &self,
                _req: &Request,
                _parent: INodeNo,
                _name: &std::ffi::OsStr,
                _newparent: INodeNo,
                _newname: &std::ffi::OsStr,
                flags: RenameFlags,
                owner: Option<crate::Owner>,
                reply: crate::ReplyEmpty,
            ) {
                SEEN.lock().unwrap().push((flags, owner.is_some()));
                reply.ok();
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let bg = Session::new(RenameFs, &mountpoint, &Config::default())
            .unwrap()
            .spawn()
            .unwrap();

        use std::os::unix::ffi::OsStringExt;
        let src =
            std::ffi::CString::new(mountpoint.join("src").into_os_string().into_vec()).unwrap();
        let dst =
            std::ffi::CString::new(mountpoint.join("dst").into_os_string().into_vec()).unwrap();
        for flags in [0, libc::RENAME_WHITEOUT] {
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    src.as_ptr(),
                    libc::AT_FDCWD,
                    dst.as_ptr(),
                    flags,
                )
            };
        }

        let seen = std::mem::take(&mut *SEEN.lock().unwrap());
        drop(bg);
        ManuallyDrop::into_inner(tmp);

        // This mount is not idmapped, so the header carries ids for both of these
        assert_eq!(
            seen,
            vec![
                (RenameFlags::empty(), false),
                (RenameFlags::RENAME_WHITEOUT, true),
            ],
            "an owner belongs to the rename that creates an inode, and to no other"
        );
    }

    /// An idmapped mount has no caller ids to report. Pinned against a real kernel, since
    /// what it sends is its rule rather than fuser's: nothing reports a caller, and the
    /// requests that create an inode name its owner instead - the caller's ids mapped through
    /// the mount, which are not the caller's.
    #[test]
    #[cfg(target_os = "linux")]
    fn idmap_withholds_caller_ids_and_names_the_owner() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        use std::time::SystemTime;

        use crate::FileAttr;
        use crate::FileType;
        use crate::INodeNo;
        use crate::MountOption;

        struct IdmapFs {
            negotiated: Arc<AtomicBool>,
            /// Whether `getattr` was given the caller's uid at all
            getattr_had_uid: Arc<Mutex<Option<bool>>>,
            mkdir_owner: Arc<Mutex<Option<crate::Owner>>>,
            /// Whether the request that names an owner also reported a caller
            mkdir_had_uid: Arc<Mutex<Option<bool>>>,
        }

        impl Filesystem for IdmapFs {
            fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
                let accepted = config
                    .add_capabilities(crate::InitFlags::FUSE_ALLOW_IDMAP)
                    .is_ok();
                self.negotiated.store(accepted, Ordering::SeqCst);
                Ok(())
            }
            /// Answered so that creating a name gets as far as mkdir: the kernel looks it up
            /// first, and a default ENOSYS there would end the operation before it
            fn lookup(
                &self,
                _req: &Request,
                _parent: INodeNo,
                _name: &std::ffi::OsStr,
                reply: crate::ReplyEntry,
            ) {
                reply.error(crate::Errno::ENOENT);
            }
            fn getattr(
                &self,
                req: &Request,
                ino: INodeNo,
                _fh: Option<crate::FileHandle>,
                reply: crate::ReplyAttr,
            ) {
                *self.getattr_had_uid.lock() = Some(req.uid().is_some());
                reply.attr(
                    &Duration::from_secs(0),
                    &FileAttr {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: SystemTime::UNIX_EPOCH,
                        mtime: SystemTime::UNIX_EPOCH,
                        ctime: SystemTime::UNIX_EPOCH,
                        crtime: SystemTime::UNIX_EPOCH,
                        kind: FileType::Directory,
                        perm: 0o777,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 512,
                        flags: 0,
                    },
                );
            }
            fn mkdir(
                &self,
                _req: &Request,
                _parent: INodeNo,
                _name: &std::ffi::OsStr,
                _mode: u32,
                _umask: u32,
                owner: crate::Owner,
                reply: crate::ReplyEntry,
            ) {
                *self.mkdir_had_uid.lock() = Some(_req.uid().is_some());
                *self.mkdir_owner.lock() = Some(owner);
                // Nothing is created; the owner is the whole point here
                reply.error(crate::Errno::ENOSPC);
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let negotiated = Arc::new(AtomicBool::new(false));
        let getattr_had_uid = Arc::new(Mutex::new(None));
        let mkdir_owner = Arc::new(Mutex::new(None));
        let mkdir_had_uid = Arc::new(Mutex::new(None));

        // Both are what the capability requires: without default_permissions the kernel
        // refuses the connection, and without allow_other fuser refuses the capability
        let mut config = Config::default();
        config.mount_options.push(MountOption::DefaultPermissions);
        config.acl = crate::SessionACL::All;

        let session = match Session::new(
            IdmapFs {
                negotiated: negotiated.clone(),
                getattr_had_uid: getattr_had_uid.clone(),
                mkdir_owner: mkdir_owner.clone(),
                mkdir_had_uid: mkdir_had_uid.clone(),
            },
            &mountpoint,
            &config,
        ) {
            Ok(session) => session,
            Err(error) => {
                // allow_other needs either root or user_allow_other in /etc/fuse.conf
                eprintln!("skipping idmap: cannot mount with allow_other: {error}");
                ManuallyDrop::into_inner(tmp);
                return;
            }
        };
        // FUSE_ALLOW_IDMAP arrived in ABI 7.41; an older kernel never offers it
        let supported = session.proto_version.is_some_and(|v| v >= Version(7, 41));
        let bg = session.spawn().unwrap();

        let _ = std::fs::metadata(&mountpoint);
        let _ = std::fs::create_dir(mountpoint.join("newdir"));

        let getattr_had_uid = getattr_had_uid.lock().take();
        let mkdir_owner = mkdir_owner.lock().take();
        let mkdir_had_uid = mkdir_had_uid.lock().take();
        let negotiated = negotiated.load(Ordering::SeqCst);
        drop(bg);
        ManuallyDrop::into_inner(tmp);

        if !supported {
            eprintln!("skipping idmap: the kernel's FUSE protocol predates 7.41");
            return;
        }
        assert!(
            negotiated,
            "a mount with default_permissions and allow_other must be allowed the capability"
        );
        assert_eq!(
            getattr_had_uid,
            Some(false),
            "a request that creates nothing must arrive with the caller's ids withheld"
        );
        assert_eq!(
            mkdir_owner,
            Some(crate::Owner {
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            }),
            "a request that creates an inode must name the owner it should get"
        );
        // The header carries ids on this request, but they are the owner mapped through the
        // mount rather than the caller's. Reporting them as the caller would let an idmapping
        // that lands on uid 0 pass for root
        assert_eq!(
            mkdir_had_uid,
            Some(false),
            "the mapped owner must not be reported as the caller's id"
        );
    }

    /// statx(2) must reach Filesystem::statx(), and the creation time it carries - which no
    /// other request can express on Linux - must arrive intact. Also pins the one field the
    /// wire format carries but the kernel drops, so that a kernel change shows up here.
    #[test]
    #[cfg(target_os = "linux")]
    fn statx_reports_btime() {
        use std::os::unix::ffi::OsStringExt;
        use std::time::Duration;
        use std::time::SystemTime;

        use crate::FileAttr;
        use crate::FileType;
        use crate::INodeNo;
        use crate::ReplyStatx;
        use crate::StatxAttr;
        use crate::StatxAttributes;
        use crate::StatxMask;

        const FILE_INO: INodeNo = INodeNo(2);
        /// Distinctive enough that reading it out of the wrong field would show
        const BTIME_SECS: u64 = 1_000_000_000;

        struct StatxFs {
            asked: Arc<Mutex<Option<StatxMask>>>,
        }

        impl StatxFs {
            fn attr(ino: INodeNo, kind: FileType) -> FileAttr {
                FileAttr {
                    ino,
                    size: 4096,
                    blocks: 8,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind,
                    perm: if kind == FileType::Directory {
                        0o755
                    } else {
                        0o644
                    },
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                }
            }
        }

        impl Filesystem for StatxFs {
            fn lookup(
                &self,
                _req: &Request,
                _parent: INodeNo,
                _name: &std::ffi::OsStr,
                reply: crate::ReplyEntry,
            ) {
                reply.entry(
                    &Duration::from_secs(0),
                    &Self::attr(FILE_INO, FileType::RegularFile),
                    crate::Generation(0),
                );
            }
            fn getattr(
                &self,
                _req: &Request,
                ino: INodeNo,
                _fh: Option<crate::FileHandle>,
                reply: crate::ReplyAttr,
            ) {
                let kind = if ino == FILE_INO {
                    FileType::RegularFile
                } else {
                    FileType::Directory
                };
                reply.attr(&Duration::from_secs(0), &Self::attr(ino, kind));
            }
            fn statx(
                &self,
                _req: &Request,
                ino: INodeNo,
                _fh: Option<crate::FileHandle>,
                _flags: u32,
                mask: StatxMask,
                reply: ReplyStatx,
            ) {
                *self.asked.lock() = Some(mask);
                let kind = if ino == FILE_INO {
                    FileType::RegularFile
                } else {
                    FileType::Directory
                };
                reply.statx(
                    &Duration::from_secs(0),
                    &StatxAttr {
                        btime: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(BTIME_SECS)),
                        attributes: StatxAttributes::IMMUTABLE | StatxAttributes::APPEND,
                        attributes_mask: StatxAttributes::IMMUTABLE
                            | StatxAttributes::APPEND
                            | StatxAttributes::NODUMP,
                        ..Self::attr(ino, kind).into()
                    },
                );
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let asked = Arc::new(Mutex::new(None));
        let session = Session::new(
            StatxFs {
                asked: asked.clone(),
            },
            &mountpoint,
            &Config::default(),
        )
        .unwrap();
        // FUSE_STATX arrived in ABI 7.38. An older kernel answers statx(2) out of
        // FUSE_GETATTR without ever asking, so there is nothing to assert against
        let supported = session
            .proto_version
            .is_some_and(|v| v >= crate::ll::fuse_abi::FUSE_STATX_VERSION);
        let bg = session.spawn().unwrap();
        if !supported {
            eprintln!("skipping statx: the kernel's FUSE protocol predates 7.38");
            bg.umount_and_join().unwrap();
            ManuallyDrop::into_inner(tmp);
            return;
        }

        let mut buf: libc::statx = unsafe { std::mem::zeroed() };
        let path =
            std::ffi::CString::new(mountpoint.join("file").into_os_string().into_vec()).unwrap();
        let rc = unsafe {
            libc::statx(
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS | libc::STATX_BTIME,
                &mut buf,
            )
        };
        let err = std::io::Error::last_os_error();

        let asked = asked.lock().take();
        drop(bg);
        ManuallyDrop::into_inner(tmp);

        assert_eq!(rc, 0, "statx(2) must be answered: {err}");
        assert!(
            asked.is_some(),
            "statx(2) must reach Filesystem::statx rather than falling back to getattr"
        );
        assert_eq!(
            buf.stx_btime.tv_sec as u64, BTIME_SECS,
            "the creation time must survive the round trip"
        );
        assert_ne!(
            buf.stx_mask & libc::STATX_BTIME,
            0,
            "the reply must mark the creation time as filled in"
        );
        assert_eq!(
            buf.stx_size, 4096,
            "the fields stat(2) also carries must still be right"
        );
        eprintln!(
            "DIAG stx_attributes={:#x} stx_attributes_mask={:#x} stx_mask={:#x} btime={}",
            buf.stx_attributes, buf.stx_attributes_mask, buf.stx_mask, buf.stx_btime.tv_sec
        ); // The kernel does not pass `attributes` on to the caller: fuse_do_statx() copies the
        // mask, btime and basic stats out of the reply and ignores this field, so the
        // immutable and append-only bits set above go nowhere. Asserted so that this stops
        // being true loudly rather than silently, since the wire format has carried the field
        // since 7.38 and only the kernel's use of it is missing
        assert_eq!(
            buf.stx_attributes, 0,
            "STATX_ATTR_* from a FUSE filesystem is dropped by the kernel; if this now \
             arrives, StatxAttr::attributes and the CHANGELOG need their caveats removed"
        );
    }

    /// An O_TMPFILE open must reach Filesystem::tmpfile() with the mode and flags it was
    /// made with, and hand back a working descriptor. The kernel takes ENOSYS from this as
    /// permanent, so a filesystem that does implement it has one chance to say so.
    ///
    /// Naming the file afterwards is the other half of what it is for, and reaches
    /// Filesystem::link() with the inode tmpfile() replied with.
    #[test]
    fn tmpfile_open_and_link() {
        use std::os::fd::AsRawFd;
        use std::time::Duration;
        use std::time::SystemTime;

        use crate::FileAttr;
        use crate::FileType;
        use crate::FopenFlags;
        use crate::Generation;
        use crate::INodeNo;
        use crate::ReplyCreate;

        const TMPFILE_INO: INodeNo = INodeNo(2);

        struct TmpFileFs {
            seen: Arc<Mutex<Option<(u32, i32)>>>,
            linked: Arc<Mutex<Option<INodeNo>>>,
        }
        impl TmpFileFs {
            fn attr(ino: INodeNo, kind: FileType, perm: u16) -> FileAttr {
                let now = SystemTime::now();
                FileAttr {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    kind,
                    perm,
                    nlink: if kind == FileType::Directory { 2 } else { 0 },
                    uid: geteuid().as_raw(),
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                }
            }
        }
        impl Filesystem for TmpFileFs {
            fn lookup(
                &self,
                _req: &Request,
                _parent: INodeNo,
                _name: &std::ffi::OsStr,
                reply: crate::ReplyEntry,
            ) {
                // The name the link below creates must not exist yet
                reply.error(Errno::ENOENT);
            }
            fn link(
                &self,
                _req: &Request,
                ino: INodeNo,
                _newparent: INodeNo,
                _newname: &std::ffi::OsStr,
                reply: crate::ReplyEntry,
            ) {
                *self.linked.lock() = Some(ino);
                reply.entry(
                    &Duration::from_secs(0),
                    &Self::attr(ino, FileType::RegularFile, 0o600),
                    Generation(0),
                );
            }
            fn getattr(
                &self,
                _req: &Request,
                ino: INodeNo,
                _fh: Option<crate::FileHandle>,
                reply: crate::ReplyAttr,
            ) {
                let attr = if ino == TMPFILE_INO {
                    Self::attr(ino, FileType::RegularFile, 0o600)
                } else {
                    Self::attr(ino, FileType::Directory, 0o755)
                };
                reply.attr(&Duration::from_secs(0), &attr);
            }
            fn tmpfile(
                &self,
                _req: &Request,
                _parent: INodeNo,
                mode: u32,
                _umask: u32,
                flags: i32,
                _kill_suid_gid: bool,
                _owner: crate::Owner,
                reply: ReplyCreate,
            ) {
                *self.seen.lock() = Some((mode, flags));
                reply.created(
                    &Duration::from_secs(0),
                    &Self::attr(TMPFILE_INO, FileType::RegularFile, 0o600),
                    Generation(0),
                    crate::FileHandle(1),
                    FopenFlags::empty(),
                );
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let linked = Arc::new(Mutex::new(None));
        let session = Session::new(
            TmpFileFs {
                seen: seen.clone(),
                linked: linked.clone(),
            },
            &mountpoint,
            &Config::default(),
        )
        .unwrap();
        // FUSE_TMPFILE arrived in ABI 7.37, and a kernel without it has no tmpfile inode
        // operation at all, so it answers O_TMPFILE itself without asking the filesystem
        // anything. fuser supports back to 7.6, so that is not a failure of this change
        let supported = session.proto_version.is_some_and(|v| v >= Version(7, 37));
        let bg = session.spawn().unwrap();
        if !supported {
            eprintln!("skipping tmpfile_open: the kernel's FUSE protocol predates 7.37");
            bg.umount_and_join().unwrap();
            ManuallyDrop::into_inner(tmp);
            return;
        }

        let opened = nix::fcntl::open(
            &mountpoint,
            nix::fcntl::OFlag::O_TMPFILE | nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        );
        // Give the anonymous file a name, which is what it exists to allow. Going through
        // /proc/self/fd rather than AT_EMPTY_PATH, which would need CAP_DAC_READ_SEARCH
        let named = opened.as_ref().map_err(|err| *err).and_then(|fd| {
            let by_fd = format!("/proc/self/fd/{}", fd.as_raw_fd());
            nix::unistd::linkat(
                nix::fcntl::AT_FDCWD,
                by_fd.as_str(),
                nix::fcntl::AT_FDCWD,
                mountpoint.join("named.txt").as_path(),
                nix::fcntl::AtFlags::AT_SYMLINK_FOLLOW,
            )
        });

        let seen = seen.lock().take();
        let linked = linked.lock().take();
        let opened = opened.map(drop);
        drop(bg);
        ManuallyDrop::into_inner(tmp);

        opened.expect("the descriptor the filesystem replied with must reach the caller");
        named.expect("linking the anonymous file must reach the filesystem");
        assert_eq!(
            linked,
            Some(TMPFILE_INO),
            "the link must name the inode tmpfile() replied with"
        );
        let (mode, flags) = seen.expect("O_TMPFILE must reach Filesystem::tmpfile");
        // The kernel insists on S_IFREG for these, and applies the umask itself
        assert_eq!(mode & libc::S_IFMT, libc::S_IFREG);
        assert_eq!(
            flags & libc::O_TMPFILE,
            libc::O_TMPFILE,
            "flags {flags:#x} must carry O_TMPFILE"
        );
    }

    /// The kernel fills a request's uid, gid and pid from the task that caused it, for
    /// every operation that goes through fuse_simple_request(). Every access decision
    /// fuser makes rests on that - SessionACL, and which operations are exempt from it
    /// because the kernel issues them with no caller - so it is worth pinning down rather
    /// than assuming. `FUSE_ARGS()` zero-initializes, so a header fuser had merely copied
    /// from there would carry uid 0 and pid 0.
    #[test]
    fn requests_carry_the_calling_task() {
        /// The caller's uid, absent on an idmapped mount, and the calling thread's id
        type Caller = (Option<u32>, u32);

        struct CallerFs {
            seen: Arc<Mutex<Option<Caller>>>,
        }
        impl Filesystem for CallerFs {
            fn getattr(
                &self,
                req: &Request,
                _ino: crate::INodeNo,
                _fh: Option<crate::FileHandle>,
                reply: crate::ReplyAttr,
            ) {
                *self.seen.lock() = Some((req.uid(), req.pid()));
                reply.error(Errno::ENOSYS);
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let bg = Session::new(
            CallerFs { seen: seen.clone() },
            &mountpoint,
            &Config::default(),
        )
        .unwrap()
        .spawn()
        .unwrap();

        // Any operation will do; this one is answered from the mountpoint's root inode
        let _ = std::fs::metadata(&mountpoint);
        let seen = seen.lock().take();
        drop(bg);
        ManuallyDrop::into_inner(tmp);

        let (uid, pid) = seen.expect("the filesystem must have been asked for the root inode");
        assert_eq!(
            uid,
            Some(geteuid().as_raw()),
            "the request must carry the caller's uid, this mount not being idmapped"
        );
        // Discriminating even when the test runs as root, where the uid above is 0 either
        // way. The kernel takes this from task_pid(current), so it is the id of the thread
        // that made the call rather than of the process
        assert_eq!(
            pid,
            nix::unistd::gettid().as_raw() as u32,
            "the request must carry the calling thread's id"
        );
    }

    /// Dropping a BackgroundSession must unmount the filesystem and wait for the
    /// session to end, so that Filesystem::destroy has run when drop returns.
    #[test]
    fn drop_waits_for_destroy() {
        struct DestroyFs {
            destroyed: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Filesystem for DestroyFs {
            fn destroy(&mut self) {
                // Give drop a chance to return early: without the join, drop
                // consistently wins this race and the assertion below fails
                std::thread::sleep(std::time::Duration::from_millis(200));
                self.destroyed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let destroyed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fs = DestroyFs {
            destroyed: destroyed.clone(),
        };
        let bg = Session::new(fs, tmp.path(), &Config::default())
            .unwrap()
            .spawn()
            .unwrap();
        drop(bg);
        assert!(
            destroyed.load(std::sync::atomic::Ordering::SeqCst),
            "destroy() must have been called by the time drop returns"
        );
        ManuallyDrop::into_inner(tmp);
    }

    /// An unmount must not fail merely because the filesystem is still in use. The
    /// Mount is consumed by the unmount attempt, so a caller that gets EBUSY has
    /// nothing left to retry with and the filesystem is left mounted (issue #686).
    #[test]
    fn umount_succeeds_while_filesystem_is_busy() {
        use std::time::SystemTime;

        use crate::FileAttr;
        use crate::FileHandle;
        use crate::FileType;
        use crate::INodeNo;
        use crate::ReplyAttr;

        /// Serves getattr, which is all that opening the mount root needs
        struct RootDirFs;
        impl Filesystem for RootDirFs {
            fn getattr(
                &self,
                _req: &Request,
                ino: INodeNo,
                _fh: Option<FileHandle>,
                reply: ReplyAttr,
            ) {
                let now = SystemTime::now();
                reply.attr(
                    &std::time::Duration::from_secs(1),
                    &FileAttr {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: now,
                        mtime: now,
                        ctime: now,
                        crtime: now,
                        kind: FileType::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 4096,
                        flags: 0,
                    },
                );
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let mut session = Session::new(RootDirFs, &mountpoint, &Config::default()).unwrap();
        let mut unmounter = session.unmount_callable();
        let runner = std::thread::spawn(move || session.run());
        // The kernel forwards requests only after the init reply was processed, so a
        // completed operation proves the session loop is past the handshake
        let _ = std::fs::metadata(&mountpoint);

        // An open handle on the mount root makes an eager unmount fail with EBUSY
        let busy = std::fs::File::open(&mountpoint).unwrap();
        unmounter
            .unmount()
            .expect("unmount must not fail while the filesystem is in use");

        // Releasing the handle lets the lazily detached filesystem go away, ending
        // the session
        drop(busy);
        runner.join().unwrap().unwrap();
        ManuallyDrop::into_inner(tmp);
    }

    /// The filesystem is still destroyed exactly once and unmounted
    #[test]
    fn panic_in_callback_ends_the_session() {
        struct PanicFs(Arc<std::sync::atomic::AtomicUsize>);
        impl Filesystem for PanicFs {
            fn getattr(
                &self,
                _req: &Request,
                _ino: crate::INodeNo,
                _fh: Option<crate::FileHandle>,
                _reply: crate::ReplyAttr,
            ) {
                panic!("deliberate panic from a test filesystem's getattr()");
            }
            fn destroy(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let destroyed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let session =
            Session::new(PanicFs(destroyed.clone()), &mountpoint, &Config::default()).unwrap();
        let runner = std::thread::spawn(move || session.run());
        // The dropped reply answers with EIO, so this returns once the panic has happened
        assert!(std::fs::metadata(&mountpoint).is_err());

        let err = runner.join().unwrap().unwrap_err();
        assert_eq!(err.to_string(), "event loop thread panicked");
        assert_eq!(destroyed.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        assert!(
            !mounts
                .lines()
                .any(|l| l.split(' ').nth(1) == mountpoint.to_str())
        );
        ManuallyDrop::into_inner(tmp);
    }

    /// Mounts fusectl when root finds it missing and unmounts it when the last holder drops;
    /// the tests that abort a connection run concurrently on hosts that do not mount it
    pub(super) struct Fusectl;

    const FUSECTL: &str = "/sys/fs/fuse/connections";

    /// Live `Fusectl` values and whether one of them mounted fusectl
    static FUSECTL_HOLDERS: Mutex<(usize, bool)> = Mutex::new((0, false));

    impl Fusectl {
        pub(super) fn ensure() -> Option<Self> {
            let mut holders = FUSECTL_HOLDERS.lock();
            let mounted = std::fs::read_to_string("/proc/self/mounts")
                .is_ok_and(|m| m.lines().any(|l| l.split(' ').nth(1) == Some(FUSECTL)));
            if !mounted {
                if !geteuid().is_root() {
                    return None;
                }
                nix::mount::mount(
                    None::<&str>,
                    FUSECTL,
                    Some("fusectl"),
                    nix::mount::MsFlags::empty(),
                    None::<&str>,
                )
                .ok()?;
                holders.1 = true;
            }
            holders.0 += 1;
            Some(Self)
        }
    }

    impl Drop for Fusectl {
        fn drop(&mut self) {
            let mut holders = FUSECTL_HOLDERS.lock();
            holders.0 -= 1;
            if holders.0 == 0 && holders.1 {
                holders.1 = false;
                if let Err(err) = nix::mount::umount(FUSECTL) {
                    eprintln!("cannot unmount the fusectl the tests mounted: {err}");
                }
            }
        }
    }

    /// The fusectl abort file for the FUSE mount at `mountpoint`: the connection
    /// directory is named after the mount's anonymous device number.
    pub(super) fn fusectl_abort_path(mountpoint: &Path) -> Option<std::path::PathBuf> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let mut device = None;
        for line in mountinfo.lines() {
            let mut fields = line.split(' ');
            let (Some(dev), Some(path)) = (fields.nth(2), fields.nth(1)) else {
                continue;
            };
            // mountinfo octal-escapes special characters; the tempdir path has none.
            // Later entries are mounted on top of earlier ones, so the last match wins
            if Path::new(path) == mountpoint {
                let (major, minor) = dev.split_once(':')?;
                let (major, minor): (u64, u64) = (major.parse().ok()?, minor.parse().ok()?);
                // fusectl names the directory with the raw kernel-internal
                // device number, (major << 20) | minor: fuse_ctl_add_conn()
                // prints fc->dev (= sb->s_dev) without re-encoding it
                device = Some((major << 20) | minor);
            }
        }
        let path = std::path::PathBuf::from(format!("/sys/fs/fuse/connections/{}/abort", device?));
        path.exists().then_some(path)
    }
}

/// Runtime tests of the io_uring transport against the kernel. They skip unless the fuse module
/// has `enable_uring=Y`, and are serialized because they inspect this process's threads and
/// captured log lines.
#[cfg(all(test, feature = "io-uring", target_os = "linux"))]
mod uring_test {
    use std::ffi::OsStr;
    use std::io::Read;
    use std::io::Write;
    use std::mem::ManuallyDrop;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;
    use std::time::SystemTime;

    use super::*;
    use crate::FileAttr;
    use crate::FileHandle;
    use crate::FileType;
    use crate::Generation;
    use crate::INodeNo;
    use crate::ReplyAttr;
    use crate::ReplyData;
    use crate::ReplyDirectory;
    use crate::ReplyEntry;
    use crate::ReplyWrite;
    use crate::ReplyXattr;
    use crate::ll::ResponseEmpty;
    use crate::uring::ring::RingIo;

    /// Records every log line with the writing thread's name; the ring tests hold `SERIAL`
    /// while they read it, so the ring lines they see are their own
    struct CaptureLogger;

    struct Line {
        thread: String,
        level: log::Level,
        text: String,
    }

    static LINES: Mutex<Vec<Line>> = Mutex::new(Vec::new());
    static SERIAL: Mutex<()> = Mutex::new(());

    impl log::Log for CaptureLogger {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            let text = format!("{}", record.args());
            let thread = thread::current().name().unwrap_or("?").to_string();
            if std::env::var_os("RUST_LOG").is_some() {
                eprintln!("[{} {thread} {}] {text}", record.level(), record.target());
            }
            LINES.lock().push(Line {
                thread,
                level: record.level(),
                text,
            });
        }
        fn flush(&self) {}
    }

    /// Serializes a ring test and starts it with an empty log
    fn serial() -> parking_lot::MutexGuard<'static, ()> {
        static LOGGER: CaptureLogger = CaptureLogger;
        let guard = SERIAL.lock();
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Debug);
        }
        LINES.lock().clear();
        guard
    }

    fn logged(level: log::Level, text: &str) -> Vec<String> {
        logged_by("", level, text)
    }

    /// Lines written by threads whose name starts with `thread`; a line without a ring-specific
    /// token is scoped this way, since the `/dev/fuse` session tests run alongside
    fn logged_by(thread: &str, level: log::Level, text: &str) -> Vec<String> {
        LINES
            .lock()
            .iter()
            .filter(|l| l.thread.starts_with(thread) && l.level == level && l.text.contains(text))
            .map(|l| l.text.clone())
            .collect()
    }

    /// Lines a thread other than the test's may still be about to write: waits for `n` of them
    fn wait_logged(level: log::Level, text: &str, n: usize) -> Vec<String> {
        wait_logged_by("", level, text, n)
    }

    fn wait_logged_by(thread: &str, level: log::Level, text: &str, n: usize) -> Vec<String> {
        wait_until(|| logged_by(thread, level, text).len() >= n);
        logged_by(thread, level, text)
    }

    fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }

    fn session_log() -> String {
        LINES
            .lock()
            .iter()
            .filter(|l| l.thread.starts_with("fuser-"))
            .fold(String::new(), |mut log, l| {
                log += &format!("[{} {}] {}\n", l.level, l.thread, l.text);
                log
            })
    }

    fn uring_unavailable() -> Option<String> {
        match std::fs::read_to_string("/sys/module/fuse/parameters/enable_uring") {
            Ok(v) if v.trim() == "Y" => {}
            Ok(v) => return Some(format!("fuse.enable_uring is {}", v.trim())),
            Err(e) => return Some(format!("fuse.enable_uring unreadable: {e}")),
        }
        if !Path::new("/dev/fuse").exists() {
            return Some("/dev/fuse is missing".into());
        }
        if let Err(e) = RingIo::open(8, 16) {
            return Some(format!("io_uring_setup failed: {e}"));
        }
        None
    }

    fn thread_names() -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
            .map(|n| n.trim().to_string())
            .collect();
        names.sort();
        names
    }

    fn count_threads(prefix: &str) -> usize {
        thread_names()
            .iter()
            .filter(|n| n.starts_with(prefix))
            .count()
    }

    fn assert_threads(prefix: &str, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while count_threads(prefix) != n {
            assert!(
                Instant::now() < deadline,
                "expected {n} {prefix} threads, have {:?}",
                thread_names()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_ring_threads_gone(timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while count_threads("fuser-ring-") + count_threads("fuser-dev") > 0 {
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        true
    }

    fn assert_not_mounted(mountpoint: &Path) {
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        assert!(
            !mounts
                .lines()
                .any(|l| l.split(' ').nth(1) == mountpoint.to_str()),
            "{} is still mounted:\n{mounts}",
            mountpoint.display()
        );
    }

    fn ring_config() -> Config {
        Config {
            io_uring: true,
            ..Config::default()
        }
    }

    /// What a ring of `depth` entries per queue reserves with the default 16 MiB `max_write`,
    /// to tell this session's mapping apart from the ring unit tests' fake rings in the log
    fn reserved_bytes(depth: usize) -> usize {
        usize::from(crate::uring::possible_cpus().unwrap())
            * depth
            * (page_size::get() + MAX_WRITE_SIZE)
    }

    const HELLO_INO: INodeNo = INodeNo(2);
    const HELLO: &[u8] = b"Hello World!\n";
    const BIG_INO: INodeNo = INodeNo(3);
    const BIG_LEN: usize = 4 << 20;
    const OTHER_INO: INodeNo = INodeNo(4);
    const OTHER: &[u8] = b"other\n";
    const XATTR: &[u8] = b"xattr value";

    fn big_byte(offset: usize) -> u8 {
        (offset % 251) as u8
    }

    /// A root with `hello.txt`, `other.txt` and a 4 MiB `big.bin`, attributes uncached so that
    /// every `stat` reaches it; the switches make it reply from elsewhere, or not at all
    #[derive(Default)]
    struct RingFs {
        /// `read` and `getattr` reply from a spawned thread that exits right after
        foreign: bool,
        /// How long `read` of `hello.txt` blocks the calling thread before returning
        park_hello: Duration,
        /// How long the spawned replier of `other.txt` waits before replying
        delay_other: Duration,
        /// The spawned replier of `other.txt` also waits for this, which `read` of
        /// `hello.txt` releases before it parks
        other_gate: Mutex<Option<mpsc::Receiver<()>>>,
        release_other: Option<mpsc::Sender<()>>,
        /// The replier of `other.txt` made its reply
        other_replied: Option<mpsc::Sender<Instant>>,
        /// Every `getattr` is kept here unanswered
        hold_getattr: Option<Arc<Mutex<Vec<ReplyAttr>>>>,
        /// `getattr` panics
        panic_getattr: bool,
        /// `init` negotiates `FUSE_ABORT_ERROR`
        abort_error: bool,
        /// `read` of `hello.txt` was dispatched
        hello_read: Option<mpsc::Sender<Instant>>,
        /// `read` of `other.txt` was dispatched
        other_read: Option<mpsc::Sender<Instant>>,
        /// `unlink` hands its reply to the test instead of answering
        unlink_reply: Option<mpsc::Sender<ReplyEmpty>>,
        destroyed: Arc<AtomicUsize>,
    }

    impl RingFs {
        fn attr(ino: INodeNo) -> FileAttr {
            let (kind, size, perm) = match ino {
                HELLO_INO => (FileType::RegularFile, HELLO.len() as u64, 0o644),
                BIG_INO => (FileType::RegularFile, BIG_LEN as u64, 0o644),
                OTHER_INO => (FileType::RegularFile, OTHER.len() as u64, 0o644),
                _ => (FileType::Directory, 0, 0o755),
            };
            FileAttr {
                ino,
                size,
                blocks: size.div_ceil(512),
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
                crtime: SystemTime::UNIX_EPOCH,
                kind,
                perm,
                nlink: 1,
                uid: geteuid().as_raw(),
                gid: 0,
                rdev: 0,
                blksize: 4096,
                flags: 0,
            }
        }

        fn ino_of(name: &OsStr) -> Option<INodeNo> {
            match name.as_bytes() {
                b"hello.txt" => Some(HELLO_INO),
                b"big.bin" => Some(BIG_INO),
                b"other.txt" => Some(OTHER_INO),
                _ => None,
            }
        }

        fn content(ino: INodeNo, offset: u64, size: u32) -> Vec<u8> {
            let bytes: Vec<u8> = match ino {
                HELLO_INO => HELLO.to_vec(),
                OTHER_INO => OTHER.to_vec(),
                BIG_INO => (0..BIG_LEN).map(big_byte).collect(),
                _ => Vec::new(),
            };
            let start = (offset as usize).min(bytes.len());
            let end = start.saturating_add(size as usize).min(bytes.len());
            bytes[start..end].to_vec()
        }
    }

    impl Filesystem for RingFs {
        fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
            if self.abort_error {
                let _ = config.add_capabilities(InitFlags::FUSE_ABORT_ERROR);
            }
            Ok(())
        }
        fn destroy(&mut self) {
            self.destroyed.fetch_add(1, Ordering::SeqCst);
        }
        fn lookup(&self, _req: &Request, _parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
            match Self::ino_of(name) {
                Some(ino) => reply.entry(&Duration::ZERO, &Self::attr(ino), Generation(0)),
                None => reply.error(Errno::ENOENT),
            }
        }
        fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
            if self.panic_getattr {
                panic!("deliberate panic from a test filesystem's getattr()");
            }
            if let Some(held) = &self.hold_getattr {
                held.lock().push(reply);
                return;
            }
            if self.foreign {
                thread::spawn(move || reply.attr(&Duration::ZERO, &Self::attr(ino)));
            } else {
                reply.attr(&Duration::ZERO, &Self::attr(ino));
            }
        }
        fn read(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            size: u32,
            _flags: crate::OpenFlags,
            _lock_owner: Option<crate::LockOwner>,
            reply: ReplyData,
        ) {
            let data = Self::content(ino, offset, size);
            if ino == HELLO_INO {
                if let Some(tx) = &self.hello_read {
                    tx.send(Instant::now()).unwrap();
                }
                if let Some(tx) = &self.release_other {
                    tx.send(()).unwrap();
                }
                thread::sleep(self.park_hello);
            }
            if ino == OTHER_INO {
                if let Some(tx) = &self.other_read {
                    tx.send(Instant::now()).unwrap();
                }
                let delay = self.delay_other;
                let gate = self.other_gate.lock().take();
                let replied = self.other_replied.clone();
                thread::spawn(move || {
                    thread::sleep(delay);
                    if let Some(gate) = gate {
                        gate.recv().unwrap();
                    }
                    reply.data(&data);
                    if let Some(tx) = replied {
                        tx.send(Instant::now()).unwrap();
                    }
                });
            } else if self.foreign {
                thread::spawn(move || reply.data(&data));
            } else {
                reply.data(&data);
            }
        }
        fn write(
            &self,
            _req: &Request,
            _ino: INodeNo,
            _fh: FileHandle,
            _offset: u64,
            data: &[u8],
            _write_flags: crate::WriteFlags,
            _flags: crate::OpenFlags,
            _lock_owner: Option<crate::LockOwner>,
            reply: ReplyWrite,
        ) {
            reply.written(data.len() as u32);
        }
        fn readdir(
            &self,
            _req: &Request,
            _ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            mut reply: ReplyDirectory,
        ) {
            let entries = [
                (INodeNo(1), FileType::Directory, "."),
                (INodeNo(1), FileType::Directory, ".."),
                (HELLO_INO, FileType::RegularFile, "hello.txt"),
                (BIG_INO, FileType::RegularFile, "big.bin"),
                (OTHER_INO, FileType::RegularFile, "other.txt"),
            ];
            for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
                if reply.add(ino, i as u64 + 1, kind, name) {
                    break;
                }
            }
            reply.ok();
        }
        fn getxattr(
            &self,
            _req: &Request,
            _ino: INodeNo,
            name: &OsStr,
            size: u32,
            reply: ReplyXattr,
        ) {
            if name.as_bytes() != b"user.test" {
                return reply.error(Errno::ENODATA);
            }
            if size == 0 {
                reply.size(XATTR.len() as u32);
            } else {
                reply.data(XATTR);
            }
        }
        fn unlink(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
            match &self.unlink_reply {
                Some(tx) => tx.send(reply).unwrap(),
                None => reply.ok(),
            }
        }
        /// Never answered: the dropped reply must turn into EIO
        fn setattr(
            &self,
            _req: &Request,
            _ino: INodeNo,
            _mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            _size: Option<u64>,
            _atime: Option<crate::TimeOrNow>,
            _mtime: Option<crate::TimeOrNow>,
            _ctime: Option<SystemTime>,
            _fh: Option<FileHandle>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<crate::BsdFileFlags>,
            _kill_suid_gid: bool,
            _reply: ReplyAttr,
        ) {
        }
    }

    struct Mounted {
        tmp: Option<tempfile::TempDir>,
        mountpoint: std::path::PathBuf,
    }

    impl Drop for Mounted {
        /// Only a failed test gets here with the directory still held: end the connection so
        /// no client stays blocked in the mount, detach it and leave the directory behind
        fn drop(&mut self) {
            if let Some(tmp) = self.tmp.take() {
                if let Some(abort) = super::test::fusectl_abort_path(&self.mountpoint) {
                    let _ = std::fs::write(abort, b"1");
                }
                let _ = nix::mount::umount2(&self.mountpoint, nix::mount::MntFlags::MNT_DETACH);
                std::mem::forget(tmp);
            }
        }
    }

    impl Mounted {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let mountpoint = tmp.path().canonicalize().unwrap();
            Self {
                tmp: Some(tmp),
                mountpoint,
            }
        }

        fn session(&self, fs: RingFs, config: &Config) -> Session<RingFs> {
            let started = Instant::now();
            let session = Session::new(fs, &self.mountpoint, config).unwrap();
            eprintln!("Session::new with io_uring took {:?}", started.elapsed());
            assert!(session.ring.is_some(), "the kernel offered the ring");
            assert!(session.negotiated.contains(InitFlags::FUSE_OVER_IO_URING));
            session
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.mountpoint.join(name)
        }

        fn finish(mut self) {
            assert!(
                wait_ring_threads_gone(Duration::from_secs(5)),
                "ring threads still running: {:?}",
                thread_names()
            );
            assert_not_mounted(&self.mountpoint);
            drop(self.tmp.take());
        }
    }

    /// `umount_and_join` that fails instead of wedging the test binary when teardown hangs
    fn umount_and_join_within(bg: BackgroundSession, timeout: Duration) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(bg.umount_and_join());
        });
        rx.recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("umount_and_join did not return within {timeout:?}"))
    }

    #[test]
    fn validate_transport_rejects_what_this_build_cannot_serve() {
        assert!(validate_transport(&Config::default()).is_ok());
        assert!(validate_transport(&ring_config()).is_ok());
        let err = validate_transport(&Config {
            io_uring_queue_depth: 0,
            ..ring_config()
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "io_uring_queue_depth must be at least 1");
        // The depth is only checked once it matters
        assert!(
            validate_transport(&Config {
                io_uring_queue_depth: 0,
                ..Config::default()
            })
            .is_ok()
        );
        // The thread count is checked for both transports alike
        let err = validate_transport(&Config {
            n_threads: Some(0),
            ..ring_config()
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "n_threads must be at least 1");
        // Both constructors refuse before touching anything
        let tmp = tempfile::tempdir().unwrap();
        let config = Config {
            io_uring_queue_depth: 0,
            ..ring_config()
        };
        let err = Session::new(RingFs::default(), tmp.path(), &config)
            .err()
            .expect("a depth of 0 must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let fd = OwnedFd::from(File::open("/dev/null").unwrap());
        let err = Session::from_fd(RingFs::default(), fd, SessionACL::Owner, config)
            .err()
            .expect("a depth of 0 must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Covers the deferred path (getxattr), a reply from another thread (unlink) and a dropped reply
    #[test]
    fn ring_serves_a_mount() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping ring_serves_a_mount: {why}");
            return;
        }
        let m = Mounted::new();
        let destroyed = Arc::new(AtomicUsize::new(0));
        let (unlink_tx, unlink_rx) = mpsc::channel();
        let fs = RingFs {
            destroyed: destroyed.clone(),
            unlink_reply: Some(unlink_tx),
            ..RingFs::default()
        };
        let session = m.session(fs, &ring_config());
        assert_threads("fuser-ring-", 1);
        let created = logged(log::Level::Debug, "queues over 1 rings, depth 8");
        assert_eq!(created.len(), 1, "{created:?}");
        let queues = crate::uring::possible_cpus().unwrap();
        assert!(
            created[0].starts_with(&format!("io_uring: {queues} queues")),
            "{created:?}"
        );
        let registered = wait_logged(log::Level::Debug, "ring 0 registered", 1);
        assert_eq!(
            registered,
            [format!(
                "io_uring: ring 0 registered {} entries",
                usize::from(queues) * 8
            )]
        );
        let bg = session.spawn().unwrap();
        assert_threads("fuser-dev", 1);

        let meta = std::fs::metadata(m.path("hello.txt")).unwrap();
        assert_eq!(meta.len(), HELLO.len() as u64);
        let mut names: Vec<String> = std::fs::read_dir(&m.mountpoint)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["big.bin", "hello.txt", "other.txt"]);
        assert_eq!(std::fs::read(m.path("hello.txt")).unwrap(), HELLO);
        let big = std::fs::read(m.path("big.bin")).unwrap();
        assert_eq!(big.len(), BIG_LEN);
        assert!(big.iter().enumerate().all(|(i, b)| *b == big_byte(i)));
        std::fs::OpenOptions::new()
            .write(true)
            .open(m.path("hello.txt"))
            .unwrap()
            .write_all(b"written through the ring")
            .unwrap();
        let path = std::ffi::CString::new(m.path("hello.txt").as_os_str().as_bytes()).unwrap();
        let name = c"user.test";
        let mut buf = [0u8; 64];
        let n = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        assert_eq!(n, XATTR.len() as isize, "{}", io::Error::last_os_error());
        assert_eq!(&buf[..n as usize], XATTR);
        // The unlink is answered only once the ring thread served a later request, so it has
        // returned from `unlink` and the reply is a direct write into a `Dispatched` entry
        let (removed_tx, removed_rx) = mpsc::channel();
        let path = m.path("other.txt");
        thread::spawn(move || {
            let _ = removed_tx.send(std::fs::remove_file(path));
        });
        let unlink = unlink_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("unlink was not dispatched");
        // The root's attributes need no lock the pending unlink holds on the directory
        std::fs::metadata(&m.mountpoint).unwrap();
        unlink.ok();
        removed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("unlink was not answered")
            .unwrap();
        let err = std::fs::set_permissions(
            m.path("hello.txt"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));

        let started = Instant::now();
        bg.umount_and_join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
        assert_eq!(logged(log::Level::Debug, "ring 0 serving").len(), 1);
        let exited = logged(log::Level::Debug, "ring 0 exited");
        assert_eq!(exited.len(), 1, "{exited:?}");
        assert!(exited[0].contains("in_kernel=0"), "{exited:?}");
        // The ring unit tests run alongside and log errors for their fake rings, numbered 7
        assert!(logged(log::Level::Error, "ring 0").is_empty());
        assert!(logged(log::Level::Error, &format!("leaking {}", reserved_bytes(8))).is_empty());
        m.finish();
    }

    #[test]
    fn two_rings_share_the_queues() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping two_rings_share_the_queues: {why}");
            return;
        }
        let m = Mounted::new();
        let config = Config {
            n_threads: Some(2),
            ..ring_config()
        };
        let session = m.session(RingFs::default(), &config);
        assert_threads("fuser-ring-", 2);
        let created = logged(log::Level::Debug, "queues over 2 rings, depth 8");
        assert_eq!(created.len(), 1, "{created:?}");
        let queues = crate::uring::possible_cpus().unwrap();
        for (index, qids) in crate::uring::partition(queues, 2).iter().enumerate() {
            let text = format!("ring {index} registered");
            assert_eq!(
                wait_logged(log::Level::Debug, &text, 1),
                [format!("io_uring: {text} {} entries", qids.len() * 8)]
            );
        }
        let bg = session.spawn().unwrap();
        assert_threads("fuser-dev", 1);
        assert_eq!(std::fs::read(m.path("hello.txt")).unwrap(), HELLO);
        assert_eq!(std::fs::read(m.path("other.txt")).unwrap(), OTHER);
        bg.umount_and_join().unwrap();
        assert_eq!(
            logged(log::Level::Debug, "ring 0 exited, in_kernel=0").len(),
            1
        );
        assert_eq!(
            logged(log::Level::Debug, "ring 1 exited, in_kernel=0").len(),
            1
        );
        m.finish();
    }

    /// With a ring there is one `/dev/fuse` reader, so `clone_fd` has nothing to apply to
    #[test]
    fn clone_fd_is_ignored_with_a_ring() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping clone_fd_is_ignored_with_a_ring: {why}");
            return;
        }
        let m = Mounted::new();
        let config = Config {
            n_threads: Some(2),
            clone_fd: true,
            ..ring_config()
        };
        let bg = m.session(RingFs::default(), &config).spawn().unwrap();
        assert_eq!(std::fs::read(m.path("hello.txt")).unwrap(), HELLO);
        assert_threads("fuser-dev", 1);
        assert_threads("fuser-ring-", 2);
        assert_eq!(
            logged(log::Level::Debug, "clone_fd has no effect with io_uring").len(),
            1
        );
        bg.umount_and_join().unwrap();
        m.finish();
    }

    #[test]
    fn replying_thread_may_exit_before_the_next_request() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping replying_thread_may_exit_before_the_next_request: {why}");
            return;
        }
        let m = Mounted::new();
        let fs = RingFs {
            foreign: true,
            ..RingFs::default()
        };
        let bg = m.session(fs, &ring_config()).spawn().unwrap();

        let (tx, rx) = mpsc::channel();
        let mountpoint = m.mountpoint.clone();
        thread::spawn(move || {
            // Pin this thread to one CPU so every request lands on the same queue
            let cpu = (0..usize::from(crate::uring::possible_cpus().unwrap()))
                .find(|&cpu| pin_to_cpu(cpu))
                .expect("no CPU accepts this thread");
            for round in 0..5 {
                let meta = std::fs::metadata(mountpoint.join("hello.txt")).unwrap();
                assert_eq!(meta.len(), HELLO.len() as u64);
                let mut file = File::open(mountpoint.join("hello.txt")).unwrap();
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                assert_eq!(buf, HELLO, "round {round} on cpu {cpu}");
                // Drop the page cache so the next round reads through the ring again
                unsafe {
                    libc::posix_fadvise(
                        std::os::fd::AsRawFd::as_raw_fd(&file),
                        0,
                        0,
                        libc::POSIX_FADV_DONTNEED,
                    )
                };
            }
            tx.send(cpu).unwrap();
        });
        let cpu = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a request after a replying thread exited must still complete");
        eprintln!("five stat+read rounds completed pinned to cpu {cpu}");
        bg.umount_and_join().unwrap();
        m.finish();
    }

    /// The queues were registered by the ring threads, not by the constructing thread
    #[test]
    fn session_built_on_a_thread_that_exited_still_serves() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping session_built_on_a_thread_that_exited_still_serves: {why}");
            return;
        }
        let m = Mounted::new();
        let mountpoint = m.mountpoint.clone();
        let session = thread::spawn(move || {
            Session::new(RingFs::default(), &mountpoint, &ring_config()).unwrap()
        })
        .join()
        .unwrap();
        assert!(session.ring.is_some());
        let bg = session.spawn().unwrap();
        assert_eq!(std::fs::metadata(&m.mountpoint).unwrap().len(), 0);
        assert_eq!(std::fs::read(m.path("hello.txt")).unwrap(), HELLO);
        std::fs::OpenOptions::new()
            .write(true)
            .open(m.path("hello.txt"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        bg.umount_and_join().unwrap();
        m.finish();
    }

    /// A reply made while the ring thread is inside a callback goes out when the callback returns
    #[test]
    fn foreign_reply_is_batched_behind_the_ring_thread() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping foreign_reply_is_batched_behind_the_ring_thread: {why}");
            return;
        }
        // Idle ring: the reply lands as soon as the replier makes it
        let m = Mounted::new();
        let fs = RingFs {
            delay_other: Duration::from_millis(100),
            ..RingFs::default()
        };
        let bg = m.session(fs, &ring_config()).spawn().unwrap();
        let started = Instant::now();
        assert_eq!(std::fs::read(m.path("other.txt")).unwrap(), OTHER);
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(600),
            "idle-ring wake took {took:?}"
        );
        bg.umount_and_join().unwrap();
        m.finish();

        // Busy ring: other.txt's read returns at once and its replier waits until hello.txt's
        // read has been dispatched, which parks the ring thread inside `read`. The reply
        // committed into the parked ring only goes out when `read` returns
        let park = Duration::from_millis(500);
        let m = Mounted::new();
        let (hello_tx, hello_rx) = mpsc::channel();
        let (other_tx, other_rx) = mpsc::channel();
        let (release_tx, gate_rx) = mpsc::channel();
        let (replied_tx, replied_rx) = mpsc::channel();
        let fs = RingFs {
            park_hello: park,
            hello_read: Some(hello_tx),
            other_read: Some(other_tx),
            other_gate: Mutex::new(Some(gate_rx)),
            release_other: Some(release_tx),
            other_replied: Some(replied_tx),
            ..RingFs::default()
        };
        let bg = m.session(fs, &ring_config()).spawn().unwrap();
        // Warm the lookups so the timed reads are the only requests in flight
        std::fs::metadata(m.path("other.txt")).unwrap();
        std::fs::metadata(m.path("hello.txt")).unwrap();
        let read_at = |name: &str| {
            let path = m.path(name);
            thread::spawn(move || {
                std::fs::read(path).unwrap();
                Instant::now()
            })
        };
        let other = read_at("other.txt");
        other_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let hello = read_at("hello.txt");
        let hello_dispatched = hello_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let other_replied = replied_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let other_done = other.join().unwrap();
        let hello_done = hello.join().unwrap();
        // The reply was made into the parked ring, or the run says nothing
        let replied_after = other_replied.duration_since(hello_dispatched);
        assert!(
            replied_after < park,
            "other.txt was replied {replied_after:?} after hello.txt parked the ring thread for {park:?}"
        );
        let waited = other_done.duration_since(hello_dispatched);
        eprintln!(
            "other.txt replied {replied_after:?} after hello.txt parked; done {waited:?} later"
        );
        assert!(
            waited >= park - Duration::from_millis(100),
            "other.txt completed {waited:?} after hello.txt parked the ring thread for {park:?}"
        );
        assert!(
            other_done.saturating_duration_since(hello_done) < Duration::from_millis(500),
            "other.txt completed {:?} after hello.txt returned",
            other_done.saturating_duration_since(hello_done)
        );
        bg.umount_and_join().unwrap();
        m.finish();
    }

    #[test]
    fn requests_before_run_wait_for_run() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping requests_before_run_wait_for_run: {why}");
            return;
        }
        let m = Mounted::new();
        let session = m.session(RingFs::default(), &ring_config());
        let (tx, rx) = mpsc::channel();
        let path = m.path("hello.txt");
        thread::spawn(move || tx.send(std::fs::metadata(path).map(|m| m.len())).unwrap());
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing serves the mount before run"
        );
        let bg = session.spawn().unwrap();
        let len = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("run must serve the waiting request")
            .unwrap();
        assert_eq!(len, HELLO.len() as u64);
        bg.umount_and_join().unwrap();
        m.finish();
    }

    /// A request fetched before the drop is answered EIO
    #[test]
    fn dropped_session_unmounts_and_drains() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping dropped_session_unmounts_and_drains: {why}");
            return;
        }
        let m = Mounted::new();
        let destroyed = Arc::new(AtomicUsize::new(0));
        let fs = RingFs {
            destroyed: destroyed.clone(),
            ..RingFs::default()
        };
        let session = m.session(fs, &ring_config());
        let (tx, rx) = mpsc::channel();
        let path = m.path("hello.txt");
        thread::spawn(move || {
            let _ = tx.send(std::fs::metadata(path).map(drop));
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing serves the mount before run"
        );
        drop(session);
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
        let err = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the fetched request was not answered")
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
        m.finish();
        // The ring unit tests log the same line for their fake rings, which are numbered 7
        assert_eq!(
            logged(
                log::Level::Error,
                "ring 0 serving EIO until the connection ends"
            )
            .len(),
            1
        );
        assert_eq!(
            logged(log::Level::Debug, "ring 0 exited, in_kernel=0").len(),
            1
        );
        assert!(logged(log::Level::Error, &format!("leaking {}", reserved_bytes(8))).is_empty());
    }

    #[test]
    fn dropped_from_fd_session_aborts_the_connection() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping dropped_from_fd_session_aborts_the_connection: {why}");
            return;
        }
        if !geteuid().is_root() {
            eprintln!(
                "skipping dropped_from_fd_session_aborts_the_connection: mount(2) needs root"
            );
            return;
        }
        /// Detaches the hand-made mount however the test ends
        struct Detach(std::path::PathBuf);
        impl Drop for Detach {
            fn drop(&mut self) {
                let _ = nix::mount::umount2(&self.0, nix::mount::MntFlags::MNT_DETACH);
            }
        }
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let device = DevFuse::open().unwrap();
        let options = format!(
            "fd={},rootmode=40000,user_id={},group_id={}",
            std::os::fd::AsRawFd::as_raw_fd(&device),
            nix::unistd::getuid(),
            nix::unistd::getgid()
        );
        nix::mount::mount(
            Some("/dev/fuse"),
            &mountpoint,
            Some("fuse"),
            nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .unwrap();
        let detach = Detach(mountpoint.clone());
        let fd = OwnedFd::from(device.0);
        let session =
            Session::from_fd(RingFs::default(), fd, SessionACL::Owner, ring_config()).unwrap();
        assert!(session.ring.is_some());
        let before = wait_logged(log::Level::Debug, "ring 0 registered", 1);
        assert_eq!(before.len(), 1, "{before:?}");
        drop(session);

        // Nothing serves the mount any more, so this either fails once the connection is
        // aborted or blocks
        let (tx, rx) = mpsc::channel();
        let path = mountpoint.clone();
        thread::spawn(move || tx.send(std::fs::metadata(path).map(drop)).unwrap());
        let err = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the connection was not aborted")
            .unwrap_err();
        assert!(
            matches!(
                err.raw_os_error(),
                Some(libc::ENOTCONN | libc::ECONNABORTED)
            ),
            "{err}"
        );
        assert!(wait_ring_threads_gone(Duration::from_secs(5)));
        // The ring unit tests log the same lines for their fake rings, which are numbered 7
        let abandoned = wait_logged(log::Level::Error, "ring 0 abandoning", 1);
        assert_eq!(abandoned.len(), 1, "{abandoned:?}");
        assert!(abandoned[0].contains("from_fd session was dropped before it was run"));
        let leaked = format!("leaking {} bytes", reserved_bytes(8));
        assert_eq!(wait_logged(log::Level::Error, &leaked, 1).len(), 1);
        drop(detach);
        assert_not_mounted(&mountpoint);
        ManuallyDrop::into_inner(tmp);
    }

    /// Pins the calling thread to `cpu`; false when that CPU cannot run it (offline)
    fn pin_to_cpu(cpu: usize) -> bool {
        // SAFETY: a zeroed cpu_set_t is valid, and the libc macros only touch it.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) == 0
        }
    }

    /// With depth 1 and a request held on every queue nothing of the ring's is in the kernel
    #[test]
    fn teardown_ends_a_ring_whose_entries_are_all_held() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping teardown_ends_a_ring_whose_entries_are_all_held: {why}");
            return;
        }
        let Some(_fusectl) = super::test::Fusectl::ensure() else {
            eprintln!("skipping teardown_ends_a_ring_whose_entries_are_all_held: no fusectl");
            return;
        };
        let m = Mounted::new();
        let held = Arc::new(Mutex::new(Vec::new()));
        let fs = RingFs {
            hold_getattr: Some(held.clone()),
            ..RingFs::default()
        };
        let config = Config {
            io_uring_queue_depth: 1,
            ..ring_config()
        };
        let bg = m.session(fs, &config).spawn().unwrap();
        let abort_path =
            super::test::fusectl_abort_path(&m.mountpoint).expect("fusectl is mounted");

        // Held requests are only ever ended by the abort; a failure before it would leave
        // their threads unkillable and this process unable to exit
        let abort = || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&abort_path)
                .unwrap()
                .write_all(b"1")
                .unwrap();
        };

        // One unanswered request from every CPU, so that every queue's single entry is held
        let n_queues = usize::from(crate::uring::possible_cpus().unwrap());
        let (tx, rx) = mpsc::channel();
        let stats: Vec<_> = (0..n_queues)
            .map(|cpu| {
                let path = m.mountpoint.clone();
                let tx = tx.clone();
                thread::spawn(move || {
                    let pinned = pin_to_cpu(cpu);
                    tx.send(pinned).unwrap();
                    pinned.then(|| std::fs::metadata(path).map(drop))
                })
            })
            .collect();
        let pinned = rx.iter().take(n_queues).filter(|ok| *ok).count();
        if pinned < n_queues {
            eprintln!(
                "{} of {n_queues} CPUs are offline; their entries stay in the kernel",
                n_queues - pinned
            );
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while held.lock().len() < pinned {
            if Instant::now() > deadline {
                let arrived = held.lock().len();
                abort();
                panic!("only {arrived} of {pinned} requests arrived");
            }
            thread::sleep(Duration::from_millis(10));
        }

        // Abort the connection: the held requests fail, and no CQE reaches the ring
        abort();
        umount_and_join_within(bg, Duration::from_secs(5)).unwrap();
        for stat in stats {
            // Threads that could not be pinned made no request
            let Some(result) = stat.join().unwrap() else {
                continue;
            };
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err.raw_os_error(),
                    Some(libc::ENOTCONN | libc::ECONNABORTED)
                ),
                "{err}"
            );
        }
        let exited = logged(log::Level::Debug, "ring 0 exited");
        assert_eq!(exited.len(), 1, "{exited:?}");
        assert_eq!(
            exited[0],
            format!("io_uring: ring 0 exited, in_kernel=0 outstanding={pinned}")
        );
        // The replies come too late and are dropped quietly
        held.lock().clear();
        let dropped = logged(log::Level::Debug, "dropping reply for unique");
        assert_eq!(
            dropped
                .iter()
                .filter(|l| l.ends_with("after ring 0 exited"))
                .count(),
            pinned
        );
        // A ring refusal of the late replies; a /dev/fuse test running alongside may log the
        // same prefix with a different cause
        assert!(
            logged(
                log::Level::Error,
                "Failed to send FUSE reply: duplicate reply"
            )
            .is_empty()
        );
        assert!(
            logged(
                log::Level::Error,
                "Failed to send FUSE reply: reply after the connection ended"
            )
            .is_empty()
        );
        assert!(logged(log::Level::Error, &format!("leaking {}", reserved_bytes(1))).is_empty());

        // The dead mount stays in the table after an abort, as after any abort
        let _ = nix::mount::umount2(&m.mountpoint, nix::mount::MntFlags::MNT_DETACH);
        m.finish();
    }

    /// The ring twin of `test::panic_in_callback_ends_the_session`
    #[test]
    fn panic_on_a_ring_thread_ends_the_session() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping panic_on_a_ring_thread_ends_the_session: {why}");
            return;
        }
        let m = Mounted::new();
        let destroyed = Arc::new(AtomicUsize::new(0));
        let fs = RingFs {
            panic_getattr: true,
            destroyed: destroyed.clone(),
            ..RingFs::default()
        };
        let session = m.session(fs, &ring_config());
        // Ends the connection if the session fails to, so a failure here cannot wedge the host
        let abort_path = super::test::fusectl_abort_path(&m.mountpoint);
        let abort = || {
            if let Some(path) = &abort_path {
                let _ = std::fs::write(path, b"1");
            }
        };
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || tx.send(session.run()).unwrap());

        // The dropped reply answers with EIO, so this returns once the panic has happened
        let (stat_tx, stat_rx) = mpsc::channel();
        let path = m.mountpoint.clone();
        thread::spawn(move || stat_tx.send(std::fs::metadata(path).map(drop)).unwrap());
        let Ok(stat) = stat_rx.recv_timeout(Duration::from_secs(5)) else {
            abort();
            panic!("the request the panicking callback owed was never answered");
        };
        assert_eq!(stat.unwrap_err().raw_os_error(), Some(libc::EIO));
        let Ok(reply) = rx.recv_timeout(Duration::from_secs(5)) else {
            abort();
            panic!("run did not return after the panic");
        };
        assert_eq!(reply.unwrap_err().to_string(), THREAD_PANICKED);
        if !wait_ring_threads_gone(Duration::from_secs(5)) {
            abort();
            panic!("threads still running: {:?}", thread_names());
        }
        // The detached threads finish their exit work after `run` returned
        assert!(
            wait_until(|| destroyed.load(Ordering::SeqCst) == 1),
            "destroyed {} times\n{}",
            destroyed.load(Ordering::SeqCst),
            session_log()
        );
        assert_eq!(unwound_replies(), 1, "{}", session_log());
        let exited = wait_logged(log::Level::Debug, "ring 0 exited, in_kernel=0", 1);
        assert_eq!(exited.len(), 1, "{}", session_log());
        m.finish();
    }

    /// Scoped by thread because the `/dev/fuse` panic test logs the same line from its reader
    fn unwound_replies() -> usize {
        wait_logged_by(
            "fuser-ring-0",
            log::Level::Warn,
            "Reply not sent for operation",
            1,
        )
        .len()
    }

    /// A mount nobody answers fails the test instead of wedging it
    fn stat_within(path: &Path, timeout: Duration) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        let target = path.to_path_buf();
        thread::spawn(move || tx.send(std::fs::metadata(target).map(drop)));
        rx.recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("stat {} was not answered", path.display()))
    }

    #[test]
    fn spawned_ring_session_answers_eio_after_a_panic() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping spawned_ring_session_answers_eio_after_a_panic: {why}");
            return;
        }
        let m = Mounted::new();
        let fs = RingFs {
            panic_getattr: true,
            ..RingFs::default()
        };
        let bg = m.session(fs, &ring_config()).spawn().unwrap();
        let stat = stat_within(&m.mountpoint, Duration::from_secs(5));
        assert_eq!(stat.unwrap_err().raw_os_error(), Some(libc::EIO));
        assert!(
            wait_until(|| bg.guard.as_ref().unwrap().is_finished()),
            "run did not return after the panic\n{}",
            session_log()
        );
        let stat = stat_within(&m.mountpoint, Duration::from_secs(5));
        assert_eq!(stat.unwrap_err().raw_os_error(), Some(libc::EIO));
        assert_eq!(
            unwound_replies(),
            1,
            "the second stat reached the filesystem\n{}",
            session_log()
        );
        let err = umount_and_join_within(bg, Duration::from_secs(5)).unwrap_err();
        assert_eq!(err.to_string(), THREAD_PANICKED);
        m.finish();
    }

    #[test]
    fn oversized_depth_falls_back_to_dev_fuse() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping oversized_depth_falls_back_to_dev_fuse: {why}");
            return;
        }
        let m = Mounted::new();
        let queues = usize::from(crate::uring::possible_cpus().unwrap());
        let depth = (crate::uring::ring::IORING_MAX_ENTRIES / queues + 1) as u32;
        let config = Config {
            io_uring_queue_depth: depth,
            ..ring_config()
        };
        let session = Session::new(RingFs::default(), &m.mountpoint, &config).unwrap();
        assert!(session.ring.is_none());
        assert!(!session.negotiated.contains(InitFlags::FUSE_OVER_IO_URING));
        let warned = logged(log::Level::Warn, "io_uring requested but");
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert_eq!(
            warned[0],
            format!(
                "io_uring requested but {queues} queues x depth {depth} exceed the 32768 entries \
                 an io_uring holds (lower io_uring_queue_depth or raise n_threads); using \
                 /dev/fuse"
            )
        );
        assert!(
            logged(log::Level::Debug, "queues over").is_empty(),
            "no ring was created"
        );
        let bg = session.spawn().unwrap();
        assert_eq!(std::fs::read(m.path("hello.txt")).unwrap(), HELLO);
        assert_eq!(count_threads("fuser-ring-"), 0);
        bg.umount_and_join().unwrap();
        m.finish();
    }

    #[test]
    fn late_reply_after_the_connection_ended_is_not_an_error() {
        let _serial = serial();
        let send = |conn_dead: bool| {
            let commit = crate::uring::ring::test::refused_commit(conn_dead);
            <ReplyRaw as Reply>::new(ll::RequestId(7), ReplySender::Ring(commit))
                .send_ll(&ResponseEmpty);
        };
        // Scoped to the ring's causes: a /dev/fuse test running alongside may log the same
        // prefix at error
        let demoted = "Failed to send FUSE reply: reply after the connection ended";
        let duplicate = "Failed to send FUSE reply: duplicate reply";
        send(true);
        assert_eq!(logged(log::Level::Debug, demoted).len(), 1);
        assert!(logged(log::Level::Error, demoted).is_empty());
        send(false);
        assert_eq!(logged(log::Level::Error, duplicate).len(), 1);
        assert!(logged(log::Level::Debug, duplicate).is_empty());
    }

    /// The ring twin of `test::session_ends_cleanly_after_abort`
    #[test]
    fn ring_session_ends_cleanly_after_abort() {
        let _serial = serial();
        if let Some(why) = uring_unavailable() {
            eprintln!("skipping ring_session_ends_cleanly_after_abort: {why}");
            return;
        }
        let Some(_fusectl) = super::test::Fusectl::ensure() else {
            eprintln!("skipping ring_session_ends_cleanly_after_abort: no fusectl");
            return;
        };
        let m = Mounted::new();
        let fs = RingFs {
            abort_error: true,
            ..RingFs::default()
        };
        let session = m.session(fs, &ring_config());
        assert!(session.negotiated.contains(InitFlags::FUSE_ABORT_ERROR));
        let bg = session.spawn().unwrap();
        assert_eq!(std::fs::read(m.path("hello.txt")).unwrap(), HELLO);
        let abort_path =
            super::test::fusectl_abort_path(&m.mountpoint).expect("fusectl is mounted");
        std::fs::write(abort_path, b"1").unwrap();
        umount_and_join_within(bg, Duration::from_secs(5))
            .expect("session must end cleanly after the connection was aborted");
        let exited = logged(log::Level::Debug, "ring 0 exited");
        assert_eq!(
            exited,
            ["io_uring: ring 0 exited, in_kernel=0 outstanding=0"]
        );
        assert!(logged(log::Level::Error, "ring 0").is_empty());
        // The dead mount stays in the table after an abort, as after any abort
        let _ = nix::mount::umount2(&m.mountpoint, nix::mount::MntFlags::MNT_DETACH);
        m.finish();
    }

    /// Where the kernel advertises the transport the runtime tests must have run, not skipped
    #[test]
    fn fuse_over_io_uring_tests_ran() {
        let advertised = std::fs::read_to_string("/sys/module/fuse/parameters/enable_uring")
            .is_ok_and(|v| v.trim() == "Y");
        if !advertised {
            eprintln!("skipping fuse_over_io_uring_tests_ran: fuse.enable_uring is not Y");
            return;
        }
        if let Some(why) = uring_unavailable() {
            panic!("the kernel advertises FUSE_OVER_IO_URING but the ring tests skipped: {why}");
        }
    }

    /// `Session::from_fd` over a socketpair standing in for the kernel; `close_peer` closes the
    /// kernel end first so the INIT reply cannot be written
    fn from_fd_over_socketpair(
        flags: InitFlags,
        close_peer: bool,
        config: Config,
    ) -> (io::Result<Session<RingFs>>, OwnedFd) {
        use zerocopy::IntoBytes;

        use crate::ll::fuse_abi::fuse_in_header;
        use crate::ll::fuse_abi::fuse_init_in;
        use crate::ll::fuse_abi::fuse_opcode;
        use crate::uring::staging::test::in_header;

        let (kernel, daemon) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let (flags_lo, flags_hi) = (flags | InitFlags::FUSE_INIT_EXT).pair();
        let len = (size_of::<fuse_in_header>() + size_of::<fuse_init_in>()) as u32;
        let header = in_header(len, fuse_opcode::FUSE_INIT as u32, 1);
        let arg = fuse_init_in {
            major: 7,
            minor: 45,
            max_readahead: 65536,
            flags: flags_lo,
            flags2: flags_hi,
            unused: [0; 11],
        };
        let request = [&header[..], arg.as_bytes()].concat();
        // Queued bytes stay readable after the writer closes; the daemon's write then fails
        nix::unistd::write(&kernel, &request).unwrap();
        let kernel = if close_peer {
            drop(kernel);
            // A stand-in for the closed end, so the caller's binding is the same either way
            OwnedFd::from(File::open("/dev/null").unwrap())
        } else {
            kernel
        };
        (
            Session::from_fd(RingFs::default(), daemon, SessionACL::Owner, config),
            kernel,
        )
    }

    #[test]
    fn kernel_without_the_flag_falls_back_to_dev_fuse() {
        let _serial = serial();
        let (session, kernel) =
            from_fd_over_socketpair(InitFlags::FUSE_ASYNC_READ, false, ring_config());
        let session = session.unwrap();
        assert!(session.ring.is_none());
        assert!(!session.negotiated.contains(InitFlags::FUSE_OVER_IO_URING));
        assert_eq!(
            logged(log::Level::Warn, "io_uring requested but"),
            [
                "io_uring requested but the kernel did not advertise FUSE_OVER_IO_URING \
                 (fuse.enable_uring=N or kernel < 6.14); using /dev/fuse"
            ]
        );
        // fuse_out_header (16) then fuse_init_out; flags2 is at offset 32 of the latter
        let mut reply = [0u8; 256];
        let n = nix::unistd::read(&kernel, &mut reply).unwrap();
        assert!(n >= 16 + 36, "short INIT reply of {n} bytes");
        let flags2 = u32::from_ne_bytes(reply[16 + 32..16 + 36].try_into().unwrap());
        let (_, io_uring_hi) = InitFlags::FUSE_OVER_IO_URING.pair();
        assert_eq!(flags2 & io_uring_hi, 0);
        assert_eq!(count_threads("fuser-ring-"), 0);
    }

    #[test]
    fn unwritable_init_reply_fails_only_a_ring_session() {
        let _serial = serial();
        if let Err(e) = RingIo::open(8, 16) {
            eprintln!("skipping unwritable_init_reply_fails_only_a_ring_session: {e}");
            return;
        }
        let config = Config {
            io_uring_queue_depth: 1,
            ..ring_config()
        };
        let (session, _kernel) =
            from_fd_over_socketpair(InitFlags::FUSE_OVER_IO_URING, true, config);
        let err = session.err().expect("a ring session cannot go on");
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE), "{err}");
        assert_eq!(
            logged(log::Level::Debug, "queues over 1 rings, depth 1").len(),
            1
        );
        assert!(wait_ring_threads_gone(Duration::from_secs(5)));
        assert_eq!(
            wait_logged(log::Level::Debug, "detaching 1 ring threads", 1).len(),
            1
        );
        assert!(logged(log::Level::Debug, "ring 0 registered").is_empty());
        assert!(logged(log::Level::Error, &format!("leaking {}", reserved_bytes(1))).is_empty());
        assert!(logged(log::Level::Error, "Failed to send FUSE reply: Broken pipe").is_empty());

        let (session, _kernel) =
            from_fd_over_socketpair(InitFlags::FUSE_OVER_IO_URING, true, Config::default());
        assert!(
            session.is_ok(),
            "a /dev/fuse session is failed by its event loop"
        );
        assert_eq!(
            logged(log::Level::Error, "Failed to send FUSE reply: Broken pipe").len(),
            1
        );
    }
}
