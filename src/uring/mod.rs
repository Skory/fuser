//! FUSE-over-io_uring transport (kernel protocol 7.42 and later).
//!
//! Userspace registers per-CPU queues of entries with `IORING_OP_URING_CMD` SQEs on an SQE128
//! ring. The kernel fills an entry with a request and posts a CQE; the reply is written into the
//! same entry and committed with `COMMIT_AND_FETCH`, which re-arms the entry. Every SQE of a ring
//! is submitted by that ring's own thread, because the kernel delivers the next request into an
//! entry as task work of the task that submitted the entry's SQE.

pub(crate) mod mem;
pub(crate) mod ring;
pub(crate) mod staging;

use std::fmt;
use std::fs;
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::JoinHandle;

use log::debug;
use nix::unistd::SysconfVar;

use crate::dev_fuse::DevFuse;
use crate::session::spawn_named;
use crate::uring::ring::FetchHandler;
use crate::uring::ring::IORING_MAX_ENTRIES;
use crate::uring::ring::Ring;
use crate::uring::ring::RingIo;
use crate::uring::ring::ring_sizes;

/// The kernel's `cpu_possible_mask`, which is the number of queues `REGISTER` must populate
/// before the connection becomes ready.
const POSSIBLE_CPUS: &str = "/sys/devices/system/cpu/possible";

/// Every ring of a session and the thread serving each.
///
/// Created before the INIT reply with the threads parked, so that any failure here leaves the
/// session free to use `/dev/fuse` instead. `start` registers the queues once the reply that
/// committed the kernel to them was written; the session hands each thread its handler when
/// it runs. Dropping the set detaches the threads, whose exit depends on the kernel ending
/// the connection.
pub(crate) struct RingSet {
    rings: Vec<Arc<Ring>>,
    threads: Vec<JoinHandle<io::Result<()>>>,
    go: Vec<mpsc::Sender<()>>,
    registered: Vec<mpsc::Receiver<io::Result<()>>>,
    handler_tx: Vec<mpsc::Sender<Box<dyn FetchHandler>>>,
}

impl fmt::Debug for RingSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingSet")
            .field("rings", &self.rings.len())
            .finish_non_exhaustive()
    }
}

impl RingSet {
    /// Opens the io_urings of `min(n_threads, queues)` rings over every possible CPU's queue,
    /// reserves their buffers and spawns their parked threads. The error text names what
    /// failed, for the session's fallback warning.
    pub(crate) fn new(
        device: Arc<DevFuse>,
        mounted: bool,
        n_threads: usize,
        depth: u32,
        payload_cap: usize,
    ) -> io::Result<Self> {
        let n_queues = possible_cpus().map_err(|err| {
            io::Error::other(format!("the possible CPU count is unknown ({err})"))
        })?;
        let rings = partition(n_queues, n_threads);
        // Beyond the largest ring the completion queue overflows and fetches can be lost
        let largest = rings.iter().map(Vec::len).max().unwrap_or(0);
        let entries = largest.checked_mul(depth as usize).unwrap_or(usize::MAX);
        if entries > IORING_MAX_ENTRIES {
            return Err(io::Error::other(format!(
                "{largest} queues x depth {depth} exceed the {IORING_MAX_ENTRIES} entries an \
                 io_uring holds (lower io_uring_queue_depth or raise n_threads)"
            )));
        }
        let mut set = Self {
            rings: Vec::new(),
            threads: Vec::new(),
            go: Vec::new(),
            registered: Vec::new(),
            handler_tx: Vec::new(),
        };
        let mut bodies = Vec::new();
        for (index, qids) in rings.into_iter().enumerate() {
            // The cheapest and likeliest refusal (a sandbox without io_uring) comes first
            let (sq, cq) = ring_sizes(qids.len() * depth as usize);
            let io = RingIo::open(sq, cq)
                .map_err(|err| io::Error::other(format!("io_uring_setup failed ({err})")))?;
            let ring = Ring::new(index, mounted, device.clone(), &qids, depth, payload_cap)?;
            let (go_tx, go_rx) = mpsc::channel();
            let (registered_tx, registered_rx) = mpsc::channel();
            let (handler_tx, handler_rx) = mpsc::channel();
            bodies.push((format!("fuser-ring-{index}"), {
                let ring = Arc::clone(&ring);
                move || ring.thread_main(io, go_rx, registered_tx, handler_rx)
            }));
            set.rings.push(ring);
            set.go.push(go_tx);
            set.registered.push(registered_rx);
            set.handler_tx.push(handler_tx);
        }
        set.threads = spawn_named(bodies)
            .map_err(|err| io::Error::other(format!("creating the ring threads failed ({err})")))?;
        debug!(
            "io_uring: {n_queues} queues over {} rings, depth {depth}, payload {payload_cap} \
             bytes per entry, {} bytes reserved",
            set.rings.len(),
            set.rings.iter().map(|r| r.reserved_bytes()).sum::<usize>()
        );
        Ok(set)
    }

    /// Releases the parked threads to register their queues and waits for every ring's
    /// REGISTER submit. Only valid once the INIT reply echoing the flag was written; an
    /// error here leaves the mount blocked on queues nobody serves, so the caller must end
    /// the session. The rings that did register are abandoned, mounted or not: a caller that
    /// entered the mount after the INIT reply is blocked holding a path reference, so the
    /// unmount alone cannot end the connection, and only cancelling the registered commands
    /// releases their `/dev/fuse` references so that it aborts once the session's own are gone.
    pub(crate) fn start(&mut self) -> io::Result<()> {
        for go in self.go.drain(..) {
            // A thread that is already gone shows up as a disconnected `registered` below
            let _ = go.send(());
        }
        for (index, registered) in self.registered.drain(..).enumerate() {
            let result = registered.recv().map_err(|_| {
                io::Error::other(format!(
                    "io_uring: ring {index} thread exited before registering"
                ))
            });
            if let Err(err) = result.and_then(|r| r) {
                for ring in &self.rings {
                    ring.abandon();
                }
                self.handler_tx.clear();
                return Err(err);
            }
        }
        Ok(())
    }

    /// Hands every ring thread the handler `make(index)` builds for it.
    pub(crate) fn serve(
        &self,
        mut make: impl FnMut(usize) -> Box<dyn FetchHandler>,
    ) -> io::Result<()> {
        for (index, handler_tx) in self.handler_tx.iter().enumerate() {
            handler_tx.send(make(index)).map_err(|_| {
                io::Error::other(format!(
                    "io_uring: ring {index} thread exited before serving"
                ))
            })?;
        }
        Ok(())
    }

    /// Tells every ring thread to leave once its kernel commands completed. Call after the
    /// connection ended, since requests still held by userspace are dropped.
    pub(crate) fn shutdown(&self) {
        for ring in &self.rings {
            ring.shutdown();
        }
    }

    /// The ring threads, for the session to join after `shutdown`.
    pub(crate) fn take_threads(&mut self) -> Vec<JoinHandle<io::Result<()>>> {
        std::mem::take(&mut self.threads)
    }
}

impl Drop for RingSet {
    /// Threads still attached here were never joined by `run`. They are not joined now:
    /// dropping `go` ends a thread that never registered, and dropping `handler_tx` makes a
    /// registered one drain to the end of the connection, which nothing here can wait for.
    /// Threads `run` took but did not join are serving a connection that is still alive, so
    /// they are left to exit with it.
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            self.shutdown();
            debug!("io_uring: detaching {} ring threads", self.threads.len());
        }
    }
}

/// Number of queues the kernel expects, from `num_possible_cpus()`.
///
/// `sysconf(_SC_NPROCESSORS_CONF)` counts present CPUs, which on hotplug-capable VMs is less
/// than the possible count; registering that many queues would leave every request on the mount
/// blocked. So only sysfs is consulted, and a value below the present count means the file
/// is not what this expects. Callers fall back to `/dev/fuse` on `Err`.
pub(crate) fn possible_cpus() -> io::Result<u16> {
    let text = fs::read_to_string(POSSIBLE_CPUS)?;
    let count = possible_cpus_parse(&text)?;
    let present = nix::unistd::sysconf(SysconfVar::_NPROCESSORS_CONF)
        .ok()
        .flatten()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0);
    if count < present {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{POSSIBLE_CPUS} lists {count} CPUs but {present} are present"),
        ));
    }
    u16::try_from(count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{count} possible CPUs exceed the 16-bit queue id"),
        )
    })
}

/// Counts the CPUs in a sysfs CPU list such as `0-3,8-11`.
fn possible_cpus_parse(text: &str) -> io::Result<usize> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot parse CPU list {text:?}"),
        )
    };
    let mut count = 0usize;
    for range in text.trim().split(',') {
        let (lo, hi) = match range.split_once('-') {
            Some((lo, hi)) => (lo, hi),
            None => (range, range),
        };
        let lo: usize = lo.parse().map_err(|_| invalid())?;
        let hi: usize = hi.parse().map_err(|_| invalid())?;
        if hi < lo {
            return Err(invalid());
        }
        count = count.checked_add(hi - lo + 1).ok_or_else(invalid)?;
    }
    if count == 0 {
        return Err(invalid());
    }
    Ok(count)
}

/// Assigns the queues `0..n_queues` round-robin to `min(n_threads, n_queues)` rings. Ring `r`
/// owns queue `q` when `q % rings == r`, so every queue belongs to exactly one ring.
pub(crate) fn partition(n_queues: u16, n_threads: usize) -> Vec<Vec<u16>> {
    let rings = n_threads.max(1).min(usize::from(n_queues));
    (0..rings)
        .map(|r| {
            (r..usize::from(n_queues))
                .step_by(rings)
                .map(|q| q as u16)
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_cpu_lists() {
        assert_eq!(possible_cpus_parse("0-447\n").unwrap(), 448);
        assert_eq!(possible_cpus_parse("0").unwrap(), 1);
        assert_eq!(possible_cpus_parse("0-3,8-11").unwrap(), 8);
        for garbage in ["", "\n", "abc", "3-1", "0-", "-1", "0,,1"] {
            let err = possible_cpus_parse(garbage).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{garbage:?}");
        }
    }

    /// The sanity check accepts the dev host's own file, and the parsed count is at least
    /// the present CPU count it is checked against
    #[test]
    fn possible_cpus_agrees_with_sysfs() {
        let count = possible_cpus().unwrap();
        let text = fs::read_to_string(POSSIBLE_CPUS).unwrap();
        assert_eq!(usize::from(count), possible_cpus_parse(&text).unwrap());
        let present = nix::unistd::sysconf(SysconfVar::_NPROCESSORS_CONF)
            .unwrap()
            .unwrap();
        assert!(i64::from(count) >= present);
    }

    /// A depth the largest ring cannot hold is refused before an io_uring is opened or a
    /// buffer reserved, so the session falls back to `/dev/fuse`
    #[test]
    fn oversized_depth_is_refused_up_front() {
        let device = Arc::new(DevFuse(fs::File::open("/dev/zero").unwrap()));
        let queues = usize::from(possible_cpus().unwrap());
        let depth = (IORING_MAX_ENTRIES / queues + 1) as u32;
        let err = RingSet::new(device.clone(), true, 1, depth, 8192).unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("{queues} queues x depth {depth} exceed")),
            "{err}"
        );
        assert!(RingSet::new(device, true, 1, u32::MAX, 8192).is_err());
    }

    #[test]
    fn partition_is_round_robin_and_complete() {
        let one = partition(448, 1);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].len(), 448);
        assert_eq!(one[0], (0..448).collect::<Vec<u16>>());

        let three = partition(448, 3);
        assert_eq!(
            three.iter().map(Vec::len).collect::<Vec<_>>(),
            [150, 149, 149]
        );
        let mut all: Vec<u16> = three.iter().flatten().copied().collect();
        all.sort_unstable();
        assert_eq!(all, (0..448).collect::<Vec<u16>>());
        for (r, qids) in three.iter().enumerate() {
            assert!(qids.iter().all(|&q| usize::from(q) % 3 == r));
        }

        // More threads than queues clamps to one ring per queue; zero threads means one ring
        assert_eq!(partition(4, 16), [[0], [1], [2], [3]]);
        assert_eq!(partition(4, 0), [[0, 1, 2, 3]]);
        assert!(partition(0, 3).is_empty());
    }
}
