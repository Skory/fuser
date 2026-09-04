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

use std::fs;
use std::io;

use nix::unistd::SysconfVar;

/// The kernel's `cpu_possible_mask`, which is the number of queues `REGISTER` must populate
/// before the connection becomes ready.
const POSSIBLE_CPUS: &str = "/sys/devices/system/cpu/possible";

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
