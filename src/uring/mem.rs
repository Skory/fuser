//! Buffer layout of a ring: one anonymous mapping holding every entry's stride.
//!
//! ```text
//! entry e at base + e * stride, stride = HEADER_AREA + payload_cap, HEADER_AREA = PAGE_SIZE
//!   [0, 288)                 fuse_uring_req_header, iov[0]        kernel owned while a SQE is pending
//!   [GAP - 168, GAP)         staging: fuse_in_header + op_in copy, ends at GAP
//!   [GAP, GAP + payload_cap) payload, iov[1]                      kernel owned while a SQE is pending
//! ```
//!
//! The staging copy makes the request contiguous for the unchanged `/dev/fuse` parser: the
//! header lands 8-byte aligned because `base`, `stride` and `GAP` are page multiples.

use std::io;
use std::mem::offset_of;
use std::num::NonZeroUsize;
use std::ptr::NonNull;

use nix::sys::mman::MapFlags;
use nix::sys::mman::MmapAdvise;
use nix::sys::mman::ProtFlags;

use crate::ll::fuse_abi as abi;

/// Bytes of `fuse_uring_req_header`, `iov[0]` of a REGISTER.
pub(crate) const HEADER_SZ: usize = size_of::<abi::fuse_uring_req_header>();
/// Largest staged request prefix: `fuse_in_header` plus a full `op_in`.
pub(crate) const STAGING_SZ: usize =
    size_of::<abi::fuse_in_header>() + abi::FUSE_URING_OP_IN_OUT_SZ;
pub(crate) const OP_IN_OFFSET: usize = offset_of!(abi::fuse_uring_req_header, op_in);
const ENT_IN_OUT_OFFSET: usize = offset_of!(abi::fuse_uring_req_header, ring_ent_in_out);
pub(crate) const FLAGS_OFFSET: usize =
    ENT_IN_OUT_OFFSET + offset_of!(abi::fuse_uring_ent_in_out, flags);
pub(crate) const COMMIT_ID_OFFSET: usize =
    ENT_IN_OUT_OFFSET + offset_of!(abi::fuse_uring_ent_in_out, commit_id);
pub(crate) const PAYLOAD_SZ_OFFSET: usize =
    ENT_IN_OUT_OFFSET + offset_of!(abi::fuse_uring_ent_in_out, payload_sz);

/// Size of the header area of every entry, and so the offset of its payload.
pub(crate) fn header_area() -> usize {
    page_size::get()
}

/// The buffers of one ring. Unmapped on drop, so the owner must only drop it once no SQE
/// naming the buffers is pending in the kernel.
#[derive(Debug)]
pub(crate) struct RingMemory {
    base: NonNull<u8>,
    len: usize,
    stride: usize,
    payload_cap: usize,
    entries: usize,
}

// SAFETY: the mapping is plain memory owned by this value; the pointer is only ever used
// through the raw-pointer discipline of the ring, never as a shared Rust reference.
unsafe impl Send for RingMemory {}
unsafe impl Sync for RingMemory {}

impl RingMemory {
    /// Reserves address space for `entries` strides. `payload_cap` is rounded up to a page
    /// multiple so every header is page aligned, and must fit `payload_sz: u32`.
    pub(crate) fn new(entries: usize, payload_cap: usize) -> io::Result<Self> {
        let page = header_area();
        if page < HEADER_SZ + STAGING_SZ {
            return Err(io::Error::other(format!(
                "page size {page} cannot hold the {HEADER_SZ} byte header and {STAGING_SZ} \
                 byte staging area"
            )));
        }
        let overflow = || io::Error::other("ring buffer size overflows the address space");
        let payload_cap = payload_cap
            .checked_next_multiple_of(page)
            .filter(|cap| u32::try_from(*cap).is_ok())
            .ok_or_else(overflow)?;
        let stride = page.checked_add(payload_cap).ok_or_else(overflow)?;
        let len = entries
            .checked_mul(stride)
            .and_then(NonZeroUsize::new)
            .ok_or_else(overflow)?;
        let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_NORESERVE;
        // SAFETY: an anonymous private mapping at a kernel-chosen address aliases nothing.
        let base = unsafe {
            nix::sys::mman::mmap_anonymous(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                flags,
            )?
        };
        let mem = Self {
            base: base.cast(),
            len: len.get(),
            stride,
            payload_cap,
            entries,
        };
        // The kernel writes into these buffers on behalf of this process only
        // SAFETY: the range is the mapping just created.
        unsafe { nix::sys::mman::madvise(base, mem.len, MmapAdvise::MADV_DONTFORK)? };
        Ok(mem)
    }

    /// Offset of the payload within a stride; the staging area ends here.
    pub(crate) fn gap(&self) -> usize {
        self.stride - self.payload_cap
    }

    pub(crate) fn payload_cap(&self) -> usize {
        self.payload_cap
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Start of entry `e`'s stride.
    pub(crate) fn entry(&self, e: usize) -> NonNull<u8> {
        assert!(e < self.entries, "entry {e} of {}", self.entries);
        // SAFETY: e * stride < len, so the result stays inside the mapping.
        unsafe { self.base.add(e * self.stride) }
    }
}

impl Drop for RingMemory {
    fn drop(&mut self) {
        // SAFETY: base/len describe the mapping created in `new`, which nothing else unmaps.
        let _ = unsafe { nix::sys::mman::munmap(self.base.cast(), self.len) };
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::fs;

    use super::*;

    /// Held by every test that asserts a mapping is gone: a concurrent test's mapping of the
    /// same size would otherwise be placed exactly where the unmapped one was
    pub(crate) static UNMAP_CHECK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// A mapping large enough that the small mappings of concurrent tests, which the kernel
    /// places top-down in a freed hole, never reach its base. `None` (with a message) when
    /// the host refuses the reservation, as `vm.overcommit_memory=2` does
    pub(crate) fn try_big(entries: usize) -> Option<RingMemory> {
        match RingMemory::new(entries, 1 << 30) {
            Ok(mem) => Some(mem),
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                eprintln!("skipping: cannot reserve {entries} GiB of address space: {e}");
                None
            }
            Err(e) => panic!("mmap: {e}"),
        }
    }

    /// The `/proc/self/maps` line covering `addr`, if any. Containment rather than a start
    /// address because the kernel merges adjacent anonymous mappings
    fn mapping_of(addr: usize) -> Option<String> {
        let maps = fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines()
            .find(|line| {
                let range = line.split(' ').next().unwrap();
                let (start, end) = range.split_once('-').unwrap();
                let start = usize::from_str_radix(start, 16).unwrap();
                let end = usize::from_str_radix(end, 16).unwrap();
                (start..end).contains(&addr)
            })
            .map(str::to_owned)
    }

    pub(crate) fn is_mapped(addr: usize) -> bool {
        mapping_of(addr).is_some()
    }

    fn vm_flags(addr: usize) -> String {
        let range = mapping_of(addr).unwrap();
        let range = range.split(' ').next().unwrap().to_owned();
        let smaps = fs::read_to_string("/proc/self/smaps").unwrap();
        let mut lines = smaps.lines().skip_while(|l| !l.starts_with(&range));
        lines.next().unwrap();
        lines
            .find_map(|l| l.strip_prefix("VmFlags:"))
            .unwrap()
            .trim()
            .to_owned()
    }

    #[test]
    fn layout_offsets() {
        assert_eq!(HEADER_SZ, 288);
        assert_eq!(STAGING_SZ, 168);
        assert_eq!(OP_IN_OFFSET, 128);
        assert_eq!(FLAGS_OFFSET, 256);
        assert_eq!(COMMIT_ID_OFFSET, 264);
        assert_eq!(PAYLOAD_SZ_OFFSET, 272);
        assert!(header_area() >= HEADER_SZ + STAGING_SZ);
    }

    #[test]
    fn strides_are_page_aligned_and_unmapped_on_drop() {
        let _serial = UNMAP_CHECK.lock();
        let page = page_size::get();
        let Some(mem) = try_big(3) else { return };
        let base = mem.entry(0).as_ptr() as usize;
        let stride = mem.entry(1).as_ptr() as usize - base;
        assert_eq!(base % page, 0);
        assert_eq!(stride, page + (1 << 30));
        assert_eq!(mem.gap(), page);
        assert_eq!(mem.payload_cap(), 1 << 30);
        assert_eq!(mem.len(), 3 * stride);
        for e in 0..3 {
            let entry = mem.entry(e).as_ptr() as usize;
            assert_eq!(entry, base + e * stride);
            assert_eq!(entry % page, 0);
            assert_eq!(
                (entry + mem.gap() - size_of::<abi::fuse_in_header>()) % 8,
                0
            );
        }
        assert!(is_mapped(base));
        let vm_flags = vm_flags(base);
        let flags: Vec<&str> = vm_flags.split(' ').collect();
        assert!(flags.contains(&"dc"), "MADV_DONTFORK: {flags:?}");
        assert!(flags.contains(&"nr"), "MAP_NORESERVE: {flags:?}");
        drop(mem);
        assert!(!is_mapped(base));
    }

    #[test]
    fn payload_cap_rounds_up_to_a_page() {
        let page = page_size::get();
        let mem = RingMemory::new(1, 8192 + 1).unwrap();
        assert_eq!(mem.payload_cap(), 8193usize.next_multiple_of(page));
        assert_eq!(RingMemory::new(1, page).unwrap().payload_cap(), page);
    }

    #[test]
    fn rejects_sizes_that_do_not_fit() {
        assert!(RingMemory::new(usize::MAX, 4096).is_err());
        assert!(RingMemory::new(0, 4096).is_err());
        assert!(RingMemory::new(1, usize::MAX - 4096).is_err());
        assert!(RingMemory::new(1, 1 << 32).is_err(), "payload_sz is a u32");
    }
}
