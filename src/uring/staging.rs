//! Turns a fetched entry into the contiguous request bytes the `/dev/fuse` parser expects.
//!
//! Works on raw pointers only: the kernel writes the header and payload of an entry whenever
//! its SQE is pending, so no Rust reference over the stride may outlive one fetch.

use std::ptr;
use std::ptr::NonNull;

use crate::ll::fuse_abi as abi;
use crate::uring::mem::COMMIT_ID_OFFSET;
use crate::uring::mem::HEADER_SZ;
use crate::uring::mem::OP_IN_OFFSET;
use crate::uring::mem::PAYLOAD_SZ_OFFSET;
use crate::uring::mem::STAGING_SZ;

const IN_HEADER_SZ: usize = size_of::<abi::fuse_in_header>();

/// A fetched request, staged so that `[req, req + len)` is one contiguous, 8-byte aligned
/// `fuse_in_header` followed by the op arguments and payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Staged {
    pub(crate) commit_id: u64,
    pub(crate) payload_sz: u32,
    pub(crate) req: NonNull<u8>,
    pub(crate) len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagingError {
    /// The kernel never hands out `commit_id` 0; nothing can be committed for this fetch.
    ZeroCommitId,
    /// The lengths do not describe a request; `commit_id` lets the caller reply `EIO`.
    Malformed {
        commit_id: u64,
        in_len: u32,
        payload_sz: u32,
    },
}

/// Copies `in_out[0..40]` and `op_in[0..op_in_len]` to the bytes just before `gap`, where
/// `op_in_len = in_header.len - 40 - payload_sz`, so the request continues into the payload.
///
/// # Safety
///
/// `entry` is the start of a stride of at least `gap + payload_cap` writable bytes whose SQE
/// has completed, `gap >= HEADER_SZ + STAGING_SZ` so the staging area is disjoint from the
/// header, and no Rust reference into the stride is live.
pub(crate) unsafe fn stage_request(
    entry: NonNull<u8>,
    gap: usize,
    payload_cap: usize,
) -> Result<Staged, StagingError> {
    debug_assert!(gap >= HEADER_SZ + STAGING_SZ);
    // SAFETY: the offsets are inside the 288-byte header at the start of the stride; reads are
    // unaligned so no reference is formed over kernel-shared memory.
    let (commit_id, payload_sz, in_len) = unsafe {
        (
            ptr::read_unaligned(entry.add(COMMIT_ID_OFFSET).as_ptr().cast::<u64>()),
            ptr::read_unaligned(entry.add(PAYLOAD_SZ_OFFSET).as_ptr().cast::<u32>()),
            ptr::read_unaligned(entry.as_ptr().cast::<u32>()),
        )
    };
    if commit_id == 0 {
        return Err(StagingError::ZeroCommitId);
    }
    let malformed = StagingError::Malformed {
        commit_id,
        in_len,
        payload_sz,
    };
    let payload_sz_u = payload_sz as usize;
    let op_in_len = (in_len as usize)
        .checked_sub(IN_HEADER_SZ + payload_sz_u)
        .ok_or(malformed)?;
    if payload_sz_u > payload_cap || op_in_len > abi::FUSE_URING_OP_IN_OUT_SZ || op_in_len % 8 != 0
    {
        return Err(malformed);
    }
    let req_offset = gap - IN_HEADER_SZ - op_in_len;
    // SAFETY: the staging area [gap - 168, gap) and the header [0, 288) are disjoint because
    // the caller guarantees gap >= 456, so the copies neither overlap nor leave the stride.
    unsafe {
        ptr::copy_nonoverlapping(entry.as_ptr(), entry.add(req_offset).as_ptr(), IN_HEADER_SZ);
        ptr::copy_nonoverlapping(
            entry.add(OP_IN_OFFSET).as_ptr(),
            entry.add(gap - op_in_len).as_ptr(),
            op_in_len,
        );
    }
    Ok(Staged {
        commit_id,
        payload_sz,
        // SAFETY: req_offset < gap, inside the stride.
        req: unsafe { entry.add(req_offset) },
        len: in_len as usize,
    })
}

#[cfg(test)]
pub(crate) mod test {
    use std::slice;

    use zerocopy::IntoBytes;

    use super::*;
    use crate::ll::AnyRequest;
    use crate::ll::Operation;
    use crate::ll::fuse_abi::fuse_opcode;

    pub(crate) const GAP: usize = 4096;
    pub(crate) const CAP: usize = 8192;

    /// The parser needs the staged header 8-byte aligned, as the mapping guarantees. The
    /// bytes are only ever reached through `FakeEntry::ptr`
    #[repr(align(8))]
    struct Stride {
        _bytes: [u8; GAP + CAP],
    }

    /// A heap stride standing in for one entry. Held as a raw pointer so that Miri checks the
    /// aliasing discipline of the code under test rather than the fixture
    pub(crate) struct FakeEntry(NonNull<Stride>);

    impl FakeEntry {
        pub(crate) fn new() -> Self {
            Self(NonNull::from(Box::leak(Box::new(Stride {
                _bytes: [0; GAP + CAP],
            }))))
        }

        pub(crate) fn ptr(&self) -> NonNull<u8> {
            self.0.cast()
        }

        /// What the kernel writes on fetch: in_header, `in_args[0]`, payload, trailer
        pub(crate) fn fill(&self, unique: u64, opcode: fuse_opcode, op_in: &[u8], payload: &[u8]) {
            let len = (IN_HEADER_SZ + op_in.len() + payload.len()) as u32;
            let header = in_header(len, opcode as u32, unique);
            self.fill_raw(&header, op_in, payload, unique, payload.len() as u32);
        }

        pub(crate) fn fill_raw(
            &self,
            in_header: &[u8],
            op_in: &[u8],
            payload: &[u8],
            commit_id: u64,
            payload_sz: u32,
        ) {
            self.write(0, in_header);
            self.write(OP_IN_OFFSET, op_in);
            self.write(COMMIT_ID_OFFSET, &commit_id.to_ne_bytes());
            self.write(PAYLOAD_SZ_OFFSET, &payload_sz.to_ne_bytes());
            self.write(GAP, payload);
        }

        pub(crate) fn write(&self, offset: usize, bytes: &[u8]) {
            assert!(offset + bytes.len() <= GAP + CAP);
            // SAFETY: in bounds, and no reference into the stride is ever live.
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.ptr().add(offset).as_ptr(),
                    bytes.len(),
                );
            }
        }

        pub(crate) fn read(&self, range: std::ops::Range<usize>) -> Vec<u8> {
            assert!(range.end <= GAP + CAP);
            let mut out = vec![0; range.len()];
            // SAFETY: in bounds, and no reference into the stride is ever live.
            unsafe {
                ptr::copy_nonoverlapping(
                    self.ptr().add(range.start).as_ptr(),
                    out.as_mut_ptr(),
                    range.len(),
                );
            }
            out
        }
    }

    impl Drop for FakeEntry {
        fn drop(&mut self) {
            // SAFETY: created by Box::leak in `new`, never freed elsewhere, no reference live.
            drop(unsafe { Box::from_raw(self.0.as_ptr()) });
        }
    }

    /// `fuse_in_header` bytes: len, opcode, unique, nodeid 1, uid/gid 1000, pid 4242
    pub(crate) fn in_header(len: u32, opcode: u32, unique: u64) -> [u8; IN_HEADER_SZ] {
        let mut h = [0u8; IN_HEADER_SZ];
        h[0..4].copy_from_slice(&len.to_ne_bytes());
        h[4..8].copy_from_slice(&opcode.to_ne_bytes());
        h[8..16].copy_from_slice(&unique.to_ne_bytes());
        h[16..24].copy_from_slice(&1u64.to_ne_bytes());
        h[24..28].copy_from_slice(&1000u32.to_ne_bytes());
        h[28..32].copy_from_slice(&1000u32.to_ne_bytes());
        h[32..36].copy_from_slice(&4242u32.to_ne_bytes());
        h
    }

    fn stage(e: &FakeEntry) -> Result<Staged, StagingError> {
        // SAFETY: the box holds GAP + CAP bytes and no reference into it is live.
        unsafe { stage_request(e.ptr(), GAP, CAP) }
    }

    fn request(s: &Staged) -> &[u8] {
        // SAFETY: the staged range lies inside the fake entry, which outlives the slice.
        unsafe { slice::from_raw_parts(s.req.as_ptr(), s.len) }
    }

    #[test]
    fn lookup_without_op_in_parses() {
        let e = FakeEntry::new();
        e.fill(7, fuse_opcode::FUSE_LOOKUP, &[], b"hello\0");
        let s = stage(&e).unwrap();
        assert_eq!(s.commit_id, 7);
        assert_eq!(s.payload_sz, 6);
        assert_eq!(s.len, IN_HEADER_SZ + 6);
        assert_eq!(
            s.req.as_ptr() as usize,
            e.ptr().as_ptr() as usize + GAP - IN_HEADER_SZ
        );
        let req = AnyRequest::try_from(request(&s)).unwrap();
        assert_eq!(req.unique().0, 7);
        assert_eq!(req.header().len as usize, s.len);
        // The whole header was copied, not just the leading fields
        assert_eq!(req.nodeid().0, 1);
        assert_eq!(req.uid().as_raw(), 1000);
        assert_eq!(req.header().gid, 1000);
        assert_eq!(req.header().pid, 4242);
        match req.operation().unwrap() {
            Operation::Lookup(l) => assert_eq!(l.name().to_str().unwrap(), "hello"),
            other => panic!("{other:?}"),
        }
    }

    /// The largest accepted prefix (op_in full), the largest payload, and the smallest request
    #[test]
    fn accepts_the_boundaries() {
        let e = FakeEntry::new();
        let getattr = fuse_opcode::FUSE_GETATTR as u32;
        e.fill_raw(
            &in_header((IN_HEADER_SZ + 128) as u32, getattr, 11),
            &[7; 128],
            &[],
            11,
            0,
        );
        let s = stage(&e).unwrap();
        assert_eq!(
            s.req.as_ptr() as usize,
            e.ptr().as_ptr() as usize + GAP - STAGING_SZ
        );
        assert_eq!(s.len, IN_HEADER_SZ + 128);
        assert_eq!(AnyRequest::try_from(request(&s)).unwrap().unique().0, 11);
        assert_eq!(e.read(GAP - 128..GAP), [7; 128]);

        let e = FakeEntry::new();
        let payload = vec![9u8; CAP];
        e.fill(12, fuse_opcode::FUSE_LOOKUP, &[], &payload);
        let s = stage(&e).unwrap();
        assert_eq!(s.payload_sz as usize, CAP);
        assert_eq!(s.len, IN_HEADER_SZ + CAP);
        assert_eq!(AnyRequest::try_from(request(&s)).unwrap().unique().0, 12);

        let e = FakeEntry::new();
        e.fill(13, fuse_opcode::FUSE_STATFS, &[], &[]);
        let s = stage(&e).unwrap();
        assert_eq!(
            s.req.as_ptr() as usize,
            e.ptr().as_ptr() as usize + GAP - IN_HEADER_SZ
        );
        assert_eq!(s.len, IN_HEADER_SZ);
        let req = AnyRequest::try_from(request(&s)).unwrap();
        assert!(matches!(req.operation().unwrap(), Operation::StatFs(_)));
    }

    #[test]
    fn write_with_op_in_and_payload_parses() {
        let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        // fuse_write_in: fh, offset, size, write_flags, lock_owner, flags, padding
        let mut arg = Vec::new();
        arg.extend_from_slice(&3u64.to_ne_bytes());
        arg.extend_from_slice(&512i64.to_ne_bytes());
        arg.extend_from_slice(&(data.len() as u32).to_ne_bytes());
        arg.extend_from_slice(&0u32.to_ne_bytes());
        arg.extend_from_slice(&9u64.to_ne_bytes());
        arg.extend_from_slice(&[0; 8]);
        assert_eq!(arg.len(), size_of::<abi::fuse_write_in>());
        let e = FakeEntry::new();
        e.fill(8, fuse_opcode::FUSE_WRITE, &arg, &data);
        let s = stage(&e).unwrap();
        assert_eq!(
            s.len,
            IN_HEADER_SZ + size_of::<abi::fuse_write_in>() + data.len()
        );
        let req = AnyRequest::try_from(request(&s)).unwrap();
        match req.operation().unwrap() {
            Operation::Write(w) => {
                assert_eq!(w.file_handle().0, 3);
                assert_eq!(w.offset().unwrap(), 512);
                assert_eq!(w.lock_owner(), None, "FUSE_WRITE_LOCKOWNER not set");
                assert_eq!(w.data(), &data[..]);
                // The payload is used in place, not copied
                assert_eq!(w.data().as_ptr() as usize, e.ptr().as_ptr() as usize + GAP);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        let e = FakeEntry::new();
        // op_in_len 12 is not a multiple of 8
        e.fill(1, fuse_opcode::FUSE_GETATTR, &[0; 12], &[]);
        assert!(matches!(
            stage(&e),
            Err(StagingError::Malformed { commit_id: 1, .. })
        ));

        // payload_sz larger than the buffer
        let e = FakeEntry::new();
        let write = fuse_opcode::FUSE_WRITE as u32;
        let header = in_header((IN_HEADER_SZ + CAP + 8) as u32, write, 2);
        e.fill_raw(&header, &[], &[], 2, (CAP + 8) as u32);
        assert!(matches!(
            stage(&e),
            Err(StagingError::Malformed {
                commit_id: 2,
                payload_sz,
                ..
            }) if payload_sz as usize == CAP + 8
        ));

        // op_in_len over 128
        let e = FakeEntry::new();
        e.fill_raw(
            &in_header((IN_HEADER_SZ + 136) as u32, write, 3),
            &[],
            &[],
            3,
            0,
        );
        assert!(matches!(
            stage(&e),
            Err(StagingError::Malformed { commit_id: 3, .. })
        ));

        // in_len shorter than the header
        e.fill_raw(&in_header(8, write, 3), &[], &[], 3, 0);
        assert!(matches!(
            stage(&e),
            Err(StagingError::Malformed { in_len: 8, .. })
        ));

        // in_len shorter than header plus payload
        e.fill_raw(
            &in_header((IN_HEADER_SZ + 4) as u32, write, 3),
            &[],
            &[0; 8],
            3,
            8,
        );
        assert!(matches!(stage(&e), Err(StagingError::Malformed { .. })));
    }

    #[test]
    fn rejects_commit_id_zero() {
        let e = FakeEntry::new();
        e.fill(0, fuse_opcode::FUSE_LOOKUP, &[], b"x\0");
        assert_eq!(stage(&e).unwrap_err(), StagingError::ZeroCommitId);
    }

    /// Miri check: `cargo +nightly miri test --features io-uring staging::`
    #[test]
    fn no_reference_survives_a_fetch() {
        let e = FakeEntry::new();
        e.fill(5, fuse_opcode::FUSE_LOOKUP, &[], b"a\0");
        let s = stage(&e).unwrap();
        let unique = AnyRequest::try_from(request(&s)).unwrap().unique().0;
        assert_eq!(unique, 5);
        let out = abi::fuse_out_header {
            len: 16,
            error: 0,
            unique,
        };
        // The request slice is gone before the reply is written
        e.write(0, out.as_bytes());
        e.write(PAYLOAD_SZ_OFFSET, &0u32.to_ne_bytes());
        e.fill(6, fuse_opcode::FUSE_LOOKUP, &[], b"bb\0");
        let s = stage(&e).unwrap();
        assert_eq!(s.commit_id, 6);
        assert_eq!(AnyRequest::try_from(request(&s)).unwrap().unique().0, 6);
        assert_eq!(e.read(GAP..GAP + 3), b"bb\0");
    }
}
