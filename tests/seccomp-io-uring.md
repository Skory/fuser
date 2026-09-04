# seccomp-io-uring.json

Docker's default seccomp profile with `io_uring_setup`, `io_uring_enter` and `io_uring_register`
added to the unconditional `SCMP_ACT_ALLOW` rule, so `make pjdfs_tests_uring` and
`make xfstests_uring` can serve the filesystem over FUSE-over-io_uring. Everything the default
profile blocks, such as `swapon`, stays blocked.

Source: `moby/profiles` tag `seccomp/v0.2.3`,
<https://raw.githubusercontent.com/moby/profiles/seccomp/v0.2.3/seccomp/default.json>.

To refresh: download the file from a newer tag, add the three names to the first `syscalls`
rule (the one with `SCMP_ACT_ALLOW` and no `includes`, `excludes` or `args`), and check that
they do not also appear in a gated rule further down, which would make the allow conditional.
