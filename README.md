# FUSE (Filesystem in Userspace) for Rust

![CI](https://github.com/cberner/fuser/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/fuser.svg)](https://crates.io/crates/fuser)
[![Documentation](https://docs.rs/fuser/badge.svg)](https://docs.rs/fuser)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cberner/fuser/blob/master/LICENSE.md)
[![dependency status](https://deps.rs/repo/github/cberner/fuser/status.svg)](https://deps.rs/repo/github/cberner/fuser)

## About

**FUSE-Rust** is a [Rust] library crate for easy implementation of [FUSE filesystems][FUSE for Linux] in userspace.

FUSE-Rust does not just provide bindings, it is a rewrite of the original FUSE C library to fully take advantage of Rust's architecture.

This library was originally forked from the [`fuse` crate](https://github.com/zargony/fuse-rs) with the intention
of continuing development. In particular adding features from ABIs after 7.19

## Use of AI

Version 0.18.0 is the last version that was primarily developed without coding agents.

Future releases will be developed primarily by a coding agent, as I believe this will lead to higher quality code,
and faster feature development.
All the changes will receive at least a cursory review from a human, and a full review from a coding agent.

## Documentation

[FUSE-Rust reference][Documentation]

## Details

A working FUSE filesystem consists of three parts:

1. The **kernel driver** that registers as a filesystem and forwards operations into a communication channel to a userspace process that handles them.
1. The **userspace library** (libfuse) that helps the userspace process to establish and run communication with the kernel driver.
1. The **userspace implementation** that actually processes the filesystem operations.

The kernel driver is provided by the FUSE project, the userspace implementation needs to be provided by the developer. FUSE-Rust provides a replacement for the libfuse userspace library between these two. This way, a developer can fully take advantage of the Rust type interface and runtime features when building a FUSE filesystem in Rust.

Except for a single setup (mount) function call and a final teardown (umount) function call to libfuse, everything runs in Rust, and on Linux these calls to libfuse are optional. They can be removed by building without the "libfuse" feature flag.

### Cargo features

All features are off by default.

- `libfuse`: mount and unmount through libfuse instead of the pure Rust implementation: libfuse3 if `pkg-config` finds it, otherwise libfuse2. `libfuse2` and `libfuse3` pin the version.
- `experimental`: the async `Filesystem` API in `fuser::experimental`, which pulls in `tokio` and `async-trait`.
- `serializable`: `serde` `Serialize`/`Deserialize` derives on `FileAttr`, `FileType` and the `ll` newtypes (`RequestId`, `INodeNo`, `FileHandle`, `LockOwner`, `Version`).
- `macos-no-mount`: compiles out the mount implementations on macOS so the code builds without macFUSE; mounting does not work with it.
- `io-uring`: the FUSE-over-io_uring transport, selected per session with `Config::io_uring`. It needs Linux 6.14 or later and the fuse module parameter `enable_uring=Y`; when the kernel does not offer it, the session logs a warning and uses `/dev/fuse`.

## Dependencies

FUSE must be installed to build or run programs that use FUSE-Rust (i.e. kernel driver and libraries. Some platforms may also require userland utils like `fusermount`). A default installation of FUSE is usually sufficient.

To build FUSE-Rust or any program that depends on it, `pkg-config` needs to be installed as well.

### Linux

[FUSE for Linux] is available in most Linux distributions and usually called `fuse` or `fuse3` (this crate is compatible with both). To install on a Debian based system:

```sh
sudo apt-get install fuse3 libfuse3-dev
```

Install on CentOS:

```sh
sudo yum install fuse
```

To build, FUSE libraries and headers are required. The package is usually called `libfuse-dev` or `fuse-devel`. Also `pkg-config` is required for locating libraries and headers.

```sh
sudo apt-get install libfuse-dev pkg-config
```

```sh
sudo yum install fuse-devel pkgconfig
```

### macOS (untested)

Install [FUSE for macOS], which can be obtained from their website or installed using the Homebrew or Nix package managers. macOS version 10.9 or later is required. If you are using a Mac with Apple Silicon, you must also [enable support for third party kernel extensions][enable kext].


#### To install using Homebrew

```sh
brew install macfuse pkgconf
```

#### To install using Nix

``` sh
nix-env -iA nixos.macfuse-stubs nixos.pkg-config
```

When using `nix` it is required that you specify `PKG_CONFIG_PATH` environment variable to point at where `macfuse` is installed:

``` sh
export PKG_CONFIG_PATH=${HOME}/.nix-profile/lib/pkgconfig
```

### FreeBSD

Install packages `fusefs-libs` and `pkgconf`.

```sh
pkg install fusefs-libs pkgconf
```

## Usage

```sh
cargo add fuser
```

or put this in your `Cargo.toml`:

```toml
[dependencies]
fuser = "0.15"
```

To create a new filesystem, implement the trait `fuser::Filesystem`. See the [documentation] for details or the `examples` directory for some basic examples.

### Benchmarking

`make bench` compares the two Linux transports. It mounts the `bench_fs` example, an in-memory file with zero attribute TTLs and `FOPEN_DIRECT_IO` so every request reaches the filesystem, once over `/dev/fuse` and once over io_uring, and runs the same load against each: `dd` streams at 4k, 128k and 1M block sizes over 1 GiB in both directions, then `stat` and 4k/64k `pread` loops from 1 and 8 client threads. Each workload is repeated (5 times by default) and the table shows the median with the min-max spread per transport. It runs on the host as root, needs `fuse.enable_uring=Y` for the io_uring column, and takes several minutes. `cargo run --release -p fuser-tests -- transport-bench --help` lists the options: repetitions, filesystem worker threads, `reply.data()` instead of `reply.fill()`, and CPU pinning.

Pin on multi-socket hosts. Unpinned, the scheduler spreads the client and the filesystem over the NUMA nodes, the spreads widen and the ordering of the two transports can flip between runs. The table below comes from

```sh
cargo run --release -p fuser-tests -- transport-bench --reps 7 --client-cpus 8-15 --server-cpus 16-31
```

and the same command with `--reply-data` for the last two rows, on an AMD EPYC 9734 running Linux 7.0, client on CPUs 8-15 and filesystem on 16-31 of the same NUMA node. Cells are the median (min-max) of 7 runs; the numbers are specific to that host, and rows whose spreads overlap show no reliable difference.

| workload                                 | `/dev/fuse`            | io_uring               |
|------------------------------------------|------------------------|------------------------|
| read 4k (MB/s)                           | 161 (152-167)          | 179 (176-183)          |
| write 4k (MB/s)                          | 137 (135-156)          | 174 (162-190)          |
| read 128k (MB/s)                         | 2639 (1860-2704)       | 2716 (2599-3235)       |
| write 128k (MB/s)                        | 917 (904-951)          | 1151 (1076-1195)       |
| read 1M (MB/s)                           | 4000 (3535-4016)       | 4035 (3947-4095)       |
| write 1M (MB/s)                          | 1140 (1107-1186)       | 1354 (1283-1399)       |
| stat, lookup+getattr, 1 client (ops/s)   | 20515 (20056-21476)    | 22441 (22201-22907)    |
| stat, lookup+getattr, 8 clients (ops/s)  | 131262 (128350-134115) | 133278 (122921-140303) |
| pread 4k, 1 client (ops/s)               | 37782 (36001-45998)    | 43619 (42411-47581)    |
| pread 4k, 8 clients (ops/s)              | 212283 (208537-216312) | 246206 (230713-256191) |
| pread 64k, 1 client (ops/s)              | 27801 (25529-29444)    | 28097 (27503-30057)    |
| pread 64k, 8 clients (ops/s)             | 70505 (69296-72207)    | 69820 (69040-70962)    |
| read 128k with `reply.data()` (MB/s)     | 2010 (1941-2151)       | 2591 (2412-2742)       |
| read 1M with `reply.data()` (MB/s)       | 4226 (3285-4353)       | 3098 (3051-3507)       |

Counting a row as a win only when the two spreads are disjoint: io_uring wins 4k reads, 4k, 128k and 1M writes, single-client `stat`, 8-client 4k `pread` and the 128k `reply.data()` read; `/dev/fuse` wins no row in this run; the 128k and 1M reads, 8-client `stat`, single-client 4k `pread` and both 64k `pread` rows overlap. The 1M `reply.data()` read also counts as an overlap, but only through the single lowest `/dev/fuse` rep (3285): on medians io_uring loses it by about a quarter. Several rows move between "overlap" and "win" from run to run: the `/dev/fuse` 128k read is bimodal on this host (about 1900 or 2600-3000 MB/s depending on the run, which is why its two rows differ); the 8-client `stat` io_uring spread is 13-16% wide in every run, with a low tail around 122-124k ops/s against a 4-5% `/dev/fuse` spread, so its parity is on the median only; the 8-client 64k `pread` row came out as a small `/dev/fuse` win in a later 3-rep run; and in an earlier 7-rep run 8-client `stat` was a `/dev/fuse` win and the 1M `reply.data()` read an io_uring loss. Each `stat` is a lookup plus a getattr because the entry TTL is zero. `reply.fill()` writes the data into the ring entry over io_uring, which is where the 1M `reply.data()` row loses against `fill`; over `/dev/fuse` `fill` writes into a fresh heap buffer that is then sent, the same work as `data()`, and the two agree within the spread.

## To Do

Most features of libfuse up to 3.10.3 are implemented. Feel free to contribute. See the [list of issues][issues] on GitHub and search the source files for comments containing "`TODO`" or "`FIXME`" to see what's still missing.

## Compatibility

Developed and tested on Linux. Tested under [Linux][FUSE for Linux] and [FreeBSD][FUSE for FreeBSD] using stable [Rust] (see CI for details).

## License

Licensed under [MIT License](LICENSE.md), except for those files in `examples/` that explicitly contain a different license.

## Contribution

**Pull requests are no longer being accepted. Please file an issue, or fork the project instead.**

Fork, hack, ~~submit pull request~~. Make sure to make it useful for the target audience, keep the project's philosophy and Rust coding standards in mind. For larger or essential changes, you may want to open an issue for discussion first. Also remember to update the [Changelog] if your changes are relevant to the users.

[Rust]: https://rust-lang.org
[Homebrew]: https://brew.sh
[Changelog]: https://keepachangelog.com/en/1.0.0/

[FUSE-Rust]: https://github.com/cberner/fuser
[issues]: https://github.com/cberner/fuser/issues
[Documentation]: https://docs.rs/fuser

[FUSE for Linux]: https://github.com/libfuse/libfuse/
[FUSE for macOS]: https://macfuse.github.io
[enable kext]: https://github.com/macfuse/macfuse/wiki/Getting-Started#enabling-support-for-third-party-kernel-extensions-apple-silicon-macs
[FUSE for FreeBSD]: https://wiki.freebsd.org/FUSEFS
