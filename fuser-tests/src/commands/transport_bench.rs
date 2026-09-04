//! Transport benchmark: the `bench_fs` example over `/dev/fuse` and over io_uring, each on its
//! own mount, under the same workloads (`dd` streams, `stat` and `pread` loops). Runs on the
//! host as root; the numbers depend on the machine, so compare transports within one run only.

use std::fmt::Write;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use clap::Args;
use clap::ValueEnum;
use tempfile::NamedTempFile;
use tokio::process::Command;

use crate::canonical_temp_dir::CanonicalTempDir;
use crate::cargo::cargo_build_example_release;
use crate::command_utils::command_output;
use crate::commands::io_uring::ENABLE_URING;
use crate::commands::io_uring::FALLBACK;
use crate::commands::io_uring::uring_enabled;
use crate::features::Feature;
use crate::fusermount::Fusermount;
use crate::mount_util::wait_for_fuse_mount;
use crate::unmount::MountGuard;
use crate::unmount::Unmount;
use crate::unmount::kill_and_unmount;

/// Compare the `/dev/fuse` and io_uring transports on the `bench_fs` example.
#[derive(Args)]
pub(crate) struct TransportBenchArgs {
    /// Repetitions of each workload; the table shows the median and the min-max spread
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..))]
    reps: u32,
    /// Transports to measure
    #[arg(long, value_delimiter = ',', default_value = "dev,uring")]
    transports: Vec<Transport>,
    /// Worker threads of the filesystem; more than one over /dev/fuse also sets --clone-fd
    #[arg(long, default_value_t = 1)]
    n_threads: usize,
    /// Serve reads with reply.data() from a heap buffer instead of reply.fill()
    #[arg(long)]
    reply_data: bool,
    /// CPUs for dd and the small-request loops, in taskset -c syntax (e.g. 8-15). The
    /// filesystem keeps the CPUs this process started with unless --server-cpus is given
    #[arg(long)]
    client_cpus: Option<String>,
    /// CPUs for the filesystem process, in taskset -c syntax
    #[arg(long)]
    server_cpus: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Transport {
    /// Reads and writes on /dev/fuse
    Dev,
    /// FUSE-over-io_uring
    Uring,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Transport::Dev => "/dev/fuse",
            Transport::Uring => "io_uring",
        }
    }
}

/// Bytes each workload covers; `bench_fs` serves a larger file, so no request hits its end.
const SPAN: u64 = 1 << 30;
const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const DATA_FILE: &str = "data";
const NAME_WIDTH: usize = 26;
const CELL_WIDTH: usize = 28;
const GUTTER: &str = "  ";

#[derive(Clone, Copy)]
enum Workload {
    /// One `dd` stream of `SPAN` bytes in `block`-sized blocks.
    Dd { block: u64, write: bool },
    /// `stat(2)` loops on `threads` client threads, `iters` calls each; with a zero entry TTL
    /// each call is a lookup and a getattr.
    Stat { threads: usize, iters: u64 },
    /// `pread(2)` loops of `size` bytes at scattered offsets, `iters` calls per thread.
    Pread {
        size: usize,
        threads: usize,
        iters: u64,
    },
}

/// The workloads every transport runs, in table order. The kernel splits requests above its
/// `max_pages` (1 MiB here), so larger `dd` blocks would measure 1 MiB requests again.
fn workloads() -> Vec<Workload> {
    let mut list = Vec::new();
    for block in [4 * KIB, 128 * KIB, MIB] {
        for write in [false, true] {
            list.push(Workload::Dd { block, write });
        }
    }
    for threads in [1, 8] {
        list.push(Workload::Stat {
            threads,
            iters: 100_000,
        });
    }
    for (size, iters) in [(4096, 100_000), (65536, 20_000)] {
        for threads in [1, 8] {
            list.push(Workload::Pread {
                size,
                threads,
                iters,
            });
        }
    }
    list
}

fn size_label(bytes: u64) -> String {
    if bytes < MIB {
        format!("{}k", bytes / KIB)
    } else {
        format!("{}M", bytes / MIB)
    }
}

impl Workload {
    fn name(&self) -> String {
        match self {
            Workload::Dd { block, write } => {
                let direction = if *write { "write" } else { "read" };
                format!("{direction} {}", size_label(*block))
            }
            Workload::Stat { threads, .. } => format!("stat (lookup+getattr) x{threads}"),
            Workload::Pread { size, threads, .. } => {
                format!("pread {} x{threads}", size_label(*size as u64))
            }
        }
    }

    fn unit(&self) -> &'static str {
        match self {
            Workload::Dd { .. } => "MB/s",
            Workload::Stat { .. } | Workload::Pread { .. } => "ops/s",
        }
    }

    /// Runs the workload once against `data` and returns its rate in `unit()`.
    fn run(&self, data: &Path) -> anyhow::Result<f64> {
        match *self {
            Workload::Dd { block, write } => dd(data, block, write),
            Workload::Stat { threads, iters } => small_ops(threads, iters, |iters| {
                for _ in 0..iters {
                    std::fs::metadata(data).context("stat failed")?;
                }
                Ok(())
            }),
            Workload::Pread {
                size,
                threads,
                iters,
            } => small_ops(threads, iters, |iters| {
                let file = File::open(data).context("Failed to open data file")?;
                let mut buf = vec![0u8; size];
                let blocks = SPAN / size as u64;
                for i in 0..iters {
                    // Odd multiplier modulo a power of two: a permutation of the blocks, so
                    // offsets are scattered and repeat only after `blocks` calls. Every thread
                    // walks the same sequence, which is harmless without caching
                    let offset = i.wrapping_mul(2_654_435_761) % blocks * size as u64;
                    let n = file.read_at(&mut buf, offset).context("pread failed")?;
                    if n != size {
                        bail!("short pread: {n} of {size} bytes at offset {offset}");
                    }
                }
                Ok(())
            }),
        }
    }
}

/// Copies `SPAN` bytes with `dd` in `block`-sized blocks, reading `data` into `/dev/null` or
/// writing zeros over it. Returns decimal MB/s over the process's wall time.
fn dd(data: &Path, block: u64, write: bool) -> anyhow::Result<f64> {
    let data = data.display();
    let mut command = std::process::Command::new("dd");
    if write {
        command
            .arg("if=/dev/zero")
            .arg(format!("of={data}"))
            .arg("conv=notrunc");
    } else {
        // Without fullblock a short read would count as a whole block
        command
            .arg(format!("if={data}"))
            .arg("of=/dev/null")
            .arg("iflag=fullblock");
    }
    command
        .arg(format!("bs={block}"))
        .arg(format!("count={}", SPAN / block));
    let start = Instant::now();
    let output = command.output().context("Failed to run dd")?;
    let secs = start.elapsed().as_secs_f64();
    if !output.status.success() {
        bail!("dd failed:\n{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(SPAN as f64 / secs / 1e6)
}

/// Runs `worker(iters)`, a loop of that many operations, on each of `threads` threads and
/// returns the aggregate ops/s over the wall time of all of them.
fn small_ops<F>(threads: usize, iters: u64, worker: F) -> anyhow::Result<f64>
where
    F: Fn(u64) -> anyhow::Result<()> + Sync,
{
    let start = Instant::now();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| scope.spawn(|| worker(iters)))
            .collect();
        for worker in workers {
            worker
                .join()
                .map_err(|_| anyhow!("small-op thread panicked"))??;
        }
        anyhow::Ok(())
    })?;
    Ok((iters * threads as u64) as f64 / start.elapsed().as_secs_f64())
}

/// Median and spread of one workload's repetitions.
struct Stats {
    median: f64,
    min: f64,
    max: f64,
}

impl Stats {
    fn of(values: &mut [f64]) -> Self {
        values.sort_by(f64::total_cmp);
        let mid = values.len() / 2;
        let median = if values.len() % 2 == 1 {
            values[mid]
        } else {
            (values[mid - 1] + values[mid]) / 2.0
        };
        Self {
            median,
            min: values[0],
            max: values[values.len() - 1],
        }
    }

    fn cell(&self, unit: &str) -> String {
        let Stats { median, min, max } = self;
        format!("{median:.0} ({min:.0}-{max:.0}) {unit}")
    }
}

/// Runs every workload `reps` times and returns the stats in `workloads` order.
fn run_workloads(data: &Path, workloads: &[Workload], reps: u32) -> anyhow::Result<Vec<Stats>> {
    workloads
        .iter()
        .map(|workload| {
            let mut values = (0..reps)
                .map(|_| workload.run(data))
                .collect::<anyhow::Result<Vec<_>>>()
                .with_context(|| format!("workload '{}' failed", workload.name()))?;
            let stats = Stats::of(&mut values);
            eprintln!(
                "  {:<NAME_WIDTH$}{GUTTER}{:>CELL_WIDTH$}",
                workload.name(),
                stats.cell(workload.unit())
            );
            Ok(stats)
        })
        .collect()
}

/// How to start `bench_fs`, apart from the transport.
struct Server<'a> {
    exe: &'a Path,
    cpus: Option<&'a str>,
    n_threads: usize,
    reply_data: bool,
}

pub(crate) async fn run_transport_bench(args: TransportBenchArgs) -> anyhow::Result<()> {
    let TransportBenchArgs {
        reps,
        mut transports,
        n_threads,
        reply_data,
        client_cpus,
        server_cpus,
    } = args;
    if transports.contains(&Transport::Uring) && !uring_enabled().await {
        eprintln!("note: {ENABLE_URING} is not Y, skipping the io_uring transport");
        transports.retain(|transport| *transport != Transport::Uring);
    }
    if transports.is_empty() {
        bail!("No transport to measure");
    }

    let exe = cargo_build_example_release("bench_fs", &[Feature::IoUring]).await?;

    // Pinning this process also pins what it spawns, so without its own CPUs the filesystem
    // is given the mask the process started with
    let server_cpus = match (&client_cpus, server_cpus) {
        (Some(_), None) => Some(current_affinity().await?),
        (_, server_cpus) => server_cpus,
    };
    match &client_cpus {
        Some(cpus) => {
            let pid = std::process::id().to_string();
            command_output(["taskset", "-a", "-c", "-p", cpus, &pid]).await?;
        }
        None => eprintln!(
            "note: unpinned; on multi-socket hosts the scheduler spreads client and \
             filesystem over the nodes, which makes the numbers noisy and can reverse the \
             ordering. Pin both, e.g. --client-cpus 8-15 --server-cpus 16-31 on one node"
        ),
    }
    let server = Server {
        exe: &exe,
        cpus: server_cpus.as_deref(),
        n_threads,
        reply_data,
    };

    let workloads = workloads();
    let mut results = Vec::new();
    for transport in transports {
        eprintln!("\n=== bench_fs over {} ===", transport.name());
        let stats = bench_transport(&server, transport, &workloads, reps).await?;
        results.push((transport, stats));
    }

    let mut table = format!("\n{:<NAME_WIDTH$}", "workload");
    for (transport, _) in &results {
        write!(table, "{GUTTER}{:>CELL_WIDTH$}", transport.name())?;
    }
    for (i, workload) in workloads.iter().enumerate() {
        write!(table, "\n{:<NAME_WIDTH$}", workload.name())?;
        for (_, stats) in &results {
            write!(
                table,
                "{GUTTER}{:>CELL_WIDTH$}",
                stats[i].cell(workload.unit())
            )?;
        }
    }
    println!("{table}\nmedian (min-max) of {reps} runs");
    Ok(())
}

/// The CPU list this process may run on, in `taskset -c` syntax.
async fn current_affinity() -> anyhow::Result<String> {
    let pid = std::process::id().to_string();
    let output = command_output(["taskset", "-c", "-p", &pid]).await?;
    // "pid 123's current affinity list: 0-447"
    let (_, cpus) = output
        .trim()
        .rsplit_once(": ")
        .context("Unexpected taskset output")?;
    Ok(cpus.to_owned())
}

/// Fails with the mount log attached if the session fell back to `/dev/fuse` although the ring
/// was requested, so a column labelled io_uring never shows `/dev/fuse` numbers.
async fn bench_transport(
    server: &Server<'_>,
    transport: Transport,
    workloads: &[Workload],
    reps: u32,
) -> anyhow::Result<Vec<Stats>> {
    let log_file = NamedTempFile::new().context("Failed to create log file")?;
    let result = bench_transport_inner(server, transport, workloads, reps, &log_file).await;
    let log = std::fs::read_to_string(log_file.path()).unwrap_or_default();
    match result {
        Ok(_) if log.contains(FALLBACK) => bail!("bench_fs fell back to /dev/fuse:\n{log}"),
        result => result.with_context(|| format!("bench_fs log:\n{log}")),
    }
}

async fn bench_transport_inner(
    server: &Server<'_>,
    transport: Transport,
    workloads: &[Workload],
    reps: u32,
    log_file: &NamedTempFile,
) -> anyhow::Result<Vec<Stats>> {
    let mount_dir = CanonicalTempDir::new()?;
    let mount_path_str = mount_dir
        .path()
        .to_str()
        .context("Mount path is not UTF-8")?;

    let mut command = match server.cpus {
        Some(cpus) => {
            let mut command = Command::new("taskset");
            command.args(["-c", cpus]).arg(server.exe);
            command
        }
        None => Command::new(server.exe),
    };
    let n_threads = server.n_threads.to_string();
    command.args([mount_path_str, "--n-threads", &n_threads]);
    match transport {
        Transport::Dev => {
            if server.n_threads > 1 {
                command.arg("--clone-fd");
            }
        }
        Transport::Uring => {
            command.arg("--io-uring");
        }
    }
    if server.reply_data {
        command.arg("--reply-data");
    }
    let fuse_process = command
        .env("RUST_LOG", "warn")
        .env(Fusermount::ENV_VAR, Fusermount::False.as_path())
        .stderr(Stdio::from(log_file.reopen()?))
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            let program = command.as_std().get_program().to_string_lossy();
            format!("Failed to start {program}")
        })?;
    let guard = MountGuard::new(fuse_process, mount_path_str);

    wait_for_fuse_mount(mount_dir.path()).await?;
    // The mount is visible before the session has answered INIT, which is where it settles on
    // the transport; the first request cannot complete until then, so after it the fallback
    // warning is in the log if there is one
    let data: PathBuf = mount_dir.path().join(DATA_FILE);
    tokio::fs::metadata(&data)
        .await
        .context("Failed to stat the data file")?;
    let log = std::fs::read_to_string(log_file.path()).context("Failed to read bench_fs log")?;
    if log.contains(FALLBACK) {
        bail!("bench_fs fell back to /dev/fuse");
    }

    let workloads = workloads.to_vec();
    let stats = tokio::task::spawn_blocking(move || run_workloads(&data, &workloads, reps))
        .await
        .context("workload thread panicked")??;

    kill_and_unmount(guard.disarm(), Unmount::Manual, mount_path_str).await?;
    Ok(stats)
}
