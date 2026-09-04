//! FUSE-over-io_uring mount tests

use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use anyhow::bail;
use tempfile::NamedTempFile;
use tokio::process::Command;

use crate::ansi::green;
use crate::canonical_temp_dir::CanonicalTempDir;
use crate::cargo::cargo_build_example;
use crate::features::Feature;
use crate::fusermount::Fusermount;
use crate::mount_util::wait_for_fuse_mount;
use crate::unmount::MountGuard;
use crate::unmount::Unmount;
use crate::unmount::kill_and_unmount;

pub(crate) const ENABLE_URING: &str = "/sys/module/fuse/parameters/enable_uring";
const QUEUE_DEPTH: &str = "2";

/// Logged by the session when it stays on `/dev/fuse` although `--io-uring` was set.
pub(crate) const FALLBACK: &str = "; using /dev/fuse";
/// The fallback reason when the kernel has FUSE-over-io_uring disabled or predates it.
const NOT_ADVERTISED: &str = "did not advertise FUSE_OVER_IO_URING";
/// The fallback reasons when the container runtime refuses the io_uring syscalls: Docker's
/// seccomp profile answers EPERM, others ENOSYS.
const SETUP_REFUSED: [&str; 2] = [
    "io_uring_setup failed (Operation not permitted",
    "io_uring_setup failed (Function not implemented",
];
/// Suffix of the request debug lines dispatched by a ring thread.
const RING_THREAD: &str = "thread=fuser-ring-";

/// Whether the fuse module has FUSE-over-io_uring enabled. A missing parameter means the
/// kernel predates it.
pub(crate) async fn uring_enabled() -> bool {
    tokio::fs::read_to_string(ENABLE_URING)
        .await
        .map(|value| value.trim() == "Y")
        .unwrap_or(false)
}

/// Logged by the session once a ring's queues are registered with the kernel:
/// `io_uring: ring <index> registered <count> entries`, the line the shell tests grep for too.
fn is_ring_ready(line: &str) -> bool {
    line.split_once("io_uring: ring ").is_some_and(|(_, rest)| {
        rest.split(' ').nth(1) == Some("registered") && rest.ends_with(" entries")
    })
}

/// Mounts `hello --io-uring` and checks which transport served the read: with `enable_uring=Y`
/// the rings must serve it unless `io_uring_setup` was refused (container seccomp profiles);
/// otherwise the session must have fallen back because the kernel did not advertise the flag.
pub(crate) async fn run_io_uring_tests() -> anyhow::Result<()> {
    let enable_uring = uring_enabled().await;
    eprintln!("enable_uring={enable_uring}");

    let log_file = NamedTempFile::new().context("Failed to create log file")?;
    let result = run_io_uring_tests_inner(enable_uring, &log_file).await;
    let log = std::fs::read_to_string(log_file.path()).unwrap_or_default();
    result.with_context(|| format!("hello log:\n{log}"))
}

async fn run_io_uring_tests_inner(
    enable_uring: bool,
    log_file: &NamedTempFile,
) -> anyhow::Result<()> {
    let mount_dir = CanonicalTempDir::new()?;
    let mount_path_str = mount_dir.path().to_str().unwrap();
    eprintln!("Mount dir: {}", mount_dir.path().display());

    let hello_exe = cargo_build_example("hello", &[Feature::IoUring]).await?;

    eprintln!("Starting hello filesystem with --io-uring...");
    let fuse_process = Command::new(&hello_exe)
        .args([
            mount_path_str,
            "--io-uring",
            "--io-uring-queue-depth",
            QUEUE_DEPTH,
        ])
        .env("RUST_LOG", "debug")
        .env(Fusermount::ENV_VAR, Fusermount::False.as_path())
        .stderr(Stdio::from(log_file.reopen()?))
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;
    let guard = MountGuard::new(fuse_process, mount_path_str);

    wait_for_fuse_mount(mount_dir.path()).await?;

    // A ring that registered but never serves would block the read forever
    let hello_path = mount_dir.path().join("hello.txt");
    let content = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::fs::read_to_string(&hello_path),
    )
    .await
    .context("Reading hello.txt did not complete in 10s")?
    .context("Failed to read hello.txt")?;
    if content != "Hello World!\n" {
        bail!(
            "hello.txt content mismatch: expected 'Hello World!', got '{}'",
            content
        );
    }
    green!("OK read hello.txt");

    kill_and_unmount(guard.disarm(), Unmount::Manual, mount_path_str).await?;

    let log = std::fs::read_to_string(log_file.path()).context("Failed to read hello log")?;
    let ring_ready = log.lines().any(is_ring_ready);
    let fallback = log.lines().find(|line| line.contains(FALLBACK));
    let ring_dispatch = log.lines().any(|line| line.contains(RING_THREAD));
    let ring_read = log
        .lines()
        .any(|line| line.contains(" READ ") && line.contains(RING_THREAD));
    let depth_line = format!(", depth {QUEUE_DEPTH},");
    let expected_reasons: &[&str] = if enable_uring {
        &SETUP_REFUSED
    } else {
        &[NOT_ADVERTISED]
    };
    let expected = |reason: &str| expected_reasons.iter().any(|text| reason.contains(text));
    match (ring_ready, fallback) {
        (true, None) if enable_uring && ring_read => {
            if !log.contains(&depth_line) {
                bail!("ring set up without '{depth_line}' in the log");
            }
            green!("OK read served over io_uring, queue depth {QUEUE_DEPTH}");
        }
        (false, Some(reason)) if !ring_dispatch && expected(reason) => {
            green!("OK read served over /dev/fuse after: {reason}");
        }
        _ => bail!(
            "unexpected transport: enable_uring={enable_uring} ring_ready={ring_ready} \
             fallback={fallback:?} ring_dispatch={ring_dispatch} ring_read={ring_read}"
        ),
    }

    green!("All io_uring tests passed!");
    Ok(())
}
