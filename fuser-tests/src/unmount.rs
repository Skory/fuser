use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use tokio::process::Child;

use crate::command_utils::command_success;
use crate::mount_util::assert_no_fuse_mount;
use crate::mount_util::assert_single_fuse_mount;
use crate::mount_util::wait_for_fuse_umount;

/// Kills the filesystem process and unmounts on every exit path, so a failed run leaves
/// neither a process nor a disconnected mount behind. Disarmed once `kill_and_unmount` has
/// done both.
pub(crate) struct MountGuard {
    child: Option<Child>,
    mount_path: String,
}

impl MountGuard {
    pub(crate) fn new(child: Child, mount_path: &str) -> Self {
        Self {
            child: Some(child),
            mount_path: mount_path.to_owned(),
        }
    }

    pub(crate) fn disarm(mut self) -> Child {
        self.child
            .take()
            .expect("a MountGuard is disarmed at most once")
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        // Closing /dev/fuse aborts the connection and releases requests a reader is stuck in,
        // which would otherwise make the unmount fail with EBUSY
        for _ in 0..100 {
            match child.try_wait() {
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                _ => break,
            }
        }
        let _ = std::process::Command::new("umount")
            .arg(&self.mount_path)
            .status();
    }
}

/// Unmount behavior for FUSE filesystem tests.
pub(crate) enum Unmount {
    /// Use `--auto-unmount` flag, filesystem unmounts automatically when process exits.
    Auto,
    /// Manual unmount required after process exits.
    Manual,
}

/// Kill the FUSE process and handle unmounting based on the unmount mode.
pub(crate) async fn kill_and_unmount(
    mut fuse_process: Child,
    unmount: Unmount,
    mount_path: &str,
) -> anyhow::Result<()> {
    let mountpoint = Path::new(mount_path);
    assert_single_fuse_mount(mountpoint).await?;

    fuse_process
        .kill()
        .await
        .context("Failed to kill FUSE process")?;

    match unmount {
        Unmount::Auto => {
            wait_for_fuse_umount(mountpoint).await?;
        }
        Unmount::Manual => {
            command_success(["umount", mount_path]).await?;
            assert_no_fuse_mount(mountpoint).await?;
        }
    }

    Ok(())
}
