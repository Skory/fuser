use std::path::PathBuf;

use fuser::Config;
use fuser::MountOption;
use fuser::SessionACL;

#[derive(clap::Parser)]
pub struct CommonArgs {
    pub mount_point: PathBuf,

    /// Automatically unmount on process exit
    #[clap(long)]
    pub auto_unmount: bool,

    /// Allow root user to access filesystem
    #[clap(long)]
    pub allow_root: bool,

    /// Number of threads to use
    #[clap(long, default_value_t = 1)]
    pub n_threads: usize,

    /// Use `FUSE_DEV_IOC_CLONE` to give each worker thread its own fd.
    /// This enables more efficient request processing
    /// when multiple threads are used. Requires Linux 4.5+.
    #[clap(long)]
    pub clone_fd: bool,

    /// Serve requests over FUSE-over-io_uring (needs the io-uring feature and enable_uring=Y).
    #[clap(long)]
    pub io_uring: bool,

    /// Ring entries per kernel queue when `--io-uring` is set
    #[clap(long, default_value_t = 8)]
    pub io_uring_queue_depth: u32,
}

impl CommonArgs {
    pub fn config(&self) -> Config {
        let mut config = Config::default();
        if self.auto_unmount {
            config.mount_options.push(MountOption::AutoUnmount);
        }
        if self.allow_root {
            config.acl = SessionACL::RootAndOwner;
        }
        if config.mount_options.contains(&MountOption::AutoUnmount)
            && config.acl != SessionACL::RootAndOwner
        {
            config.acl = SessionACL::All;
        }
        config.n_threads = Some(self.n_threads);
        config.clone_fd = self.clone_fd;
        config.io_uring = self.io_uring;
        config.io_uring_queue_depth = self.io_uring_queue_depth;
        config
    }
}
