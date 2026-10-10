//! Bounded process and filesystem sampling using the already pinned sysinfo dependency.
use crate::metrics::{counter, gauge};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sysinfo::{Disks, Pid, ProcessRefreshKind, System};

#[expect(
    clippy::redundant_pub_crate,
    reason = "process sampling is an internal node metrics interface"
)]
#[derive(Default)]
pub(crate) struct ProcessSampler {
    system: System,
    disks: Disks,
    path: Option<PathBuf>,
    disk_refreshed: Option<Instant>,
    /// Total and available bytes of the data directory's filesystem.
    disk: Option<(u64, u64)>,
    started: Option<u64>,
}

const PROCESS_HELP: &str = "Process or data filesystem observation.";
const IO_HELP: &str = "Cumulative process I/O since process start.";
impl ProcessSampler {
    pub(crate) fn set_path(&mut self, path: PathBuf) {
        self.path = Some(path.canonicalize().unwrap_or(path));
        self.disk_refreshed = None;
    }
    pub(crate) fn sample(&mut self, out: &mut String) {
        gauge(
            out,
            "neutrino_data_directory_configured",
            PROCESS_HELP,
            u8::from(self.path.is_some()),
        );
        let pid = Pid::from_u32(std::process::id());
        let refreshed = self.system.refresh_process_specifics(
            pid,
            ProcessRefreshKind::new()
                .with_cpu()
                .with_memory()
                .with_disk_usage(),
        );
        gauge(
            out,
            "neutrino_process_sample_available",
            PROCESS_HELP,
            u8::from(refreshed),
        );
        if let Some(process) = self.system.process(pid).filter(|_| refreshed) {
            if process.start_time() > 0 {
                self.started = Some(process.start_time());
            }
            gauge(
                out,
                "process_resident_memory_bytes",
                PROCESS_HELP,
                process.memory(),
            );
            gauge(
                out,
                "process_virtual_memory_bytes",
                PROCESS_HELP,
                process.virtual_memory(),
            );
            gauge(
                out,
                "neutrino_process_cpu_usage_ratio",
                PROCESS_HELP,
                f64::from(process.cpu_usage()) / 100.0,
            );
            let io = process.disk_usage();
            counter(
                out,
                "neutrino_process_read_bytes_total",
                IO_HELP,
                io.total_read_bytes,
            );
            counter(
                out,
                "neutrino_process_written_bytes_total",
                IO_HELP,
                io.total_written_bytes,
            );
        }
        if let Some(started) = self.started {
            gauge(out, "process_start_time_seconds", PROCESS_HELP, started);
        }
        let _ = writeln!(
            out,
            "# HELP neutrino_build_info Node binary build identity.\n# TYPE neutrino_build_info gauge\nneutrino_build_info{{version=\"{}\",os=\"{}\",arch=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        self.refresh_disk();
        gauge(
            out,
            "neutrino_data_filesystem_sample_available",
            PROCESS_HELP,
            u8::from(self.disk.is_some()),
        );
        if let Some((total, available)) = self.disk {
            gauge(
                out,
                "neutrino_data_filesystem_size_bytes",
                PROCESS_HELP,
                total,
            );
            gauge(
                out,
                "neutrino_data_filesystem_available_bytes",
                PROCESS_HELP,
                available,
            );
        }
    }

    /// Re-read the data directory's filesystem at most every 30 seconds.
    fn refresh_disk(&mut self) {
        if self
            .disk_refreshed
            .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
        {
            return;
        }
        self.disks.refresh_list();
        let disk = self
            .disks
            .iter()
            .filter(|disk| {
                self.path
                    .as_ref()
                    .is_some_and(|path| path.starts_with(disk.mount_point()))
            })
            .max_by_key(|disk| disk.mount_point().components().count())
            .filter(|disk| disk.total_space() > 0);
        self.disk = disk.map(|disk| (disk.total_space(), disk.available_space()));
        self.disk_refreshed = Some(Instant::now());
    }
}
