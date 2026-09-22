//! Every subprocess owns a process group; cancellation also kills its descendants.
use std::{
    ffi::OsStr, fs::File, io::Read, os::unix::process::CommandExt, path::Path, process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    process::{Child, Command},
    time::timeout,
};

struct Running {
    child: Child,
    group: i32,
}

impl Drop for Running {
    fn drop(&mut self) {
        // SAFETY: this positive PID is the process group created for our own child.
        unsafe {
            libc::kill(-self.group, libc::SIGKILL);
        }
        let _ = self.child.start_kill();
    }
}

pub async fn output(program: &str, args: &[&OsStr], deadline: Duration) -> Result<Vec<u8>> {
    let file = tempfile::NamedTempFile::new()?;
    to_file(program, args, deadline, file.path()).await?;
    let mut bytes = Vec::new();
    File::open(file.path())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "command output exceeds limit");
    Ok(bytes)
}

pub async fn to_file(
    program: &str,
    args: &[&OsStr],
    deadline: Duration,
    output: &Path,
) -> Result<()> {
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(File::create(output)?)
        .stderr(Stdio::null())
        .env("LC_ALL", "C")
        .env("AWS_PAGER", "")
        .env("AWS_MAX_ATTEMPTS", "3");
    let child = Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot start {program}"))?;
    let group = i32::try_from(child.id().context("missing child PID")?)?;
    let mut running = Running { child, group };
    let status = timeout(deadline, running.child.wait())
        .await
        .with_context(|| format!("{program} timed out"))??;
    ensure!(
        status.success(),
        "{program} failed ({status}); subprocess output suppressed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_and_timed_out_commands_fail() {
        assert!(
            output(
                "/bin/sh",
                &["-c".as_ref(), "exit 7".as_ref()],
                Duration::from_secs(1)
            )
            .await
            .is_err()
        );
        assert!(
            output(
                "/bin/sh",
                &["-c".as_ref(), "sleep 30".as_ref()],
                Duration::from_millis(50)
            )
            .await
            .is_err()
        );
    }
}
