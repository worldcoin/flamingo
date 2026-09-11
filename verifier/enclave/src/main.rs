#[cfg(target_os = "linux")]
mod runtime;

/// Starts the Linux enclave runtime.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    runtime::run()
}

/// Refuses an unsandboxed or in-process fallback on unsupported platforms.
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("verifier-enclave requires x86_64 Linux with Minijail and Nitro NSM")
}
