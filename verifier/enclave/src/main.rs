// Release builds, which the EIF uses, cannot enable `dev`. Debug builds still compile it, so
// `--all-features` lints and tests the workspace, but `main` refuses to run them.
#[cfg(all(feature = "dev", not(debug_assertions)))]
compile_error!("the `dev` feature must never reach an enclave binary");

#[cfg(target_os = "linux")]
mod runtime;

/// Starts the Linux enclave runtime.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        !cfg!(feature = "dev"),
        "verifier-enclave was built with the `dev` feature"
    );
    runtime::run()
}

/// Refuses an unsandboxed or in-process fallback on unsupported platforms.
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("verifier-enclave requires x86_64 Linux with Minijail and Nitro NSM")
}
