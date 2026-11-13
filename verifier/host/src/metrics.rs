//! Metrics through the `metrics` facade; they reach a backend once a recorder is installed.

pub const BILLING_PUSHES: &str = "flamingo.billing.pushes";
pub const BILLING_RESTARTS: &str = "flamingo.billing.restarts";
pub const BILLING_PUSHED_BLOCK: &str = "flamingo.billing.pushed_block";
pub const BILLING_ENCLAVE_REGISTRATIONS: &str = "flamingo.billing.enclave_registrations";
pub const BILLING_ENCLAVE_READY: &str = "flamingo.billing.enclave_ready";
pub const BILLING_ENCLAVE_MAX_REGISTRATIONS: &str = "flamingo.billing.enclave_max_registrations";

/// A gauge value; block numbers and counts stay far below `f64`'s exact integer range.
#[expect(clippy::cast_precision_loss, reason = "values stay below 2^53")]
pub const fn gauge_value(value: u64) -> f64 {
    value as f64
}
