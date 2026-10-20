use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Loads the WIP-201 release manifest of this boot's Engine bundle.
///
/// The enclave checks it against the bundle it runs and keeps it for the boot. Loading the same
/// manifest again succeeds, so the provisioner can retry a load during startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadReleaseRequest {
    /// The release manifest as a compact JWS.
    pub manifest: String,
}

impl Request for LoadReleaseRequest {
    const ROUTE_ID: &'static str = "/v1/release";
    type Response = Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::LoadReleaseRequest;

    #[test]
    fn the_release_route_id_is_versioned_and_stable() {
        assert_eq!(LoadReleaseRequest::ROUTE_ID, "/v1/release");
    }
}
