//! Configuration for the verifier client.
//!
//! Follows the shape `world-id-protocol` uses for authenticator configuration. Configuration
//! is explicit — nothing is read from the environment.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use url::Url;

use pontifex::attestation::{PcrConfig, PcrMeasurement, Verifier};

/// Default freshness bound, matching the few-hour lifetime of a Nitro certificate.
const fn default_max_attestation_age_millis() -> u64 {
    60 * 60 * 1000
}

const fn default_connect_timeout_millis() -> u64 {
    5_000
}

const fn default_request_timeout_millis() -> u64 {
    60_000
}

/// Configuration to interact with a Flamingo Verifier host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base URL of the host, e.g. `https://verifier.example.com`.
    host_url: Url,
    /// Measurements to trust. A document is accepted if it matches any one configuration in
    /// full, which lets several enclave versions be trusted at once during a rollout.
    #[serde(default, with = "pcr_configs")]
    allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
    /// Explicit development-only bypass of all PCR measurement checks.
    #[serde(default)]
    dangerously_skip_measurements: bool,
    /// How old an attestation document's own timestamp may be.
    #[serde(default = "default_max_attestation_age_millis")]
    max_attestation_age_millis: u64,
    /// Bound on establishing a connection.
    #[serde(default = "default_connect_timeout_millis")]
    connect_timeout_millis: u64,
    /// Bound on a whole request.
    #[serde(default = "default_request_timeout_millis")]
    request_timeout_millis: u64,
}

impl Config {
    /// Instantiates a configuration with the default bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if `host_url` is not a valid URL or the measurement policy fails
    /// the requirements of [`Self::verifier`].
    pub fn new(
        host_url: &str,
        allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
    ) -> Result<Self, Error> {
        Self::new_inner(host_url, allowed_pcr_configs, false)
    }

    /// Creates a configuration that bypasses all PCR measurement checks.
    ///
    /// No measurements are required. Certificate chain, signature, freshness, and
    /// channel public-key commitment verification remain enabled.
    ///
    /// # Warning
    /// Accepts any enclave code with otherwise valid attestation, including Nitro
    /// debug enclaves. Use only for development, never in production.
    ///
    /// # Errors
    ///
    /// Returns an error if `host_url` is not a valid URL.
    pub fn dangerously_skip_measurements(host_url: &str) -> Result<Self, Error> {
        Self::new_inner(host_url, vec![], true)
    }

    fn new_inner(
        host_url: &str,
        allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
        dangerously_skip_measurements: bool,
    ) -> Result<Self, Error> {
        let host_url = Url::parse(host_url).map_err(|error| Error::InvalidConfig {
            attribute: "host_url".to_string(),
            reason: error.to_string(),
        })?;

        let config = Self {
            host_url,
            allowed_pcr_configs,
            dangerously_skip_measurements,
            max_attestation_age_millis: default_max_attestation_age_millis(),
            connect_timeout_millis: default_connect_timeout_millis(),
            request_timeout_millis: default_request_timeout_millis(),
        };
        config.validate()?;

        Ok(config)
    }

    /// Bounds how old an attestation document's own timestamp may be.
    #[must_use]
    pub fn with_max_attestation_age(mut self, max_age: Duration) -> Self {
        self.max_attestation_age_millis = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
        self
    }

    /// Loads a configuration from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is invalid or the resulting configuration is not usable.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let config: Self = serde_json::from_str(json)
            .map_err(|error| Error::MalformedConfig(error.to_string()))?;
        config.validate()?;

        Ok(config)
    }

    /// Validates the measurement policy before constructing the verifier.
    fn validate(&self) -> Result<(), Error> {
        self.verifier().map(|_| ())
    }

    /// Builds a Pontifex verifier applying the configured measurements and freshness bound.
    ///
    /// # Errors
    ///
    /// Without the explicit measurement bypass, rejects an empty policy, missing
    /// or zero PCR0, duplicate indices, or malformed measurements.
    pub fn verifier(&self) -> Result<Verifier, Error> {
        let max_age = Duration::from_millis(self.max_attestation_age_millis);
        if self.dangerously_skip_measurements {
            return Ok(Verifier::new(vec![], max_age).dangerously_skip_measurements());
        }
        let invalid = || Error::InvalidConfig {
            attribute: "allowed_pcr_configs".to_owned(),
            reason: "each configuration must pin a nonzero 48-byte PCR0; \
                     all measurements must be 48 bytes with unique indices"
                .to_owned(),
        };
        if self.allowed_pcr_configs.is_empty() {
            return Err(invalid());
        }
        let mut configs = Vec::new();
        for measurements in &self.allowed_pcr_configs {
            let mut indices = std::collections::BTreeSet::new();
            if measurements
                .iter()
                .any(|pcr| pcr.value.len() != 48 || !indices.insert(pcr.index))
            {
                return Err(invalid());
            }
            let pcr0 = measurements
                .iter()
                .find(|pcr| pcr.index == 0)
                .ok_or_else(invalid)?;
            let image = <[u8; 48]>::try_from(pcr0.value.as_slice()).map_err(|_| invalid())?;
            if image == [0; 48] {
                return Err(invalid());
            }
            let mut config = PcrConfig::new(image);
            for pcr in measurements.iter().filter(|pcr| pcr.index != 0) {
                config = config.with_pcr(pcr.index, pcr.value.clone());
            }
            configs.push(config);
        }
        Ok(Verifier::new(configs, max_age))
    }

    /// The host to call.
    #[must_use]
    pub const fn host_url(&self) -> &Url {
        &self.host_url
    }

    /// Bound on establishing a connection.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_millis)
    }

    /// Bound on a whole request.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_millis)
    }
}

mod pcr_configs {
    use pontifex::PcrMeasurement;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Measurement {
        index: u32,
        #[serde(
            serialize_with = "hex::serde::serialize",
            deserialize_with = "deserialize_pcr"
        )]
        value: Vec<u8>,
    }

    fn deserialize_pcr<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        hex::decode(value.strip_prefix("0x").unwrap_or(&value)).map_err(serde::de::Error::custom)
    }

    pub(super) fn serialize<S: serde::Serializer>(
        configs: &[Vec<PcrMeasurement>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let configs: Vec<Vec<Measurement>> = configs
            .iter()
            .map(|measurements| {
                measurements
                    .iter()
                    .map(|pcr| Measurement {
                        index: pcr.index,
                        value: pcr.value.clone(),
                    })
                    .collect()
            })
            .collect();
        configs.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<PcrMeasurement>>, D::Error> {
        let configs = Vec::<Vec<Measurement>>::deserialize(deserializer)?;
        Ok(configs
            .into_iter()
            .map(|measurements| {
                measurements
                    .into_iter()
                    .map(|pcr| PcrMeasurement::new(pcr.index, pcr.value))
                    .collect()
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Config;
    use super::PcrMeasurement;
    use crate::error::Error;

    fn pcrs() -> Vec<Vec<PcrMeasurement>> {
        vec![vec![PcrMeasurement::new(0, [0xabu8; 48])]]
    }

    #[test]
    fn rejects_a_configuration_that_pins_nothing() {
        let error = Config::new("http://localhost:8000", Vec::new())
            .expect_err("an empty policy must fail closed");

        assert!(matches!(error, Error::InvalidConfig { .. }));
    }

    #[test]
    fn rejects_an_invalid_host_url() {
        let error =
            Config::new("not a url", pcrs()).expect_err("an unparseable URL must be rejected");

        assert!(matches!(error, Error::InvalidConfig { .. }));
    }

    #[test]
    fn rejects_missing_zero_malformed_and_duplicate_measurements() {
        let policies = [
            vec![],
            vec![PcrMeasurement::new(1, [0xab; 48])],
            vec![PcrMeasurement::new(0, [0; 48])],
            vec![PcrMeasurement::new(0, [0xab; 32])],
            vec![
                PcrMeasurement::new(0, [0xab; 48]),
                PcrMeasurement::new(1, [0xab; 32]),
            ],
            vec![
                PcrMeasurement::new(0, [0xab; 48]),
                PcrMeasurement::new(0, [0xcd; 48]),
            ],
        ];
        for policy in policies {
            let error = Config::new("http://localhost:8000", vec![policy]).unwrap_err();
            assert!(matches!(error, Error::InvalidConfig { .. }));
        }
    }

    #[test]
    fn deserialization_cannot_bypass_client_policy_validation() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "host_url": "http://localhost:8000",
            "allowed_pcr_configs": []
        }))
        .unwrap();
        assert!(matches!(
            crate::FlamingoVerifierClient::new(config),
            Err(Error::InvalidConfig { .. })
        ));
    }

    #[test]
    fn measurement_skip_is_explicit_and_survives_json_round_trip() {
        assert!(Config::dangerously_skip_measurements("not a URL").is_err());
        let config = Config::dangerously_skip_measurements("http://localhost:8000").unwrap();
        assert!(config.verifier().is_ok());
        let mut json = serde_json::to_value(config).unwrap();
        assert_eq!(json["dangerously_skip_measurements"], true);
        assert_eq!(json["allowed_pcr_configs"], serde_json::json!([]));
        assert!(
            Config::from_json(&json.to_string())
                .unwrap()
                .verifier()
                .is_ok()
        );
        json.as_object_mut().unwrap().remove("allowed_pcr_configs");
        assert!(
            Config::from_json(&json.to_string())
                .unwrap()
                .verifier()
                .is_ok()
        );
        json.as_object_mut()
            .unwrap()
            .remove("dangerously_skip_measurements");
        assert!(Config::from_json(&json.to_string()).is_err());
        json["dangerously_skip_measurements"] = serde_json::json!(false);
        assert!(Config::from_json(&json.to_string()).is_err());
        json.as_object_mut()
            .unwrap()
            .remove("dangerously_skip_measurements");
        json["allow_debug_measurements"] = serde_json::json!(true);
        assert!(Config::from_json(&json.to_string()).is_err());
    }

    #[test]
    fn measurement_skip_ignores_supplied_pins() {
        for pins in [
            vec![],
            vec![PcrMeasurement::new(1, [0; 48])],
            vec![PcrMeasurement::new(0, [0; 48])],
            vec![PcrMeasurement::new(0, [0; 47])],
            vec![
                PcrMeasurement::new(0, [1; 48]),
                PcrMeasurement::new(1, [0; 49]),
            ],
            vec![
                PcrMeasurement::new(0, [1; 48]),
                PcrMeasurement::new(0, [1; 48]),
            ],
        ] {
            let mut config =
                Config::dangerously_skip_measurements("http://localhost:8000").unwrap();
            config.allowed_pcr_configs = vec![pins];
            let mut json = serde_json::to_value(config).unwrap();
            assert!(
                Config::from_json(&json.to_string())
                    .unwrap()
                    .verifier()
                    .is_ok()
            );
            json["dangerously_skip_measurements"] = serde_json::json!(false);
            assert!(Config::from_json(&json.to_string()).is_err());
        }
    }

    #[test]
    fn accepts_pcr_values_with_and_without_the_0x_prefix() {
        // Release metadata records PCRs 0x-prefixed; both spellings should be accepted.
        let json = r#"{
            "host_url": "http://localhost:8000",
            "allowed_pcr_configs": [[
                { "index": 0, "value": "0xab01" },
                { "index": 1, "value": "ab01" }
            ]]
        }"#;

        let json = json
            .replace("0xab01", &format!("0x{}", "ab".repeat(48)))
            .replace("ab01", &"ab".repeat(48));
        let config = Config::from_json(&json).expect("both spellings should parse");

        let pcrs = &config.allowed_pcr_configs[0];
        assert_eq!(pcrs[0].value, pcrs[1].value);

        Config::from_json(
            r#"{
            "host_url": "http://localhost:8000",
            "allowed_pcr_configs": [[{ "index": 0, "value": "0xzz" }]]
        }"#,
        )
        .expect_err("non-hex must still be rejected");
    }

    #[test]
    fn round_trips_through_json_with_defaults_applied() {
        let config = Config::new(
            "http://localhost:8000",
            vec![
                vec![
                    pontifex::PcrMeasurement::new(0, [0xab; 48]),
                    pontifex::PcrMeasurement::new(1, [0xcd; 48]),
                ],
                vec![pontifex::PcrMeasurement::new(0, [0xef; 48])],
            ],
        )
        .expect("Pontifex measurements should be accepted");
        let json = serde_json::to_value(&config).expect("config should serialize");
        assert_eq!(json["dangerously_skip_measurements"], false);
        assert_eq!(
            json["allowed_pcr_configs"],
            serde_json::json!([
                [
                    { "index": 0, "value": "ab".repeat(48) },
                    { "index": 1, "value": "cd".repeat(48) }
                ],
                [{ "index": 0, "value": "ef".repeat(48) }]
            ])
        );

        let decoded = Config::from_json(&json.to_string()).expect("config should parse");
        assert_eq!(decoded.request_timeout(), Duration::from_mins(1));
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
    }
}
