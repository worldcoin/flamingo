# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.9.0...flamingo-verifier-client-v0.10.0) - 2026-10-28

### Changed

- [**breaking**] upgrade public World ID dependencies to 0.18.0. Consumers must align their `world-id-flamingo` and `world-id-primitives` dependencies with this release.

## [0.9.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.8.0...flamingo-verifier-client-v0.9.0) - 2026-10-21

### Added

- [**breaking**] use the WIP-201 channel domains and attestation policy ([#149](https://github.com/worldcoin/flamingo/pull/149))
- [**breaking**] verify WIP-201 requests with world-id-flamingo and reject replays ([#148](https://github.com/worldcoin/flamingo/pull/148))
- [**breaking**] load WIP-201 release manifests and serve their release_hash ([#147](https://github.com/worldcoin/flamingo/pull/147))
- [**breaking**] release responses at WIP-201 response slots and apply its response limits ([#150](https://github.com/worldcoin/flamingo/pull/150))

### Fixed

- *(client)* depend on webpki-roots 1, drop tokio-tungstenite's roots feature ([#154](https://github.com/worldcoin/flamingo/pull/154))

## [0.8.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.7.0...flamingo-verifier-client-v0.8.0) - 2026-10-02

### Added

- *(matches)* [**breaking**] return worker diagnostics and rejection details ([#133](https://github.com/worldcoin/flamingo/pull/133))

## [0.6.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.5.0...flamingo-verifier-client-v0.6.0) - 2026-09-28

### Other

- *(verifier)* [**breaking**] replace HTTP match API with WebSocket ([#125](https://github.com/worldcoin/flamingo/pull/125))

## [0.5.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.4.0...flamingo-verifier-client-v0.5.0) - 2026-09-28

### Added

- *(client)* add an explicit dangerous measurement bypass using Pontifex 2.1.0 ([#130](https://github.com/worldcoin/flamingo/pull/130))
- *(sandbox)* [**breaking**] integrate external biometric operations with updated match claims and rejection types ([#112](https://github.com/worldcoin/flamingo/pull/112))

### Other

- [**breaking**] rename ApiErrorResponse to ErrorEnvelope and AppError to ApiError ([#119](https://github.com/worldcoin/flamingo/pull/119))

## [0.4.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.3.0...flamingo-verifier-client-v0.4.0) - 2026-09-17

### Added

- *(api)* [**breaking**] update the binary matches interface ([#113](https://github.com/worldcoin/flamingo/pull/113))

## [0.3.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.2.2...flamingo-verifier-client-v0.3.0) - 2026-09-08

### Other

- *(client)* [**breaking**] rename face verifier client to flamingo verifier client ([#105](https://github.com/worldcoin/flamingo/pull/105))

## [0.2.2](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.2.1...flamingo-verifier-client-v0.2.2) - 2026-09-07

### Other

- dzejkop/client improvements ([#72](https://github.com/worldcoin/flamingo/pull/72))

## [0.2.1](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.2.0...flamingo-verifier-client-v0.2.1) - 2026-09-05

### Added

- expose the enclave public key in assignments ([#98](https://github.com/worldcoin/flamingo/pull/98))
- adopt pontifex channel in the verifier enclave ([#96](https://github.com/worldcoin/flamingo/pull/96))

### Other

- migrate verifier client to pontifex ([#97](https://github.com/worldcoin/flamingo/pull/97))
- give the sealed match payload its own crate ([#90](https://github.com/worldcoin/flamingo/pull/90))

## [0.2.0](https://github.com/worldcoin/flamingo/compare/flamingo-verifier-client-v0.1.0...flamingo-verifier-client-v0.2.0) - 2026-09-04

### Fixed

- pad match result to obfuscate information ([#84](https://github.com/worldcoin/flamingo/pull/84))
