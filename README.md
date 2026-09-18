```text
                    __
                  .'o `.
                 /  .-. \
                 \_/  / /
                     / /       _____
                    / /     .-'     `-.
                   / /    .'           \
                  /  `---'    .---.     \
                  `-.______.-'    `-.   \
                           `-._      \   \
                               `-----.\   \
                                  ||  `-._ \
                                  ||      `-\
                                  ||      //
                                  ||     //
                                  ||    //
                                  ||   //
                                  ||  //
                                  || ((
                                  ||  `'
                               ___||___
```

<h1 align="center">Flamingo</h1>

<p align="center">
  <a href="https://github.com/worldcoin/flamingo/actions/workflows/rust-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/worldcoin/flamingo/rust-ci.yml?style=flat&labelColor=1C2C2E&label=ci&color=BEC5C9&logo=GitHub%20Actions&logoColor=BEC5C9" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg?style=flat&labelColor=1C2C2E&color=BEC5C9&label=license&logoColor=BEC5C9" alt="License: MIT"></a>
  <a href="https://deepwiki.com/worldcoin/flamingo"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
</p>

<p align="center">
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="docs/api.md">API &amp; client</a> ·
  <a href="docs/development.md">Development</a> ·
  <a href="docs/release.md">Releases</a>
</p>

⚠️ Active development. Not ready for production use. ⚠️

Flamingo compares an Orb credential photo, a live selfie, and a challenge image
inside an AWS Nitro Enclave. If all three face comparisons meet the requested
threshold, it returns a signed match statement. Images and results stay encrypted
between the client and enclave; the host relays them.

This repository includes:

- An HTTP host and enclave service for DeepFace matching.
- A Rust client that verifies enclave attestation, encrypts inputs, and checks signed results.
- Reproducible OCI and Nitro EIF builds, with PCR measurements for clients to pin.

GrayBadge and LightGuard requests are defined but not supported yet.
