# Candidate match policy for Orb DeepFace

**Review decision requested.** Evaluate the mobile Vanilla capture cutoff as a candidate for the three-way Orb DeepFace match. Biometrics and World ID should agree on the acceptable whole-flow false-match and false-rejection rates before selecting a release policy.

## Candidate rule

For the Orb, Vanilla selfie and RTMS pipeline, require every image check to pass. Generate one embedding per role. Compare Orb to selfie, Orb to RTMS, and selfie to RTMS. Each comparison must have a finite raw cosine in `[-1, 1]` and must satisfy `raw_cosine >= 0.459`. All three comparisons must pass.

| Policy | Score used for the decision | Cutoff |
| --- | --- | --- |
| Mobile Vanilla capture | Raw cosine | 0.459 |
| Current Flamingo level 2 | Normalized cosine | 0.90 |
| Proposed comparison for evaluation | Raw cosine | 0.459 |

The phone loads its configuration by purpose. Its Vanilla capture cutoff is a baseline for evaluating this proposal. Extending it to the RTMS pairs is a separate product decision. [Mobile default configuration](https://github.com/worldcoin/app-backend-app-config/blob/main/face-auth-config/default.ts)

In real arithmetic, `(1 + 0.459) / 2 = 0.7295`. Flamingo currently rounds normalized scores to f32. For example, raw f32 `0.45900002121925354` passes the proposed rule but normalizes to `0.7294999957084656`. Compare the worker's raw score before normalization to reproduce the mobile capture boundary. [Current score conversion](../../verifier/enclave/src/biometric_engine.rs) · [Current level table](../../verifier/enclave/src/pipeline.rs)

## Qualification and release

1. Run the candidate and level 2 against the same labeled, held-out triples. Include genuine triples and different-person triples with each role replaced in turn. Measure false matches and false rejections for each pair and for the complete decision. Report sample sizes and uncertainty. If the common cutoff misses the agreed target, evaluate source-pair cutoffs on separate calibration data.
2. Test the f32 values immediately below and above the raw boundary, rejection of invalid scores, and rejection when any single pair fails. Include a regression case for the existing level 2 decision.
3. If qualified, publish the new operating point under a distinct ordered strictness value in a new signed release. Confirm ordering and meaning for every pipeline the release advertises. The authenticator selects that level, and the RP explicitly accepts its engine configuration hash. [WIP-201 strictness and versioning](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-201.md#432-match-strictness-levels)
