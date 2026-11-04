# Feature overview

Gravenlace's recovered research source and the tested management demo are different artifacts. This overview keeps their evidence separate.

## Recovered server research

| Area | Evidence status |
| --- | --- |
| Operator roles, private configuration, session expiry, and authorization gates | Source present; full-server runtime behavior unverified |
| Concurrent state, listener registry, and profile models | Source present; transport implementations have mixed completeness |
| Live logs, historical records, and optional telemetry export | Source present; no full-server durability or delivery proof |
| Credential records, file metadata, technique mappings, and playbook registration | Models and handlers present; these do not establish collection, file transfer, analytics, or playbook execution |
| X25519 exchange and session-key metadata | Inline and standalone source present; cryptographic guarantees unverified |
| DNS, SMB, HTTP/3, and other declared transports | Several partial or placeholder paths; see the body-level evidence |
| Payload output and proxy/routing support | Placeholder or partial implementation; no end-to-end capability demonstrated |
| Monitoring, recovery, and shutdown | Health/lifecycle code and restart configuration present; complete readiness, self-healing, and draining not established |
| Original server build | Matching Cargo metadata was not recovered; this source is not built by repository CI |

The [detailed feature table](research/FEATURE_EVIDENCE.md) provides line links and describes each limitation. [Review notes](research/REVIEW_NOTES.md) explain the main security and completeness observations. Implant capabilities and comparative performance claims are outside this publication.

## Tested management service

| Feature | What was verified |
| --- | --- |
| Concurrent HTTP handling | Four clients completed while another connection was incomplete, both natively and in Docker |
| Health and protected process status | Health, valid/invalid authentication, and the limited route scope passed smoke checks |
| Private startup credential | Four Python tests cover token generation, private file modes, and preserving existing configuration |
| Request handling bounds | Supplied malformed/body/oversized-request rejection checks passed |
| Logging and native shutdown | Native SIGTERM shutdown and token-redaction checks passed |
| Container startup | Image built, Compose validation passed, and the container became healthy |
| Reproducible dependency graph | Five direct pins and the real committed Cargo.lock passed locked builds |
| Current publication integrity | Snapshot checksums and provenance are checked separately from runtime tests |

The [successful main-branch CI run](https://github.com/jp101216/Gravenlace-C2/actions/runs/41831371225) supports the management-service results. This is a functional baseline, not a production security audit or capacity benchmark. See [VALIDATION.md](VALIDATION.md) for details.
