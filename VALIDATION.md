# Validation record

The runtime results below apply only to the compiled management service. The recovered server and standalone exchange have separate static-publication checks and are not compiled or executed by this workflow.

Verified November 4, 2026 in GitHub Actions on Ubuntu 24.04, using Rust 1.99.1.

Evidence: [successful complete workflow run](https://github.com/jp101216/Gravenlace-C2/actions/runs/41829639900), source commit `adaedfafdc0dc5cc81565bb3a79fa45d7b481146`.

| Check | Result |
| --- | --- |
| Current documented direct releases and Rust/image selection | Checked against primary project sources |
| Cargo dependency resolution | Passed; real lockfile generated and retained as a CI artifact |
| Recovered lockfile | Artifact SHA-256 verified; 48 packages and all five direct pins checked |
| Cargo/toolchain metadata and setup helper | Passed; four Python tests passed |
| Rust unit tests | Three passed |
| Clippy | Passed with warnings denied |
| Native release build | Passed |
| Native health, authentication, four-client concurrency, and input rejection | Passed |
| Native SIGTERM shutdown and token redaction | Passed |
| Docker Compose semantic configuration check | Passed |
| Docker image build | Passed |
| Container startup and health | Container became healthy |
| Container health, authentication, four-client concurrency, and input rejection | Passed |
| Container cleanup | Compose shutdown completed successfully |
| Formatting, systemd activation, other host architectures, and production load | Not verified |
| Dependency advisory scan and complete third-party license audit | Not performed |

The checked-in lockfile was recovered from the successful run after its ZIP artifact digest matched `37f68e1ab9b002531531fdfc54b662e0390441455950954c30aa0de17372b520`. The application source is the source exercised in that run. The follow-up repository revision commits that exact graph and makes Docker/CI require it with `--locked`.

This evidence covers the standalone management-only health/status service. It does not validate the recovered C2 server, an implant, or an encrypted tasking channel. The four-client check is a functional concurrency check, not a capacity benchmark. No production-readiness or complete security-audit claim is made.

The local preparation workspace still lacks Rust and Docker. Compilation and execution evidence above comes from the linked GitHub runner, rather than the local Python/static checks.

## Research publication checks

Four source/configuration snapshots are preserved with provenance, byte counts, line counts, and SHA-256 hashes. Their content is unchanged during this import, including the standalone exchange file's CRLF line endings. The server/container revisions already contain earlier naming and defensive management edits; they are not untouched historical originals.

The publication verifier checks snapshot identity, the expected file set, local documentation links, the absence of research Cargo manifests, and declared build-boundary settings. In CI it also examines Cargo's actual metadata and confirms that the package targets are the two management sources under `src/`.

These integrity and metadata checks do not establish source compilation, protocol interoperability, forward secrecy, feature completeness, or operational behavior of the recovered server. No implant implementation or binaries are part of the publication. See [feature evidence](research/FEATURE_EVIDENCE.md) and [review notes](research/REVIEW_NOTES.md).
