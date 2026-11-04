# Recovered Gravenlace server research

This directory publishes the supplied server and exchange material for static review. It preserves the larger project context that the separate management demo does not implement.

| File | Preserved material |
| --- | --- |
| [snapshots/server/main.rs](snapshots/server/main.rs) | Current recovered server revision: 80,914 bytes and 1,952 lines |
| [snapshots/crypto_exchange.rs](snapshots/crypto_exchange.rs) | Standalone exchange source: 5,029 bytes and 101 lines |
| [snapshots/server/Dockerfile](snapshots/server/Dockerfile) | Recovered server Dockerfile: 1,478 bytes |
| [snapshots/server/compose.yaml](snapshots/server/compose.yaml) | Recovered server Compose configuration: 790 bytes |

## Revision and preservation

The server and container files already include the earlier Gravenlace naming and defensive management edits. Those revisions are preserved byte-for-byte in this import. The standalone crypto file is preserved as supplied. The files are not described as untouched historical originals from the lost desktop.

[PROVENANCE.json](PROVENANCE.json) records the supplied filenames, revision context, byte counts, line endings, and SHA-256 hashes. [SHA256SUMS](SHA256SUMS) is the compact integrity list. Snapshot files are exempt from Git text normalization so the original crypto CRLF bytes remain intact.

## Build and validation scope

The matching original server manifests and lockfile were not recovered. This directory supplies no replacement Cargo metadata, peer implementation, or instructions for completing the operational server. The snapshot Dockerfile still refers to its historical workspace layout; that workspace is not reconstructed here.

These files are outside the root Cargo targets and explicitly excluded from the management image's build context. The compiled `src/` directory contains the separate health/status service. Passing its CI does not establish that these research files compile, interoperate, or provide their claimed security properties.

The server already has an inline `crypto_exchange` module. The standalone file overlaps it; this publication makes no new integration or module-selection decision. No source body was repaired or extended during this import.

## Reading order

1. Start with the [technical case study](../docs/CASE_STUDY.md) and [architecture notes](../docs/ARCHITECTURE.md).
2. Use [FEATURE_EVIDENCE.md](FEATURE_EVIDENCE.md) to connect feature statements to code bodies.
3. Read [REVIEW_NOTES.md](REVIEW_NOTES.md) before treating source comments as guarantees.
4. Check the [validation record](../VALIDATION.md) to distinguish static review from executed tests.

No implant implementation, payload executable, credential file, database contents, or certificate private key is included. Component names and placeholder output labels inside the server source do not supply the corresponding implant code.
