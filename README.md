# Gravenlace-C2

Rust C2 server research, recovered source, and a tested management service.

Gravenlace is an ongoing security research project. This repository preserves the broader recovered server and exchange code for inspection, alongside a separate management demo with a reproducible build and recorded runtime checks.

## Start here

| What you want to review | Where to start |
| --- | --- |
| Project background and engineering decisions | [Technical case study](docs/CASE_STUDY.md) |
| Recovered server and crypto source | [Research snapshot](research/README.md) |
| Features and their evidence | [Feature overview](FEATURES.md) and [source evidence](research/FEATURE_EVIDENCE.md) |
| Component organization and build boundaries | [Architecture](docs/ARCHITECTURE.md) |
| Crypto, lifecycle, and completeness findings | [Review notes](research/REVIEW_NOTES.md) |
| A working administrative demo | [Management service guide](docs/MANAGEMENT_GUIDE.md) |
| What was tested | [Validation record](VALIDATION.md) |

## What is in this repository

| Material | Contents | Verification |
| --- | --- | --- |
| `research/snapshots/server/main.rs` | The 1,952-line recovered server revision, including its broader models, handlers, listener sketches, state, and lifecycle code | Preserved without content changes during this import; not compiled or runtime-validated here |
| `research/snapshots/crypto_exchange.rs` | The 101-line standalone exchange file | Preserved as supplied, including its original line endings; not integrated into the demo |
| `research/snapshots/server/Dockerfile` and `compose.yaml` | The corresponding recovered server container configuration | Reference configuration; no successful build of this recovered server is claimed |
| Root `Cargo.toml`, `Cargo.lock`, `src/`, `Dockerfile`, and `compose.yaml` | The separate Rust management service | Rust tests, Clippy, native smoke checks, and Docker startup/smoke checks passed in [CI](https://github.com/jp101216/Gravenlace-C2/actions/runs/41831371225) |

The research files already contain earlier Gravenlace naming and defensive management edits. Their [provenance record](research/PROVENANCE.json) identifies the supplied revisions and exact hashes. They are not represented as untouched copies of the lost development machine.

The root Cargo package builds the management service. It does not compile the research snapshots, and the root Docker build excludes them. No implant source, payload binaries, live credentials, databases, or certificate private keys are included.

## Research represented in the recovered source

The server contains operator/session models, concurrent shared state, listener profiles and lifecycle handlers, live/historical logging, optional telemetry export, credential and file-metadata records, technique mappings, playbook registration, key-exchange code, and shutdown handling.

Implementation depth varies. Some features have substantial source bodies; others are models, partial loops, or placeholders. The [feature evidence table](research/FEATURE_EVIDENCE.md) links each statement to the relevant code and records its limits. Source comments mentioning production status, forward secrecy, or completed capabilities are retained as source material and do not establish those claims.

## Run the tested management demo

The demo exposes process health and authenticated process status. It does not run the recovered C2 code. Follow the [management service guide](docs/MANAGEMENT_GUIDE.md) for setup, Docker startup, native builds, and the four-client smoke check.

The root manifest pins five direct crates and the committed lockfile records the tested graph. [Dependency details](DEPENDENCIES.md) apply to that demo; they are not a reconstructed dependency graph for the recovered server.

## Review the publication

```sh
python3 scripts/verify_research.py
python3 scripts/verify_structure.py
python3 -B -m unittest discover -s tests -v
```

The research verifier checks file hashes, provenance, local documentation links, and build-boundary declarations. It does not execute the snapshots or validate their cryptographic properties. CI separately builds and exercises the management service.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). MIT license: [LICENSE](LICENSE). Dependencies retain their own licenses.
