# Contributing

This repository contains recovered server research and a separate management health/status service. Identify which material a proposed change affects, include the evidence for behavior claims, and describe checks actually run and remaining limitations.

Preserve the published research snapshots. A different recovered revision should have its own provenance and a clear account of changes instead of silently replacing the reference bytes. Documentation corrections should point to the relevant source and distinguish implemented bodies from models, placeholders, and unverified claims. Run `python3 scripts/verify_research.py` for snapshot integrity and local-link checks.

For management-service changes, run the metadata/helper checks and the Rust/native/container checks in the [management guide](docs/MANAGEMENT_GUIDE.md). Retain the real `Cargo.lock` and update it with the manifest when dependencies change; never invent transitive versions or registry checksums. Keep [DEPENDENCIES.md](DEPENDENCIES.md) and [VALIDATION.md](VALIDATION.md) accurate. A passing management test does not validate the recovered server or exchange.

Do not commit local credentials, `.env`, build outputs, or private environment data. Use [SECURITY.md](SECURITY.md) for sensitive findings. The project license is [MIT](LICENSE); dependencies retain their own licenses.
