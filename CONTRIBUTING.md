# Contributing

This repository contains a standalone management health/status service. Keep proposed changes within that scope. Include the concrete behavior change, checks actually run, and remaining limitations.

Run the Python metadata/helper checks and the Rust/native/container checks listed in [README.md](README.md). Generate and retain a real `Cargo.lock`; never invent transitive versions or registry checksums. Keep [DEPENDENCIES.md](DEPENDENCIES.md) and [VALIDATION.md](VALIDATION.md) accurate when versions or verification results change.

Do not commit local credentials, `.env`, build outputs, or private environment data. Use [SECURITY.md](SECURITY.md) for sensitive findings. The project license is [MIT](LICENSE); dependencies retain their own licenses.
