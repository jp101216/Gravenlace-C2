# Management-only feature list

The supplied Rust/native/container checks passed in [GitHub Actions](https://github.com/jp101216/Gravenlace-C2/actions/runs/41829639900). This records a tested management-service baseline, not a production security audit.

| Feature | Scope and current evidence |
| --- | --- |
| Concurrent HTTP handling | Axum on a two-thread Tokio runtime; the four-client smoke check passed natively and in Docker |
| Health endpoint | Minimal public process-health response after configuration and socket bind succeed |
| Protected process status | Exact bearer-token authentication; version, uptime, and request count only |
| Private startup credential | Random token helper; private file-mode and non-overwrite behavior covered by passing Python tests |
| Request handling bounds | No request bodies; application header/URI bounds; 32 handler permits; handler/body timeouts |
| Logging | Fixed event/route labels and status codes; request headers and tokens are not intentionally logged |
| Shutdown | SIGINT/SIGTERM, Axum draining, eight-second deadline, honest failure on deadline expiry |
| Container configuration | Non-root, loopback host port, read-only root, dropped capabilities, bounded resource/log settings |
| Independent local instances | Separate checkouts/tokens, distinct Compose project names, configurable host ports |
| Current dependency selection | Five direct crates pinned to current documented releases, with Rust 1.99.1 selected |
| Build/runtime verification | CI passed Rust tests, lint, native smoke checks, image build/start, and container smoke checks |

This service does not implement remote team login, independent operator accounts, an implant channel, tasking, payload execution, key exchange, database-backed telemetry, or the other operational parts of the recovered C2 server. Its health endpoint is not proof of those capabilities. Container restart configuration is not a self-healing guarantee.
