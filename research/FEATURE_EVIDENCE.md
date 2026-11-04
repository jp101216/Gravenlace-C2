# Recovered feature evidence

All rows below refer to the frozen research snapshots. **Source present** means relevant code exists and was inspected; it does not mean the recovered server compiled or passed a runtime test. **Partial** and **placeholder** describe the supplied body, regardless of its comments or success messages.

| Area | Source evidence | What the snapshot supports | Limit |
| --- | --- | --- | --- |
| Shared state | [AppState](snapshots/server/main.rs#L506) | Shared database handle, locks, concurrent maps, and channels | State lifetime and concurrency behavior not runtime-validated |
| Operator configuration and sessions | [Credential loading](snapshots/server/main.rs#L200), [authorization](snapshots/server/main.rs#L1501), [login](snapshots/server/main.rs#L1524) | Private account configuration, role checks, and expiring session logic | Source present; no full-server authentication integration proof |
| Profile schemas | [Profile types](snapshots/server/main.rs#L296) | Traffic placement, timing, mimicry, and filtering data models | Models do not prove every advertised control is implemented |
| Listener registry/lifecycle | [Factory](snapshots/server/main.rs#L808), [inventory](snapshots/server/main.rs#L1608), [deletion](snapshots/server/main.rs#L1644) | Worker creation/tracking and management handlers | Source present; worker failure and readiness handling need evidence |
| Dynamic ingress | [Handler](snapshots/server/main.rs#L600) | Profile matching and telemetry-dispatch code | Source present; not an interoperability result |
| HTTP/HTTPS declarations | [Factory selection](snapshots/server/main.rs#L812), [stream body](snapshots/server/main.rs#L1305) | Stream listener implementation and declared transport variants | The HTTPS variant selects the same raw stream body; the name alone does not establish TLS there |
| QUIC / HTTP/3 label | [Engine](snapshots/server/main.rs#L1362) | QUIC endpoint setup and connection logging | Partial; HTTP/3 request processing is not demonstrated |
| DNS | [Engine](snapshots/server/main.rs#L766) | UDP receipt and event logging | Partial; a complete DNS data channel is not shown |
| DNS-over-HTTPS label | [Ingress branch](snapshots/server/main.rs#L621) | A DNS-content-type body echo branch | Partial; full DNS-over-HTTPS behavior is not established |
| SMB | [Engine body](snapshots/server/main.rs#L795) | Timing and shutdown loop | Placeholder; pipe operations are not present in that body |
| Webhook | [Poller](snapshots/server/main.rs#L1413) | Timed HTTP polling and logging | Partial; complete bidirectional integration is not shown |
| Raw TCP console | [Worker](snapshots/server/main.rs#L1447) | Accept/read/reply loop | Diagnostic source; not a validated operator control interface |
| Payload output | [Handler](snapshots/server/main.rs#L694) | Fixed buffer and embedded profile metadata | Placeholder; no executable or declared-format generation is established |
| Proxy and routing | [Proxy scaffold](snapshots/server/main.rs#L1034), [routing branch](snapshots/server/main.rs#L550) | Session/channel structures and partial loops | Partial; end-to-end proxy/routing behavior is not demonstrated |
| Credential records | [Handler](snapshots/server/main.rs#L1756), [storage](snapshots/server/main.rs#L1883) | Record serialization, storage, and retrieval | Source present; this is not evidence of an agent collection capability |
| File metadata | [Handler](snapshots/server/main.rs#L1802), [storage](snapshots/server/main.rs#L1906) | File-metadata records | Source present; the handler does not demonstrate binary file transfer |
| Technique mapping | [Ledger update](snapshots/server/main.rs#L1687) | Technique metadata stored in a map | Source present; not an automatic detection/analytics engine |
| Autorun playbooks | [Registration/listing](snapshots/server/main.rs#L1714) | Playbook data registration and listing | Partial; an execution engine is not established by these handlers |
| Live/historical logs | [WebSocket](snapshots/server/main.rs#L858), [pipeline](snapshots/server/main.rs#L917), [history](snapshots/server/main.rs#L1848) | Streaming authorization checks and event persistence paths | Source present; durability and complete access-control coverage unverified |
| Optional telemetry export | [Pipeline](snapshots/server/main.rs#L917) | HTTPS configuration checks, send timeouts, and bounded concurrent exports | Source present; no durable retry/replay guarantee |
| Exchange implementations | [Inline module](snapshots/server/main.rs#L46), [standalone file](snapshots/crypto_exchange.rs#L13) | X25519 negotiation source in two places | Unverified; no new integration, protocol proof, or interoperability test |
| Key expiration | [RAM reaper](snapshots/server/main.rs#L986), [database lookup](snapshots/server/main.rs#L556) | Expiration metadata and in-memory removal | End-to-end expiry, rotation, erasure, and forward-secrecy claims are not established |
| Health monitoring | [Health handler](snapshots/server/main.rs#L267), [container configuration](snapshots/server/Dockerfile#L1) | Minimal liveness code and a probe declaration | Does not prove database readiness or internal worker recovery |
| Shutdown | [Signal handler](snapshots/server/main.rs#L1214) | Shutdown flag, bounded inventory-lock wait, worker aborts, and WAL reporting | Partial; complete draining/teardown unverified |
| Container lifecycle | [Dockerfile](snapshots/server/Dockerfile), [Compose](snapshots/server/compose.yaml) | Non-root/hardening configuration and container restart policy | Configuration only; the recovered workspace build is not demonstrated |
| Self-healing | [Worker error path](snapshots/server/main.rs#L839), [restart configuration](snapshots/server/compose.yaml#L1) | Error logging and a container restart setting | Application self-healing is not established |
| Implant capabilities or comparative performance | No implementation or benchmark is included | Outside this publication | Not assessed or advertised as demonstrated server features |

The root [management feature results](../FEATURES.md) have separate runtime evidence. They must not be used as proof for rows in this table.
