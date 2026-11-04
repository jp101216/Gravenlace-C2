# Selected source-review findings

These observations apply to the frozen recovered server and standalone exchange. They are static findings, not exploit reproductions, a cryptographic proof, or a complete audit. No operational source was repaired in this publication.

## Key lifecycle and claims

The [standalone exchange](snapshots/crypto_exchange.rs#L13) creates ephemeral keypairs and writes derived key bytes to both application state and a database. It records an expiration timestamp, but that assignment does not itself enforce expiration or rotate a key.

The server's [reaper](snapshots/server/main.rs#L986) removes expired in-memory contexts. The [message-processing path](snapshots/server/main.rs#L556) reads its key from the database. This snapshot does not establish a single enforced lifetime, revocation, and erasure policy across both paths. Its comments and log messages asserting forward secrecy or enforced rotation therefore remain unverified claims.

The server also contains an [inline exchange module](snapshots/server/main.rs#L46), while the separate file repeats overlapping functionality. The recovered workspace is insufficient to establish the intended authoritative module layout. This publication does not choose or integrate one.

For general context, [OWASP's key-management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) treats key generation, storage, recovery, and destruction as lifecycle concerns. [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) discusses secret erasure in TLS 1.3. Those references explain why lifecycle evidence matters; this custom snapshot is not represented as a TLS 1.3 implementation or an independently verified protocol.

## Declared features and actual bodies

Several declarations are broader than the behavior shown. The [payload handler](snapshots/server/main.rs#L694) constructs a fixed buffer. The [SMB body](snapshots/server/main.rs#L795) has an idle timing/shutdown loop. The [QUIC engine](snapshots/server/main.rs#L1362) sets up connections but does not demonstrate HTTP/3 request processing. The [autorun handlers](snapshots/server/main.rs#L1714) register and list data rather than establish an execution engine.

The [file-record handler](snapshots/server/main.rs#L1802) accepts metadata and stores a record; comments mentioning real binary multipart uploads exceed the body shown. A row named "file transfer" would overstate the evidence.

The [feature table](FEATURE_EVIDENCE.md) records these distinctions without attempting to complete the components.

## Health, recovery, and shutdown

The [health handler](snapshots/server/main.rs#L267) is minimal liveness code. A probe declaration does not establish database readiness or recovery of failed internal work.

The [worker error path](snapshots/server/main.rs#L839) logs a failure. The [Compose restart setting](snapshots/server/compose.yaml#L1) concerns container lifecycle. Neither shows that this application supervises and recreates failed internal workers, so application self-healing remains unverified.

The [shutdown routine](snapshots/server/main.rs#L1214) marks shutdown, bounds the inventory-lock wait, aborts listener tasks, and reports WAL errors. It does not establish that every spawned connection/export operation drained. Its presence supports a statement about shutdown handling, not a complete teardown guarantee.

## Persistent and volatile state

The [startup state](snapshots/server/main.rs#L1130) creates empty listener, session, technique, and playbook collections, while selected logs, registrations, and records have database paths. The presence of a database does not establish recovery of all runtime configuration after a restart.

Some operational input/error paths also retain unchecked indexing or `unwrap` calls. Whole-path bounds and failure behavior have not been validated. No malformed operational traffic was sent and no reproducer is included.

## Earlier defensive edits

The imported server revision already includes private operator configuration, session-age checks, authenticated live logs, reduced listener inventory, administrator restriction on credential-record listing, bounded optional exports, loopback binding defaults, liveness handling, and more explicit shutdown error reporting. These are source-level changes in this recovered revision. The separately tested management service does not validate their full-server runtime behavior.

The [provenance record](PROVENANCE.json) preserves that distinction. Older review findings about a fixed embedded administrator verifier or an unauthenticated log stream must not be copied forward as if they still describe this exact revision.
