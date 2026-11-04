# Gravenlace: recovering a Rust server research project

## Why I am sharing it

Gravenlace is a security research project I want prospective employers to be able to inspect. After losing my desktop, I recovered server, crypto, and container files, but the matching original build metadata was missing. I am publishing the surviving work with a clear account of what the source shows and what has actually been tested.

The repository has two parts: the broader recovered server research and a separate, buildable management demo. The demo is useful evidence of a small working service. It is not a reconstruction of every capability represented in the recovered source.

## The engineering problem

The recovered server brings together concurrent state, management handlers, listener abstractions, record persistence, event streaming, key-exchange source, and shutdown handling. Its declarations cover more ground than some implementation bodies. A transport enum, a success log, or an expiration timestamp cannot establish a complete feature by itself.

The missing manifests also matter. The root management package's Cargo files describe that program only; substituting them for the recovered server would misrepresent the dependency graph and the build result.

## What this publication does

**Preserves the evidence.** The imported server, exchange, Dockerfile, and Compose files retain their supplied bytes. A provenance record identifies their revision context, original filenames, sizes, line endings, and hashes. The server revision already contains the earlier naming and defensive management edits, so it is not labeled as an untouched historical original.

**Checks feature claims against code bodies.** The feature evidence table distinguishes source that is present, partial implementations, placeholders, and unsupported guarantees. Examples include QUIC connection setup without demonstrated HTTP/3 request processing, playbook registration without an established execution engine, and payload output that constructs a fixed buffer.

**Keeps a reproducible runtime baseline.** The separate management service has a real Cargo.lock, exact direct dependency pins, a non-root container configuration, and a deliberately small health/status surface. Its native and container checks cover authentication, input rejection, and four clients while another connection is incomplete. Native shutdown and token-redaction checks also passed.

**Makes the build boundary explicit.** Research snapshots are outside the Cargo targets and excluded from the image context. CI verifies their integrity without executing them, then tests the management service independently.

## Review findings that matter

The exchange source creates ephemeral keypairs but also persists derived session keys. The source records expiry metadata and removes expired in-memory entries, while another path reads database keys. That is a key-lifecycle finding, not evidence of enforced rotation or proven forward secrecy.

The server also illustrates the difference between process health and readiness, container restart configuration and internal worker supervision, and initiating shutdown and proving that all work drained. Those distinctions are documented alongside the code instead of being hidden behind feature names.

## What an employer can assess

- How shared state, async workers, event channels, and persistence were organized in the recovered design.
- How feature statements were traced to specific source locations and given an evidence status.
- How a limited Rust service was packaged, authenticated, constrained, and exercised in Docker.
- How missing inputs and unverified properties were documented during source recovery.

Start with the [architecture](ARCHITECTURE.md), [feature evidence](../research/FEATURE_EVIDENCE.md), [review notes](../research/REVIEW_NOTES.md), and [validation record](../VALIDATION.md). The [management guide](MANAGEMENT_GUIDE.md) provides the reproducible demonstration.

The recovery edits, management demo, and review documentation were developed with AI assistance. The preserved server material, the reconstructed demo, and the test evidence are identified separately so reviewers can assess the actual work rather than infer authorship or functionality from a project label.
