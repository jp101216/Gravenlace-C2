# Selected versions

Checked November 4, 2026 using each project's current documentation and the Rust release announcement. These are the direct versions requested by this management-only package. They are not a compiler-validated compatible graph.

| Dependency | Exact manifest version | Source |
| --- | --- | --- |
| axum | 0.8.9 | [Current crate documentation](https://docs.rs/axum/latest/axum/) |
| tokio | 1.54.1 | [Current crate documentation](https://docs.rs/tokio/latest/tokio/) |
| serde | 1.0.229 | [Current crate documentation](https://docs.rs/serde/latest/serde/) |
| serde_json | 1.0.154 | [Current crate documentation](https://docs.rs/serde_json/latest/serde_json/) |
| subtle | 2.6.1 | [Current crate documentation](https://docs.rs/subtle/latest/subtle/) |
| Rust toolchain | 1.99.1 | [Rust release announcement](https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/) |
| Rust Docker builder | 1.99.1-bookworm | [Official image tag manifest](https://github.com/docker-library/official-images/blob/master/library/rust) |

The old lockfile belonged to a dependency-free implementation and was removed. Cargo must generate the real lockfile from the registry; checksums and transitive versions have not been invented. The Dockerfile handles this first resolution, then builds with `--locked`. Export and commit the generated lockfile as described in the README.

The new service uses only these five direct crates. The recovered original C2 server's larger dependency inventory is a different project and was not migrated or made buildable by this package.

Exact pins make the selected direct versions explicit. The lockfile records actual transitive selections. Neither mechanism promises that all future releases will be compatible or that every transitive crate will use its newest published major version. Recheck releases and rerun compilation/runtime checks when updating. The included Dependabot file requests weekly update proposals without automatic merging.

No dependency advisory scan, resolved third-party license audit, Rust build, or runtime test has been completed in the preparation environment. The selected compiler, image tag, and documented crate releases were verified from primary project sources; compatibility remains unverified.
