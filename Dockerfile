FROM rust:1.99.1-bookworm AS builder
WORKDIR /workspace
COPY . .
# Resolve the real graph on first build. Reuse a supplied lockfile on later builds.
RUN if [ ! -f Cargo.lock ]; then cargo generate-lockfile; fi \
    && cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=builder /workspace/target/release/gravenlace-management /usr/local/bin/gravenlace-management
COPY --from=builder /workspace/Cargo.lock /usr/share/gravenlace/Cargo.lock
COPY --from=builder /workspace/LICENSE /usr/share/gravenlace/LICENSE
ENV GRAVENLACE_BIND=0.0.0.0:8000 \
    GRAVENLACE_ALLOW_NON_LOOPBACK=1 \
    GRAVENLACE_TOKEN_FILE=/run/secrets/gravenlace_admin_token
USER 10001:10001
EXPOSE 8000/tcp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/gravenlace-management", "--health-check"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/gravenlace-management"]
