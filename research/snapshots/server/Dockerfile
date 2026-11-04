# Recovered server build layout is retained; the original Cargo workspace is required.
FROM rust:1.91 AS builder
WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config cmake libzstd-dev libssl-dev clang libclang-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
ENV CARGO_HTTP_MULTIPLEXING=false
# Cargo metadata must declare the gravenlace_server binary.
RUN cargo install --path ./gravenlace-server --root /usr/local/cargo-install --locked --force

FROM debian:13
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl-dev libstdc++6 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 gravenlace \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /app gravenlace \
    && mkdir -p /app/gravenlace_db \
    && chown 10001:10001 /app/gravenlace_db
WORKDIR /app
COPY --from=builder /usr/local/cargo-install/bin/gravenlace_server /app/gravenlace_server
RUN chmod 0555 /app/gravenlace_server
ENV GRAVENLACE_AUTH_FILE=/run/secrets/gravenlace_operators \
    GRAVENLACE_LISTEN_ADDR=0.0.0.0:8000 \
    GRAVENLACE_ALLOW_NETWORK_BIND=1 \
    GRAVENLACE_DB_DIR=/app/gravenlace_db
USER 10001:10001
EXPOSE 8000/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error --max-time 3 http://127.0.0.1:8000/healthz || exit 1
STOPSIGNAL SIGTERM
CMD ["/app/gravenlace_server"]
