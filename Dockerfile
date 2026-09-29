# Stage 1: Builder (Rust)
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# The pure-Rust crates need a C toolchain for a couple of transitive deps, and
# pkg-config for any that probe the system. No OpenSSL is required: TLS is
# rustls (ring), which is pure Rust.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY rust/ ./rust/

WORKDIR /app/rust

RUN cargo build --release --locked \
    && strip target/release/fortresswaf \
    && strip target/release/fortressctl \
    && strip target/release/healthcheck

# Stage 2: Final runtime image (distroless, no shell)
FROM gcr.io/distroless/cc-debian12:latest

USER 65534:65534

COPY --from=builder /app/rust/target/release/fortresswaf /fortresswaf
COPY --from=builder /app/rust/target/release/fortressctl /fortressctl
COPY --from=builder /app/rust/target/release/healthcheck /healthcheck
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

ENV TZ=UTC

# /health, /ready and /live are served by the admin API on port 8443,
# not by the reverse-proxy listener.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/healthcheck", "http://localhost:8443/health"]

EXPOSE 80 443 8443

ENTRYPOINT ["/fortresswaf"]
