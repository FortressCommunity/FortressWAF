# Stage 1: Builder
FROM golang:1.25.13-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static binaries so the distroless runtime image needs no libc.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /app/fortresswaf \
    ./cmd/proxy

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /app/fortressctl \
    ./cmd/ctl

# Tiny probe used by the image and compose healthchecks.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /app/healthcheck \
    ./cmd/healthcheck

# Stage 2: Final runtime image (distroless, no shell)
FROM gcr.io/distroless/static-debian12:latest

USER 65534:65534

COPY --from=builder /app/fortresswaf /fortresswaf
COPY --from=builder /app/fortressctl /fortressctl
COPY --from=builder /app/healthcheck /healthcheck
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

ENV TZ=UTC

# /health, /ready and /live are served by the admin API on port 8443,
# not by the reverse-proxy listener.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/healthcheck", "http://localhost:8443/health"]

EXPOSE 80 443 8443

ENTRYPOINT ["/fortresswaf"]
