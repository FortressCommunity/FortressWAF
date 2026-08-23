# Stage 1: Builder
FROM golang:1.27-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /app/fortresswaf \
    ./cmd/proxy

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /app/fortressctl \
    ./cmd/ctl

# Stage 2: Final runtime image (distroless)
FROM gcr.io/distroless/static-debian12:latest

USER 65534:65534

COPY --from=builder /app/fortresswaf /fortresswaf
COPY --from=builder /app/fortressctl /fortressctl
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

ENV TZ=UTC

WORKDIR /

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

EXPOSE 80 443 8443 8080

ENTRYPOINT ["/fortresswaf"]
