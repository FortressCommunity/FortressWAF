# FortressWAF Performance Benchmarks

> **No per-benchmark figures are published here.** The earlier contents of this
> file measured the Go implementation's benchmark suite. That backend — and its
> benchmark harness — was removed when the project was rewritten in Rust, so the
> old numbers no longer describe this code. Rather than carry forward numbers
> that no longer correspond to anything, this file states how to measure the
> current implementation yourself.

## Measuring the current (Rust) build

```bash
cd rust
cargo build --release --locked

# Run the proxy and read the in-process Prometheus metrics.
./target/release/fortresswaf --config ../deploy/config.yaml &
curl -s http://localhost:9090/metrics | grep fortresswaf_
```

The engine hot path can be exercised without the proxy:

```bash
cd rust
# The full detection pipeline over the whole attack corpus, timed:
cargo test --workspace --test attack_corpus --release -- --nocapture
```

## What is (and is not) claimed

- **Correctness is measured on every CI run.** `cargo test --workspace` walks
  the full detection pipeline over the entire attack corpus (≈1,400 payloads)
  and asserts the documented per-category detection floors and zero false
  positives on the benign corpus. See `rust/DEVIATIONS.md`.
- **Throughput/latency numbers are host-specific** and depend on the enabled
  inspector set and config. No single "requests per second" figure is quoted
  here because it would not hold across deployments.
- To profile: build release and run under `perf` (Linux), e.g.
  `perf record -g -- ./target/release/fortresswaf --config ../deploy/config.yaml`.

## History

The pre-rewrite benchmark numbers (Go, reference host DO-Regular 4 vCPU / 8 GB)
are preserved in the git history of this file if a comparison is ever needed.
