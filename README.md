# dkg-ceremony

Coordinator tool for running a RedPallas FROST DKG to produce an Orchard-compatible group spend validating key (`ak`) and a public `KeysetManifest.json`.

This repo is part of the `junocash-tools` org.

## Build / Test

- `make build`
- `make test`
- `make lint`

## Usage

`dkg-ceremony` is driven by a ceremony `config.json` (see `CeremonyConfigV1` in `src/config.rs`).

### Online (mTLS gRPC)

Runs the full 2-round RedPallas FROST DKG as coordinator over mTLS gRPC to each operator's `dkg-admin`, then writes:

- `out/KeysetManifest.json`
- `transcript/` (non-secret transcript directory)

Command:

```bash
dkg-ceremony --config config.json online \
  --tls-ca-cert-pem-path ca.pem \
  --tls-client-cert-pem-path client.pem \
  --tls-client-key-pem-path client.key
```

### Offline (File Routing + Finalize)

For airgapped ceremonies, `dkg-ceremony offline` helps route the Round 1 and Round 2 package files produced by operators running `dkg-admin` in file mode:

```bash
# Build per-operator Round 1 bundles:
dkg-ceremony --config config.json offline bundle-round1 \
  --round1-dir round1_in \
  --deliver-dir deliver

# Build per-operator Round 2 bundles:
dkg-ceremony --config config.json offline bundle-round2 \
  --round2-dir round2_in \
  --deliver-dir deliver

# Produce public manifest + non-secret transcript:
dkg-ceremony --config config.json offline finalize \
  --round1-dir round1_in \
  --round2-dir round2_in
```
