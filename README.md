# dkg-ceremony

Coordinator tool for running a RedPallas FROST DKG (Orchard spend-auth, RedPallas) to produce:

- an Orchard-compatible group spend validating key `ak` (32 bytes, canonical sign-bit enforced)
- a single public `KeysetManifest.json` that operators and auditors can verify

This repo is part of the `junocash-tools` org.

## Build / Test

- `make build`
- `make test`
- `make test-unit`
- `make test-e2e`
- `make lint`

## Usage

`dkg-ceremony` is driven by a ceremony `config.json` (see `CeremonyConfigV1` in `src/config.rs`).

### Inputs

The config includes:

- `threshold` and `max_signers` (enforced: `1 < threshold <= max_signers`)
- `network` (`mainnet`, `testnet`, `regtest`) which selects ZIP-316 HRPs:
  - UA HRP: `j` / `jtest` / `jregtest`
  - UFVK HRP: `jview` / `jviewtest` / `jviewregtest`
- a `roster` of participants, including:
  - stable `operator_id` strings (recommended: lowercase hex Ethereum address)
  - online transport info (`grpc_endpoint`) for each operator when running online
  - offline transport info (`age_recipient`) for each operator when running offline

#### Identifier Assignment Rule

Participants are assigned FROST identifiers deterministically:

1. sort `operator_id` ascending
2. assign identifiers `1..=n` (u16, non-zero)

This rule is used by both `dkg-ceremony` and `dkg-admin` (which refuses to participate if it is assigned a different identifier than the roster implies).

### Config Examples

Roster (`RosterV1`) example (online):

```json
{
  "roster_version": 1,
  "operators": [
    { "operator_id": "0x...01", "grpc_endpoint": "https://op1.example.com:8443" },
    { "operator_id": "0x...02", "grpc_endpoint": "https://op2.example.com:8443" },
    { "operator_id": "0x...03", "grpc_endpoint": "https://op3.example.com:8443" },
    { "operator_id": "0x...04", "grpc_endpoint": "https://op4.example.com:8443" },
    { "operator_id": "0x...05", "grpc_endpoint": "https://op5.example.com:8443" }
  ]
}
```

Roster (`RosterV1`) example (offline):

```json
{
  "roster_version": 1,
  "operators": [
    { "operator_id": "0x...01", "age_recipient": "age1..." },
    { "operator_id": "0x...02", "age_recipient": "age1..." },
    { "operator_id": "0x...03", "age_recipient": "age1..." },
    { "operator_id": "0x...04", "age_recipient": "age1..." },
    { "operator_id": "0x...05", "age_recipient": "age1..." }
  ],
  "coordinator_age_recipient": "age1..."
}
```

Coordinator `CeremonyConfigV1` example:

```json
{
  "config_version": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "regtest",
  "roster": { "...": "see above" },
  "roster_hash_hex": "<sha256 hex>",
  "out_dir": "./out",
  "transcript_dir": "./transcript"
}
```

### Outputs

`dkg-ceremony` writes:

- `out/KeysetManifest.json` (public)
- `transcript/` (public, non-secret transcript directory)

The manifest includes (non-exhaustive):

- ordered `operators[]` with `{operator_id, identifier}`
- `ak_bytes_hex` (32)
- `nk_bytes_hex` (32) and `rivk_bytes_hex` (32) derived deterministically from `ak_bytes`
- `orchard_fvk_bytes_hex` (96) and `ufvk` (ZIP-316 bech32m, HRP `jview*`)
- `owallet_ua` (ZIP-316 bech32m unified address at diversifier index 0, HRP `j*`)
- `public_key_package` bytes (base64) + `public_key_package_hash`
- `transcript_hash`

### Canonicalization + Deterministic FVK

For Orchard compatibility and auditability:

- `ak_bytes` is enforced canonical: if `ak_bytes[31] & 0x80 != 0`, the keyset is canonicalized by negating all shares and the group key before publishing.
- `nk` and `rivk` are derived deterministically from `ak_bytes` (so the UFVK is deterministic and auditable).

### Online (mTLS gRPC)

Runs the full 2-round RedPallas FROST DKG as coordinator over mTLS gRPC to each operator's `dkg-admin`.

#### 5 Operators Runbook (n=5, threshold=3)

Coordinator:

1. Collect from each operator:
   - `operator_id` (stable string)
   - `grpc_endpoint` (where `dkg-admin serve` will listen)
2. Construct the roster and publish:
   - the full roster JSON
   - `roster_hash_hex`
   - the resulting identifier mapping (from the sort rule)
3. Ensure each operator has a `dkg-admin` config that pins the above values.
4. Run the ceremony:

```bash
dkg-ceremony --config config.json online \
  --tls-ca-cert-pem-path ca.pem \
  --tls-client-cert-pem-path client.pem \
  --tls-client-key-pem-path client.key \
  --tls-domain-name-override localhost
```

mTLS requirements:

- The coordinator presents a client certificate signed by the ceremony CA.
- Each operator presents a server certificate signed by the ceremony CA.
- Server cert SANs must match the operator `grpc_endpoint` hostnames (SNI). Use `--tls-domain-name-override` only for local testing.

Operators:

1. Verify `roster_hash_hex` and your assigned `identifier`.
2. Start `dkg-admin` in service mode:

```bash
dkg-admin --config ./config.json serve
```

On success, the coordinator distributes `out/KeysetManifest.json` and `transcript/` to all operators (and auditors).

### Offline (File Routing + Finalize)

For airgapped ceremonies, `dkg-ceremony offline` helps route files produced by operators running `dkg-admin` in offline file mode.

Round 2 packages are confidential (they contain per-recipient secret shares). `dkg-ceremony` never prints Round 2 payloads and never persists them unencrypted.

#### 5 Operators Runbook (n=5, threshold=3)

Coordinator:

1. Publish the offline roster that includes:
   - `age_recipient` for each operator (so operators can encrypt Round 2 packages to recipients)
   - optional `coordinator_age_recipient` (so operators also encrypt Round 2 packages to the coordinator for routing)
2. Collect all Round 1 package files from operators into `round1_in/`:
   - `round1_1.bin` ... `round1_5.bin`
3. Bundle per-operator Round 1 inputs:

```bash
dkg-ceremony --config config.json offline bundle-round1 \
  --round1-dir round1_in \
  --deliver-dir deliver
```

4. Deliver `deliver/round1_to_<id>/` to each operator.
5. Collect all Round 2 encrypted package files into `round2_in/`:
   - `round2_to_<recv>_from_<sender>.age` for all pairs `(sender != recv)`
6. Bundle per-operator Round 2 inputs:

```bash
dkg-ceremony --config config.json offline bundle-round2 \
  --round2-dir round2_in \
  --deliver-dir deliver
```

7. Deliver `deliver/round2_to_<id>/` to each operator.
8. After operators finalize part3, generate the public manifest + transcript:

```bash
dkg-ceremony --config config.json offline finalize \
  --round1-dir round1_in \
  --round2-dir round2_in
```

Operators run `dkg-admin dkg part1/part2/part3` and `export-key-package` (see the `dkg-admin` README for operator-side steps).

### Verification Checklist

Operators and auditors should verify:

- `operators[]` are ordered by `operator_id` ascending and identifiers are `1..=n`
- `public_key_package_hash` matches the hash computed from `public_key_package` bytes
- `transcript_hash` matches `transcript/transcript_hash.hex`
- `ak_bytes_hex` is canonical (sign-bit clear)
- (optional) decode `ufvk` and `owallet_ua` and confirm HRPs match the configured `network`

## Testing

- `make test-unit` runs hermetic unit/integration tests (no Docker).
- `make test-e2e` runs an end-to-end regtest:
  - DKG (real `dkg-admin` processes)
  - scan + plan via `juno-scan` and `juno-txbuild`
  - external signing via `juno-txsign ext-prepare` / `ext-finalize`
  - broadcast + mine against a Dockerized `junocashd` regtest

`make test` runs both.
