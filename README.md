<img src="/.github/assets/reticle.png" width="400px" align="right"></img>

### reticle



Hardware attestation stack for confidential computing environments.

Verifies the integrity of CPUs (AMD SEV-SNP, Intel TDX) and GPUs (NVIDIA) through cryptographic attestation.

Includes an attestation server serving REST APIs and a portable SDK with support for Node.js, Bun, Deno, and browser runtimes.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  attestation-server                 │  REST API
│              runtime module detection               │
└──────┬──────────────┬──────────────┬────────────────┘
       │              │              │
┌──────▼─────┐ ┌──────▼─────┐ ┌──────▼─────────┐  ┌───────────┐
│ snp-attest │ │ tdx-attest │ │ nvidia-attest  │  │ libattest │ (Core primitives)
│  AMD SNP   │ │ Intel TDX  │ │  GPU (EAT/JWT) │  └───────────┘
└──────┬─────┘ └──────┬─────┘ └──────┬─────────┘
       │              │              │
       └──────────────┼──────────────┘
                      |
                      │
                ┌─────▼─────┐
                │  prem-rs  │  Unified WASM SDK
                └───────────┘

```

| Crate | Description |
|---|---|
| **[libattest](./libattest)** | Core library: nonce generation, pluggable `VerificationRule` trait, module detection |
| **[snp-attest](./snp-attest)** | AMD SEV-SNP attestation — report generation & verification via X.509 cert chains |
| **[tdx-attest](./tdx-attest)** | Intel TDX attestation — DCAP quote verification via Intel PCS |
| **[nvidia-attest](./nvidia-attest)** | NVIDIA GPU attestation — EAT/JWT token parsing & signature verification |
| **[prem-rs](./prem-rs)** | Unified WASM SDK aggregating all modules, published to npm |
| **[attestation-server](./attestation-server)** | REST server with runtime hardware detection |

## Prerequisites

- Rust toolchain (stable)
- CMake and a C++ compiler (for NVIDIA attestation SDK)
- `libssl-dev`, `pkg-config`
- `wasm-pack` (for WASM builds)
- Optional: `libtss2-dev` (for AMD SEV-SNP with Hyper-V support)

## Build

### NVIDIA C++ SDK

```bash
make nvidia-cpp-sdk
```

This clones, builds, and installs the NVIDIA attestation SDK (`libnvat`).

### Rust binaries

```bash
make bins
```

Optionally build a specific package or feature set:

```bash
make bins PACKAGE=snp-attest FEATURES=hyperv
```

### WASM SDK

```bash
make wasm
```

Produces the `@premai/prem-rs` npm package in `prem-rs/pkg/`.

### Docker (attestation-server)

The attestation server ships as a Docker image built via the CI pipeline. See [`attestation-server/Dockerfile`](./attestation-server/Dockerfile).

## Development

### Testing the WASM SDK locally

1. Build the WASM package:
   ```bash
   make wasm
   ```
2. Link the local package:
   ```bash
   cd prem-rs/pkg && npm link
   ```
3. Use it in an [example](./examples):
   ```bash
   cd examples/bun && bun link @premai/prem-rs
   ```

### Running the attestation server

```bash
cargo run -p attestation-server
```

The server auto-detects available hardware modules (SEV-SNP, TDX, NVIDIA GPU) and exposes matching endpoints under `/attestation/`.

## API

| Endpoint | Description |
|---|---|
| `GET /attestation/modules` | Lists available attestation modules on this host |
| CPU attestation routes | Dynamically registered based on detected CPU TEE (SNP or TDX) |
| GPU attestation routes | Registered when NVIDIA GPU module is available |

## License

See [LICENSE](./LICENSE).
