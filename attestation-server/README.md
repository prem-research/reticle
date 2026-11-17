# Attestation Server

Rocket service providing CPU/GPU attestation and a streaming OHTTP reverse proxy for confidential workloads.

## Operation

At startup, the server detects SEV-SNP (`/dev/sev-guest`), TDX (`/dev/tdx-guest`), or Azure Confidential VM (IMDS), in that order. NVIDIA support is enabled when `/dev/nvidiactl` exists; initialization remotely attests the GPUs, verifies the returned evidence, and enables confidential-compute operation. A supported CPU platform is mandatory.

Each process generates an ephemeral OHTTP key (X-Wing KEM; HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305). Its public configuration is included in the pod manifest alongside the workload ID and PodVM image version. Attestation binds the manifest to the client nonce; optional NVIDIA evidence binds the CPU report to the same nonce. Binding uses SHA-512 over `nonce || postcard(data)`, truncated to the platform's input size.

Clients must verify the evidence, bindings, and manifest policy before trusting the OHTTP key. Restarting the server rotates the key and requires fresh attestation. The gateway decrypts chunked OHTTP/BHTTP requests, forwards them to configured backends, and streams encrypted BHTTP responses.

## Endpoints

| Method | Path | Contract |
| --- | --- | --- |
| GET | `/attestation/modules` | Detected modules, e.g. `{"cpu":"Tdx","gpu":null}`. CPU: `Sev`, `Tdx`, or `Azure`; GPU: `Nvidia` or `null`. |
| GET | `/attestation/attest?nonce=<nonce>` | Returns a JSON `CvmReport` containing `manifest`, `cpu`, and `gpu`. Nonce must decode to exactly 64 bytes; accepts hex or unpadded base64url, trying hex first. |
| GET | `/gateway/key_config` | JSON `{"key_config":"<base64>"}` containing the encoded public OHTTP key configuration, **without attestation**. |
| POST | `/gateway/` | Chunked OHTTP-encapsulated BHTTP request; returns `message/ohttp-chunked-res`. Request reader is capped at 20 MiB. Backend status and headers are carried inside the encrypted response. |

`CvmReport.cpu` is externally tagged as `Sev`, `Tdx` (base64 quote), or `Azr`; `gpu` is `"Absent"` or `{"Nvidia":"<detached EAT>"}`. The manifest contains `podvm_version`, `workload_id`, and `ohttp_key_config: {"key_config":"<base64>"}`. See [`attestation-protocol`](../attestation-protocol/src/report.rs) for evidence schemas.

Handler errors return HTTP 500 with `{"failed":true,"error":"..."}`; Rocket handles request-validation errors separately. Unknown routes return HTTP 404 with `route not found`. No application-level authentication is implemented.

Browser CORS is handled by `rocket_cors` and allows any origin (`*`), GET/POST, and `Content-Type`/`Authorization` headers. Valid unrouted CORS OPTIONS preflights return an empty HTTP 204; disallowed methods or headers return HTTP 403. Cookie credentials are not supported. This applies only to this server; collateral and policy services need their own CORS configuration.

## Configuration

`RETICLE_CONFIG` selects the required TOML file; default: `./config.toml`, relative to the working directory.

```toml
[[gateway.routes]]
path = "/api"
forward_to = "http://127.0.0.1:8080"
```

Routes match decrypted request paths on segment boundaries. The matched prefix is replaced with the backend URL's path, preserving the request query: `/api/v1?q=x` becomes `http://127.0.0.1:8080/v1?q=x`. The configured backend determines the host, not the encapsulated authority. Redirects are not followed; hop-by-hop headers are stripped and request trailers are unsupported. Use `[gateway]` with `routes = []` if no forwarding routes are needed.

| Variable | Purpose |
| --- | --- |
| `RETICLE_CONFIG` | Gateway configuration path. |
| `ROCKET_ADDRESS` | Bind address; container sets `0.0.0.0`. |
| `ROCKET_PORT` | Listening port; default/container value: `8000`. |
| `RUST_LOG` | Application log filter; default: `info`. |

Required PodVM metadata files (fixed paths):

- `/run/podvm/os-release`: `KEY=VALUE` lines including `IMAGE_VERSION`.
- `/run/podvm/initdata.toml`: string fields `algorithm`, `version`, and a `[data]` string map containing `id` (workload ID).

Expose the selected platform's devices with appropriate permissions. TDX additionally requires a working configfs TSM quote provider under `/sys/kernel/config`; the container entrypoint mounts configfs when `/dev/tdx-guest` exists, requiring mount privileges if not already mounted. Azure requires IMDS access and `/dev/tpmrm0` or `/dev/tpm0`. NVIDIA requires its devices, NVML/NVAT runtime libraries, and network access to remote attestation/key services. Missing metadata or platform initialization failures prevent startup.

## Run

From the repository root, with platform dependencies and metadata available:

```sh
cargo build --release -p attestation-server
RETICLE_CONFIG=attestation-server/config.toml \
  ROCKET_ADDRESS=0.0.0.0 ./target/release/attestation-server
```

The Dockerfile packages the prebuilt `target/release/attestation-server` and `${SYSROOT}/lib` from the repository-root build context. Mount the configuration and PodVM metadata, pass the required devices/libraries, and set `RETICLE_CONFIG` to the mounted file; the image does not include `config.toml`.
