# reticle

Hardware attestation SDK for JavaScript and TypeScript. Cryptographically verifies AMD SEV-SNP, Intel TDX, and NVIDIA GPU attestations from an [attestation server](https://github.com/prem-research/reticle) — runs in Node.js, Bun, Deno and the browser via WASM.

## Install

```bash
npm install @premai/reticle
```

## Quick start

```typescript
import { ClientBuilder } from "@premai/reticle";

const client = await new ClientBuilder("https://attestation.example.com")
  .build();

// End-to-end attestation: generates a nonce, verifies signatures and
// certificate chains, evaluates the signed OPA policies and binds the
// workload Init-Data and GPU count (see "What attest() verifies")
const result = await client.attest();

console.log("CPU:", result.modules().cpu());   // CpuModule.Sev, CpuModule.Tdx or CpuModule.Azure
console.log("GPU:", result.modules().gpu());   // GpuModule.Nvidia or undefined
```

## API

### `ClientBuilder`

Creates and configures a `Client` instance. `build()` is async: it fetches the
sigstore-signed OPA policies and the signed `measurements.json` catalog from
Trustbase, so a client is ready to verify as soon as it is built.

```typescript
const client = await new ClientBuilder(url)
  .with_authorization("Bearer <token>")  // optional: set Authorization header
  .with_kds(new Kds(kdsUrl))             // optional: custom AMD KDS cache
  .with_pcs(new Pcs(pcsUrl))             // optional: custom Intel PCS cache
  .with_policies_url(policiesUrl)        // optional: custom OPA policies index URL
  .with_measurements_url(trustbaseUrl)   // optional: custom Trustbase measurements URL
  .with_gpu_required(true)               // optional: fail if the server reports no GPU
  .build();
```

### `Client`

#### High-level (recommended)

| Method | Returns | Description |
|---|---|---|
| `client.attest()` | `Promise<AttestResult>` | Full attestation of all available modules (CPU + GPU). See [What `attest()` verifies](#what-attest-verifies). |
| `client.set_query(query: QueryParams)` | `void` | Set custom query parameters sent with every attestation request |

To pass custom query parameters, call `set_query` before attesting:

```typescript
const query = new QueryParams()
  .with("model", "my-model")
  .with("version", "1.0");

client.set_query(query);
await client.attest();
```

#### Low-level

This method fetches the raw evidence without verifying it (**discouraged**) —
useful when you need to inspect the response or implement custom validation:

| Method | Returns | Description |
|---|---|---|
| `client.request_attestation(nonce: CvmNonce)` | `Promise<AttestResponse>` | Fetch the unified CVM report (manifest, CPU report, optional GPU token) bound to `nonce` |

### What `attest()` verifies

`attest()` fails (rejects) unless **all** of the following hold:

1. **Nonce binding** — the CPU report's `report_data` is bound to a fresh
   64-byte nonce and the pod manifest; the GPU token is bound to the CPU report.
2. **Hardware evidence** — the SEV-SNP certificate chain (via KDS), the TDX
   quote and PCS collateral, the Azure vTPM/HCL report, or the NVIDIA NRAS EAT
   token verify cryptographically.
3. **OPA policy** — the sigstore-verified policy for the module
   (`sev`, `tdx`, `azure`, `nvidia`) allows the claims against the signed
   `measurements.json` catalog.
4. **Workload catalog** — the manifest's `workload_id` is present in the
   signed `measurements.json`. Unknown workloads are rejected.
5. **Init-Data binding** — the SEV `host_data` (or TDX `mrconfigid`) equals
   the digest of the workload's signed Init-Data from the catalog, so the
   agent policy running inside the CVM is exactly the one Trustbase published.
6. **GPU count** — the workload's signed Init-Data is fetched from the
   Trustbase repository, checked against its catalog digest, and its agent
   policy is parsed for the number of GPUs assigned to the pod. The number of
   verified GPU tokens must equal that number. A workload whose policy assigns
   no GPU must present no GPU evidence; a workload that assigns GPUs must
   present exactly that many verified GPUs.

`with_gpu_required(true)` adds a stricter check on top of (6): the server
must report GPU evidence even if the Init-Data policy assigns no GPU.

### `AttestResult`

Returned by `client.attest()`.

| Method | Returns | Description |
|---|---|---|
| `result.pod_report()` | `any` | The pod manifest (`workload_id`, `podvm_version`) as plain JSON |
| `result.modules()` | `Modules` | CPU and GPU module info |
| `result.headers()` | `ResponseHeaders` | HTTP response headers from the attestation request |

`Modules` exposes:
- `.cpu()` → `CpuModule` (`CpuModule.Sev`, `CpuModule.Tdx` or `CpuModule.Azure`)
- `.gpu()` → `GpuModule | undefined` (`GpuModule.Nvidia` or `undefined`)
- `.has_gpu()` → `boolean`

`ResponseHeaders` exposes:
- `.get(name: string)` → `string | undefined`
- `.keys()` → `string[]`

### `QueryParams`

Pass custom query parameters to the attestation server. The `nonce` key is reserved and will throw if used.

```typescript
const query = new QueryParams()
  .with("model", "my-model")
  .with("version", "1.0");

client.set_query(query);
```

### Low-level sub-module exports

The building blocks used by `Client` are also exported, for callers that
implement their own flow: `Kds`, `Pcs`, `SevQuote`, `VerifiedChain`, `CRL`,
`EATToken`, `KeyChain`, and the nonce types `CvmNonce`, `SevNonce`, `TdxNonce`
and `NvidiaNonce` (each with `generate()` and `to_hex()`).

```typescript
import { CvmNonce, EATToken, Kds, SevQuote } from "@premai/reticle";

// Raw evidence bound to a nonce you control
const nonce = CvmNonce.generate();
const response = await client.request_attestation(nonce);

// AMD SEV-SNP: parse a raw report and fetch its verified certificate chain
const quote = SevQuote.new(reportBytes);
const chain = await new Kds("https://kds.example.com").fetch_certificates(quote);

// NVIDIA: parse a raw EAT token
const token = EATToken.parse(rawJwt);
```

These exports do not run the policy, Init-Data or GPU-count checks; prefer
`client.attest()` unless you need the raw data.

## Memory management

WASM objects are not garbage-collected automatically. Call `.free()` when done, or use `using` (TypeScript 5.2+) for automatic disposal:

```typescript
using client = await new ClientBuilder(url).build();
using result = await client.attest();
// automatically freed at end of scope
```

## Examples

- **[Bun](../examples/bun)** — minimal CLI attestation
- **[Vite](../examples/vite)** — browser UI with attestation status

## License

See [LICENSE](../LICENSE).
