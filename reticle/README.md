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

// End-to-end attestation: discovers modules, generates nonces,
// verifies cryptographic signatures and certificate chains
const result = await client.attest();

console.log("CPU:", result.modules().cpu());   // CpuModule.Sev or CpuModule.Tdx
console.log("GPU:", result.modules().gpu());   // GpuModule.Nvidia or undefined
```

## API

### `ClientBuilder`

Creates and configures a `Client` instance. `build()` is async.

```typescript
const client = await new ClientBuilder(url)
  .with_authorization("Bearer <token>")  // optional: set Authorization header
  .with_kds(new Kds(kdsUrl))             // optional: custom AMD KDS cache
  .with_pcs(new Pcs(pcsUrl))             // optional: custom Intel PCS cache
  .with_policies_url(policiesUrl)        // optional: custom OPA policies index URL
  .build();
```

### `Client`

#### High-level (recommended)

These methods handle nonce generation, request, and full cryptographic verification in a single call:

| Method | Returns | Description |
|---|---|---|
| `client.attest()` | `Promise<AttestResult>` | Full attestation of all available modules (CPU + GPU) |
| `client.attest_sev()` | `Promise<void>` | AMD SEV-SNP attestation only |
| `client.attest_tdx()` | `Promise<void>` | Intel TDX attestation only |
| `client.attest_nvidia()` | `Promise<ResponseHeaders>` | NVIDIA GPU attestation only |

To pass custom query parameters, call `set_query` before attesting:

```typescript
const query = new QueryParams()
  .with("model", "my-model")
  .with("version", "1.0");

client.set_query(query);
await client.attest();
```

#### Low-level

These methods fetch and parse attestation evidence (**discouraged**) — useful when you need to inspect raw data or implement custom validation:

| Method | Returns | Description |
|---|---|---|
| `client.request_modules()` | `Promise<Modules>` | List available attestation modules on the server |
| `client.request_sev(nonce: SevNonce)` | `Promise<ParsedAttestation>` | Fetch raw SEV-SNP attestation report |
| `client.request_tdx(nonce: TdxNonce)` | `Promise<TdxQuote>` | Fetch raw TDX quote |
| `client.request_nvidia(nonce: NvidiaNonce)` | `Promise<NvidiaAttestResult>` | Fetch raw NVIDIA EAT attestation result |

### `AttestResult`

Returned by `client.attest()`.

| Method | Returns | Description |
|---|---|---|
| `result.modules()` | `Modules` | CPU and GPU module info |
| `result.headers()` | `AttestHeaders` | HTTP response headers from attestation requests |

`Modules` exposes:
- `.cpu()` → `CpuModule` (`CpuModule.Sev` or `CpuModule.Tdx`)
- `.gpu()` → `GpuModule | undefined` (`GpuModule.Nvidia` or `undefined`)
- `.has_gpu()` → `boolean`

`AttestHeaders` exposes:
- `.cpu()` → `ResponseHeaders | undefined`
- `.gpu()` → `ResponseHeaders | undefined`

### `QueryParams`

Pass custom query parameters to the attestation server. The `nonce` key is reserved and will throw if used.

```typescript
const query = new QueryParams()
  .with("model", "my-model")
  .with("version", "1.0");

client.set_query(query);
```

### Low-level sub-module usage

Lower-level types are available as top-level named exports:

```typescript
import {
  fetch_keychain,
  EATToken,
  Kds,
  NvidiaNonce,
  SevNonce,
} from "@premai/reticle";

// NVIDIA: manual token parsing and verification
const keychain = await fetch_keychain();
const nonce = NvidiaNonce.generate();
const token = EATToken.parse(rawJwt);
const claims = token.verify(keychain, nonce);

// AMD SEV-SNP: manual certificate chain verification
const kds = new Kds("https://kds.example.com");
const sevNonce = SevNonce.generate();
const chain = await kds.fetch_certificates(attestation);
attestation.verify(chain, sevNonce);
```

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
