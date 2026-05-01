# prem-rs

Hardware attestation SDK for JavaScript and TypeScript. Cryptographically verifies AMD SEV-SNP, Intel TDX, and NVIDIA GPU attestations from an [attestation server](https://github.com/prem-research/reticle) — runs in Node.js, Bun, Deno and the browser via WASM.

## Install

```bash
npm install @premai/prem-rs
```

## Quick start

```typescript
import { ClientBuilder } from "@premai/prem-rs";

const client = new ClientBuilder("https://attestation.example.com")
  .build();

// End-to-end attestation: discovers modules, generates nonces,
// verifies cryptographic signatures and certificate chains
const result = await client.attest();

console.log("CPU:", result.modules().cpu());   // CpuModule.Sev or CpuModule.Tdx
console.log("GPU:", result.modules().gpu());   // GpuModule.Nvidia or undefined
```

## API

### `ClientBuilder`

Creates and configures a `Client` instance.

```typescript
const client = new ClientBuilder(url)
  .with_authorization("Bearer <token>")  // optional: set Authorization header
  .with_kds(new Kds(kdsUrl))             // optional: custom AMD KDS cache
  .with_pcs(new Pcs(pcsUrl))             // optional: custom Intel PCS cache
  .build();
```

### `Client`

#### High-level (recommended)

These methods handle nonce generation, request, and full cryptographic verification in a single call:

| Method | Description |
|---|---|
| `client.attest(query?)` | Full attestation of all available modules (CPU + GPU) |
| `client.attest_sev(query?)` | AMD SEV-SNP attestation only |
| `client.attest_tdx(query?)` | Intel TDX attestation only |
| `client.attest_nvidia(query?)` | NVIDIA GPU attestation only |

#### Low-level

These methods fetch and parse attestation evidence (**discouraged**) — useful when you need to inspect raw data or implement custom validation:

| Method | Description |
|---|---|
| `client.request_modules(query?)` | List available attestation modules on the server |
| `client.request_sev(nonce, query)` | Fetch raw SEV-SNP attestation report |
| `client.request_tdx(nonce, query)` | Fetch raw TDX quote |
| `client.request_nvidia(nonce, query)` | Fetch raw NVIDIA EAT/JWT token |

### `QueryParams`

Pass custom query parameters to the attestation server. The `nonce` key is reserved and will throw if used.

```typescript
const query = new QueryParams()
  .with("model", "my-model")
  .with("version", "1.0");

await client.attest(query);
```

### Sub-module access

Lower-level types from the attestation modules are available under namespaces:

```typescript
import { nvidia, sev } from "@premai/prem-rs";

// NVIDIA: manual token parsing and verification
const keychain = await nvidia.fetch_keychain();
const token = nvidia.EATToken.parse(rawJwt);
const claims = token.verify(keychain);
claims.validate(nonce);

// AMD SEV-SNP: manual certificate chain verification
const kds = new sev.Kds("https://kcds.prem.io");
const chain = await kds.fetch_certificates(attestation);
attestation.verify(chain, nonce);
```

## Memory management

WASM objects are not garbage-collected automatically. Call `.free()` when done, or use `using` (TypeScript 5.2+) for automatic disposal:

```typescript
using client = new ClientBuilder(url).build();
using result = await client.attest();
// automatically freed at end of scope
```

## Examples

- **[Bun](../examples/bun)** — minimal CLI attestation
- **[Vite](../examples/vite)** — browser UI with attestation status

## License

See [LICENSE](../LICENSE).
