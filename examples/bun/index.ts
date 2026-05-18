import * as reticle from "@premai/reticle";

const {
    ATTESTATION_SERVER
} = process.env;

if (!ATTESTATION_SERVER) throw new Error("missing ATTESTATION_SERVER...");

const client = await new reticle.ClientBuilder(ATTESTATION_SERVER).build();
// const modules = await client.request_modules();
await client.attest();
