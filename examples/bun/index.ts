import * as prem_rs from "@premai/prem-rs";

const {
    ATTESTATION_SERVER
} = process.env;

if (!ATTESTATION_SERVER) throw new Error("missing ATTESTATION_SERVER...");


const client = new prem_rs.ClientBuilder(ATTESTATION_SERVER).build();
// const modules = await client.request_modules();
await client.attest();
