import { TextEncoder, TextDecoder } from 'bare-encoding';
import { Headers, Request, Response } from 'bare-fetch';
import fetch from 'fetch';
import { AbortController } from 'bare-abort-controller';
import { getRandomValues } from 'bare-crypto/web';
import { "default" as process } from "bare-process";

global.fetch = fetch;
global.Headers = Headers;
global.Request = Request;
global.Response = Response;
global.AbortController = AbortController;
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
global.crypto = {
    getRandomValues
};

const {
    ATTESTATION_SERVER
} = process.env;

if (!ATTESTATION_SERVER) throw new Error("missing ATTESTATION_SERVER...");

const prem = await import("@premai/prem-rs", { with: { type: "script" } });

let client = await new prem.ClientBuilder(ATTESTATION_SERVER).build();

try {
    let query_params = new prem.QueryParams();
    await client.attest(query_params);
} catch (e) {
    console.log(e);
}
