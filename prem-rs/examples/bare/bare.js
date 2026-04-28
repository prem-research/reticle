import { TextEncoder, TextDecoder } from 'bare-encoding';
import { Headers, Request } from 'bare-fetch';
import fetch from 'fetch';
import { AbortController } from 'bare-abort-controller';

global.fetch = fetch;
global.Headers = Headers;
global.Request = Request;
global.AbortController = AbortController;
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

const prem = await import("prem-rs", { with: { imports: "./package.json" } });

let client = await new prem.ClientBuilder("https://gateway.prem.io/").build();

try {
    let query_params = new prem.QueryParams();
    client.attest(query_params);
} catch (e) {
    console.log(e);
}
