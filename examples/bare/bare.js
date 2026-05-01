import { "default" as process } from "bare-process";

import "bare-fetch/global";
import "bare-crypto/global";
import "bare-abort-controller/global";
import "bare-encoding/global";

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
