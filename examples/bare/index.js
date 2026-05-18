import { "default" as process } from "bare-process";

import "bare-fetch/global";
import "bare-crypto/global";
import "bare-abort-controller/global";
import "bare-encoding/global";

const {
    ATTESTATION_SERVER
} = process.env;

if (!ATTESTATION_SERVER) throw new Error("missing ATTESTATION_SERVER...");

const reticle = await import("@premai/reticle", { with: { type: "script" } });

let client = await new reticle.ClientBuilder(ATTESTATION_SERVER).build();

try {
    client.set_query(new reticle.QueryParams());
    await client.attest();
} catch (e) {
    console.log(e);
}
