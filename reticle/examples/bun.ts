// import a from "../"

import { ClientBuilder, QueryParams, GatewayError } from "../pkg/prem_rs.js";


try {
    let client = await new ClientBuilder("https://gateway.prem.io/").build();
    let query_params = new QueryParams().with("model", "modelmodel");

    await client.attest(query_params);
} catch (e) {
    if (e.kind instanceof GatewayError)
        console.log("Gateway error:", e.kind.message);
    else
        console.log(e);
}
