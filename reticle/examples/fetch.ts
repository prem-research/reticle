import { ClientBuilder, QueryParams, GatewayError, AttestedHttp } from "../pkg/reticle";

try {
    let client = await new ClientBuilder("https://gateway.prem.io/").build();
    // let query_params = new QueryParams().with("model", "modelmodel");

    let attestation = await client.attest();
    let ohttp_client = new AttestedHttp(attestation);
    let fetch = ohttp_client.fetch_client();

    fetch("lmao");
} catch (e: any) {
    if (e.kind instanceof GatewayError)
        console.log("Gateway error:", e.kind.message);
    else
        console.log(e);
}
