// import a from "../"

import a, { QueryParams } from "../pkg";

let client = await new a.ClientBuilder("https://gateway.prem.io/").build();

try {
    let query_params = new QueryParams().with("model", "modelmodel");
    client.attest(query_params);
} catch (e) {
    console.log(e);
}
