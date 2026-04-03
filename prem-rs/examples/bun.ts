// import a from "../"

import a from "../pkg"

let client = new a.ClientBuilder("htswtp://localddfewdfeahost:8000").build();

try {
    client.attest()
} catch (e) {
    console.log(a);
}
