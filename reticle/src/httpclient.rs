use std::{sync::LazyLock, time::Duration};

use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};

/// Client builder that injects
/// default client parameters for other parts of the program
/// to build upon
pub fn client_builder(reqwest: reqwest::Client) -> ClientBuilder {
    ClientBuilder::new(reqwest)
        .with_init(|req: RequestBuilder| req.timeout(Duration::from_secs(10)))
}

/// The default client for this application, initialized once
/// and stored
pub fn client() -> &'static ClientWithMiddleware {
    static CLIENT: LazyLock<ClientWithMiddleware> =
        LazyLock::new(|| client_builder(reqwest::Client::default()).build());
    &CLIENT
}
