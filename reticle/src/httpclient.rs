use std::{ops::Deref, time::Duration};

use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};

pub struct SafeHttpBuilder {
    client: reqwest::Client,
    timeout: Option<Duration>,
}

impl Default for SafeHttpBuilder {
    fn default() -> Self {
        Self {
            client: reqwest::Client::default(),
            timeout: None,
        }
    }
}

impl SafeHttpBuilder {
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            timeout: Some(timeout),
            ..self
        }
    }

    pub fn build(self) -> SafeHttp {
        let client = ClientBuilder::new(self.client)
            .with_init(move |req: RequestBuilder| {
                req.timeout(self.timeout.unwrap_or(Duration::MAX))
            })
            .build();

        SafeHttp { client }
    }
}

pub struct SafeHttp {
    client: ClientWithMiddleware,
}

impl SafeHttp {
    pub fn builder() -> SafeHttpBuilder {
        SafeHttpBuilder::default()
    }
}

impl Deref for SafeHttp {
    type Target = ClientWithMiddleware;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

// /// Client builder that injects
// /// default client parameters for other parts of the program
// /// to build upon
// pub fn client_builder(reqwest: reqwest::Client) -> ClientBuilder {
//     ClientBuilder::new(reqwest)
//         .with_init(|req: RequestBuilder| req.timeout(Duration::from_secs(10)))
// }
//
// /// The default client for this application, initialized once
// /// and stored
// pub fn client() -> &'static ClientWithMiddleware {
//     static CLIENT: LazyLock<ClientWithMiddleware> =
//         LazyLock::new(|| client_builder(reqwest::Client::default()).build());
//     &CLIENT
// }
