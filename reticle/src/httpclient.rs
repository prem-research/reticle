use std::{ops::Deref, time::Duration};

use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};

#[derive(Default)]
pub struct SafeHttpBuilder {
    client: reqwest::Client,
    timeout: Option<Duration>,
}

impl SafeHttpBuilder {
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            timeout: Some(timeout),
            ..self
        }
    }

    pub fn build(self) -> SafeHttp {
        let mut client = ClientBuilder::new(self.client);
        if let Some(timeout) = self.timeout {
            client = client.with(DefaultTimeout(timeout));
        }

        SafeHttp {
            client: client.build(),
        }
    }
}

/// Middleware applying a default timeout to every outgoing request.
///
/// `Request::timeout_mut` is honored on every target (wasm32 maps it to fetch's `AbortSignal`).
/// A timeout already set on the request takes precedence.
struct DefaultTimeout(Duration);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for DefaultTimeout {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        req.timeout_mut().get_or_insert(self.0);
        next.run(req, extensions).await
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
