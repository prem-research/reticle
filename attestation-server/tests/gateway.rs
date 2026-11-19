use std::{path::PathBuf, time::Duration};

use attestation_protocol::report::manifest::{PodKey, PodManifest};
use attestation_server::ohttp;
use reqwest::{Method, StatusCode, Url};
use reticle::ohttp::AttestedHttp;
use rocket::{
    Build, Rocket, State,
    fairing::AdHoc,
    response::{content::RawText, status::Custom, stream::ByteStream},
    routes,
};
use tokio::sync::{Notify, oneshot};

const TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_LEN: usize = 128 * 1024;
const LAST_LEN: usize = 96 * 1024;

struct Server {
    url: Url,
    shutdown: rocket::Shutdown,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.clone().notify();
        self.task.abort();
    }
}

async fn launch(rocket: Rocket<Build>) -> Server {
    let (ready, listening) = oneshot::channel();
    let rocket = rocket
        .configure(rocket::Config {
            address: std::net::Ipv4Addr::LOCALHOST.into(),
            port: 0,
            log_level: rocket::config::LogLevel::Off,
            ..rocket::Config::debug_default()
        })
        .attach(AdHoc::on_liftoff("Test listener", move |rocket| {
            Box::pin(async move {
                ready.send(rocket.config().port).unwrap();
            })
        }))
        .ignite()
        .await
        .unwrap();
    let shutdown = rocket.shutdown();
    let task = tokio::spawn(async move {
        rocket.launch().await.unwrap();
    });
    let port = tokio::time::timeout(TIMEOUT, listening)
        .await
        .expect("server did not start")
        .unwrap();
    Server {
        url: Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
        shutdown,
        task,
    }
}

#[rocket::post("/upstream/<path..>?<query>", data = "<body>")]
fn echo(path: PathBuf, query: &str, body: String) -> Custom<RawText<String>> {
    Custom(
        rocket::http::Status::Accepted,
        RawText(format!("{}?{query}\n{body}", path.display())),
    )
}

#[rocket::get("/upstream/stream")]
fn stream(release: &State<Notify>) -> ByteStream![Vec<u8> + '_] {
    ByteStream! {
        yield vec![b'a'; FIRST_LEN];
        release.notified().await;
        yield vec![b'b'; LAST_LEN];
    }
}

async fn setup() -> (Server, Server, AttestedHttp) {
    let backend = launch(
        rocket::build()
            .manage(Notify::new())
            .mount("/", routes![echo, stream, release]),
    )
    .await;
    let proxy: ohttp::ReverseProxyConfig = serde_json::from_value(serde_json::json!({
        "routes": [{"path": "/api", "forward_to": backend.url.join("upstream").unwrap()}]
    }))
    .unwrap();
    let key_server = ohttp::generate_key_server();
    let manifest = PodManifest {
        podvm_version: "test".into(),
        workload_id: "mock-backend".into(),
        ohttp_key_config: Some(PodKey {
            key_config: key_server.config().clone(),
        }),
    };
    let gateway = launch(
        rocket::build()
            .manage(proxy.build().unwrap())
            .manage(key_server)
            .manage(manifest)
            .mount("/gateway", routes![ohttp::ohttp_tunnel, ohttp::key_config]),
    )
    .await;

    let key = reqwest::Client::new()
        .get(gateway.url.join("gateway/key_config").unwrap())
        .timeout(TIMEOUT)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Option<PodKey>>()
        .await
        .unwrap()
        .expect("gateway must expose its public key");
    let client = AttestedHttp::new_insecure(gateway.url.join("gateway/").unwrap(), &key).unwrap();
    (backend, gateway, client)
}

#[tokio::test]
async fn forwards_requests_to_mock_backend() {
    tokio::time::timeout(TIMEOUT, async {
        let (_backend, _gateway, client) = setup().await;
        for body in ["first request", "second request"] {
            // This host must never be contacted: only the configured backend is used.
            let request = client
                .request(
                    Method::POST,
                    Url::parse("http://unused.invalid/api/nested/echo?query=hello%20world")
                        .unwrap(),
                )
                .body(body)
                .build()
                .unwrap();
            let response = client.make_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                response.headers()["content-type"],
                "text/plain; charset=utf-8"
            );
            assert_eq!(
                response.text().await.unwrap(),
                format!("nested/echo?hello world\n{body}")
            );
        }
    })
    .await
    .expect("gateway request timed out");
}

#[tokio::test]
async fn streams_response_before_backend_finishes() {
    tokio::time::timeout(TIMEOUT, async {
        let (backend, _gateway, client) = setup().await;
        let mut response = client
            .request(
                Method::GET,
                Url::parse("http://unused.invalid/api/stream").unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The backend cannot finish until the client has received the whole prefix.
        // Buffering the full response anywhere in the tunnel deadlocks this test.
        let mut first = Vec::new();
        while first.len() < FIRST_LEN {
            first.extend_from_slice(&response.chunk().await.unwrap().expect("early EOF"));
        }
        assert_eq!(first, vec![b'a'; FIRST_LEN]);

        // Notify the backend through a separate mock-only endpoint.
        reqwest::Client::new()
            .post(backend.url.join("release").unwrap())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            vec![b'b'; LAST_LEN]
        );
    })
    .await
    .expect("response was buffered instead of streamed");
}

#[rocket::post("/release")]
fn release(release: &State<Notify>) {
    release.notify_one();
}
