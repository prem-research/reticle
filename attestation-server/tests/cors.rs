use attestation_server::cors::cors;
use rocket::{
    http::{Header, Status},
    local::blocking::Client,
    routes,
};

#[rocket::get("/attestation/modules")]
fn modules() -> &'static str {
    "modules"
}

#[rocket::options("/explicit")]
fn explicit_options() -> &'static str {
    "explicit options"
}

fn client() -> Client {
    Client::tracked(
        rocket::build()
            .attach(cors().unwrap())
            .mount("/", routes![modules, explicit_options]),
    )
    .unwrap()
}

#[test]
fn preflights_support_gateway_and_attestation() {
    let client = client();
    for (path, method, headers) in [
        ("/gateway/", "POST", "content-type"),
        ("/attestation/attest?nonce=00", "GET", "authorization"),
        ("/gateway/", "POST", "content-type, authorization"),
    ] {
        let response = client
            .options(path)
            .header(Header::new("Origin", "https://app.example"))
            .header(Header::new("Access-Control-Request-Method", method))
            .header(Header::new("Access-Control-Request-Headers", headers))
            .dispatch();
        assert_eq!(response.status(), Status::NoContent);
        assert_eq!(
            response.headers().get_one("Access-Control-Allow-Origin"),
            Some("*")
        );
        let header_values = |value: &str| {
            value
                .split(',')
                .map(|part| part.trim().to_ascii_lowercase())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(
            header_values(
                response
                    .headers()
                    .get_one("Access-Control-Allow-Methods")
                    .unwrap()
            ),
            header_values("GET, POST")
        );
        assert_eq!(
            header_values(
                response
                    .headers()
                    .get_one("Access-Control-Allow-Headers")
                    .unwrap()
            ),
            header_values(headers)
        );
        assert!(
            response
                .headers()
                .get_one("Access-Control-Allow-Credentials")
                .is_none()
        );
        assert!(response.into_string().unwrap_or_default().is_empty());
    }
}

#[test]
fn preflights_reject_disallowed_methods_and_headers() {
    let client = client();
    for (method, headers) in [("DELETE", "content-type"), ("POST", "x-custom")] {
        let response = client
            .options("/gateway/")
            .header(Header::new("Origin", "https://app.example"))
            .header(Header::new("Access-Control-Request-Method", method))
            .header(Header::new("Access-Control-Request-Headers", headers))
            .dispatch();
        assert_eq!(response.status(), Status::Forbidden);
        assert!(
            response
                .headers()
                .get_one("Access-Control-Allow-Origin")
                .is_none()
        );
    }
}

#[test]
fn cors_headers_cover_successes_and_errors() {
    let client = client();
    for (path, status) in [
        ("/attestation/modules", Status::Ok),
        ("/missing", Status::NotFound),
    ] {
        let response = client
            .get(path)
            .header(Header::new("Origin", "https://app.example"))
            .dispatch();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get_one("Access-Control-Allow-Origin"),
            Some("*")
        );
    }
}

#[test]
fn ordinary_options_and_explicit_handlers_are_preserved() {
    let client = client();
    assert_eq!(
        client.options("/missing").dispatch().status(),
        Status::NotFound
    );
    let response = client
        .options("/explicit")
        .header(Header::new("Origin", "https://app.example"))
        .header(Header::new("Access-Control-Request-Method", "POST"))
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().as_deref(), Some("explicit options"));
}
