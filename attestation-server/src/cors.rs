use rocket::http::Method;
use rocket_cors::{AllowedHeaders, AllowedOrigins, Cors, CorsOptions, Error};

pub fn cors() -> Result<Cors, Error> {
    CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_methods: [Method::Get, Method::Post]
            .into_iter()
            .map(Into::into)
            .collect(),
        allowed_headers: AllowedHeaders::some(&["Content-Type", "Authorization"]),
        allow_credentials: false,
        send_wildcard: true,
        ..Default::default()
    }
    .to_cors()
}
