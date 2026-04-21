use rocket::{Responder, serde::json::Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorInner {
    failed: bool,
    error: String,
}

#[derive(Responder)]
#[response(status = 500, content_type = "json")]
pub struct ApiError(Json<ErrorInner>);

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        let inner = ErrorInner {
            failed: true,
            error: value.to_string(),
        };

        ApiError(inner.into())
    }
}

pub fn ok<T>(ok: T) -> ApiJsonResult<T> {
    ApiJsonResult::Ok(Json(ok))
}

pub type ApiJsonResult<T> = Result<Json<T>, ApiError>;

// impl<T: std::error::Error> From<T> {}
