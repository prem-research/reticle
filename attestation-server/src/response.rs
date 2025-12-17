use rocket::{Responder, serde::json::Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorInner {
    error: bool,
    message: String,
}

#[derive(Responder)]
#[response(status = 500, content_type = "json")]
pub struct ApiError(Json<ErrorInner>);

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        let inner = ErrorInner {
            error: true,
            message: value.to_string(),
        };

        ApiError(inner.into())
    }
}

pub type ApiJsonResult<T> = Result<Json<T>, ApiError>;

// impl<T: std::error::Error> From<T> {}
