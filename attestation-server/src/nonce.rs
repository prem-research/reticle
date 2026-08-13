use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rocket::form::{self, FromFormField};

pub struct NonceParam<T: From<Box<[u8; N]>>, const N: usize>(pub T);

impl<T: From<Box<[u8; N]>>, const N: usize> NonceParam<T, N> {
    pub(crate) fn inner(&self) -> &T {
        &self.0
    }
}

impl<'a, const N: usize, T: From<Box<[u8; N]>> + Send + Sync> FromFormField<'a>
    for NonceParam<T, N>
{
    fn from_value(field: rocket::form::ValueField<'a>) -> rocket::form::Result<'a, Self> {
        use form::Error;

        let decoded = hex::decode(field.value) // either decode using hex
            .or(BASE64_URL_SAFE_NO_PAD.decode(field.value)) // or using base64
            .map_err(|_| {
                Error::validation("nonce could not be decoded neither from hex nor base64")
            })?;

        let nonce: Box<[u8; N]> = decoded
            .try_into()
            .map_err(|_| Error::validation(format!("nonce is not exactly {} bytes wide", N)))?;

        Ok(NonceParam(nonce.into()))
    }
}
