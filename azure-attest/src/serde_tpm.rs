use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tpm2_protocol::{TpmMarshal, TpmSized, TpmUnmarshal, TpmWriter};

pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: TpmMarshal + TpmSized,
{
    let mut buf = vec![0; T::SIZE];
    let mut writer = TpmWriter::new(&mut buf);

    obj.marshal(&mut writer)
        .map_err(<S::Error as serde::ser::Error>::custom)?;

    buf.serialize(serializer)
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TpmUnmarshal + TpmSized,
{
    let buf = Vec::<u8>::deserialize(deserializer)?;

    if buf.len() != T::SIZE {
        return Err(serde::de::Error::custom(
            "too many bytes to deserialize tpm type",
        ));
    }

    let (unmarshaled, _) = T::unmarshal(&buf).map_err(<D::Error as serde::de::Error>::custom)?;

    Ok(unmarshaled)
}
