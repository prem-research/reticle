use der::{
    Any, AnyRef, Choice, Decode, DecodeValue, Length, Sequence,
    asn1::{ObjectIdentifier, OctetString, OctetStringRef},
    oid::{self, AssociatedOid, ObjectIdentifierRef},
};

use crate::{certificates::CertificateError, dcap::types};

#[derive(Debug)]
pub enum SgxExtension<'a> {
    Fmspc(&'a OctetStringRef),
    Unknown {
        identifier: ObjectIdentifier,
        value: AnyRef<'a>,
    },
}

impl SgxExtension<'_> {
    pub fn fmspc(&self) -> Option<types::Fmspc> {
        let Self::Fmspc(fmspc) = self else {
            return None;
        };

        fmspc.as_bytes().try_into().map(types::Fmspc).ok()
    }
}

impl<'a> Decode<'a> for SgxExtension<'a> {
    type Error = CertificateError;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> Result<Self, Self::Error> {
        #[derive(Sequence)]
        struct SgxExtensionSequence<'a> {
            object_identifier: ObjectIdentifier,
            data: AnyRef<'a>,
        }

        let sequence: SgxExtensionSequence = decoder.decode()?;

        let extension = match sequence.object_identifier {
            Self::FMSPC_OID => Self::Fmspc(sequence.data.decode_as()?),
            _ => Self::Unknown {
                identifier: sequence.object_identifier,
                value: sequence.data,
            },
        };

        Ok(extension)
    }
}

impl SgxExtension<'_> {
    const FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");
}

#[derive(Debug)]
pub struct SgxExtensions<'a> {
    extensions: Vec<SgxExtension<'a>>,
}

impl SgxExtensions<'_> {
    pub fn fmspc(&self) -> Option<types::Fmspc> {
        self.extensions.iter().find_map(SgxExtension::fmspc)
    }
}

impl AssociatedOid for SgxExtensions<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
}

impl<'a> der::Decode<'a> for SgxExtensions<'a> {
    type Error = CertificateError;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> Result<Self, Self::Error> {
        let extensions: Vec<SgxExtension<'_>> = decoder.decode()?;
        Ok(SgxExtensions { extensions })
    }
}
