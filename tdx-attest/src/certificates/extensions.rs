//!
//! # Reference material
//! [Intel PCK extensions documentation](https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf)

use der::{
    Any, AnyRef, Choice, Decode, DecodeValue, FixedTag, Length, Reader, Sequence, Tag, Tagged,
    asn1::{Int, ObjectIdentifier, OctetString, OctetStringRef, SequenceRef},
    oid::{self, AssociatedOid, ObjectIdentifierRef},
};
// use sec1::der::asn1::SequenceOf;

use crate::{certificates::CertificateError, dcap::types};

#[derive(Sequence, Debug)]
struct TaggedField<'a> {
    object_identifier: ObjectIdentifier,
    data: AnyRef<'a>,
}

#[derive(Debug)]
pub struct TcbExtension {
    pub cpu_svn: Box<[u32; 16]>,
    pub pce_svn: u32,
}

impl TcbExtension {
    fn decode<'a>(mut from: AnyRef<'a>) -> Result<TcbExtension, CertificateError> {
        let fields: Vec<TaggedField> = from.decode_as()?;

        let cpu_svn = fields.get(..16).ok_or(CertificateError::WrongFormat)?;
        let cpu_svn = cpu_svn
            .iter()
            .map(|a| {
                (a.data.tag() == Tag::Integer)
                    .then(|| a.data.decode_as::<u32>().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u32>>>()
            .ok_or(CertificateError::WrongFormat)?;

        let cpu_svn = cpu_svn
            .try_into()
            .map_err(|_| CertificateError::WrongFormat)?;

        let pce_svn = fields
            .get(16)
            .and_then(|TaggedField { data, .. }| {
                (data.tag() == Tag::Integer)
                    .then(|| data.decode_as::<u32>().ok())
                    .flatten()
            })
            .ok_or(CertificateError::WrongFormat)?;

        Ok(TcbExtension { cpu_svn, pce_svn })
    }
}

#[derive(Debug)]
pub enum SgxExtension<'a> {
    Fmspc(&'a OctetStringRef),
    Tcb(TcbExtension),
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

    pub fn tcb(&self) -> Option<&TcbExtension> {
        match self {
            Self::Tcb(tcb) => Some(tcb),
            _ => None,
        }
    }
}

impl<'a> Decode<'a> for SgxExtension<'a> {
    type Error = CertificateError;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> Result<Self, Self::Error> {
        let sequence: TaggedField = decoder.decode()?;

        let extension = match sequence.object_identifier {
            Self::FMSPC_OID => Self::Fmspc(sequence.data.decode_as()?),
            Self::TCB_OID => Self::Tcb(TcbExtension::decode(sequence.data)?),
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
    const TCB_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
}

#[derive(Debug)]
pub struct SgxExtensions<'a> {
    extensions: Vec<SgxExtension<'a>>,
}

impl SgxExtensions<'_> {
    pub fn fmspc(&self) -> Option<types::Fmspc> {
        self.extensions.iter().find_map(SgxExtension::fmspc)
    }

    pub fn tcb(&self) -> Option<&TcbExtension> {
        self.extensions.iter().find_map(SgxExtension::tcb)
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
