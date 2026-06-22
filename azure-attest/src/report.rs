//! Azure confidential VM attestation report types.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub use jsonwebtoken::jwk::Jwk;

/// Fixed Azure-defined attestation report header.
#[repr(C, packed)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
pub struct AttestationReportHeader {
    /// Embedded signature. Expected value: [`ATTESTATION_REPORT_SIGNATURE`].
    pub signature: u32,
    /// Format version. Expected value: [`ATTESTATION_REPORT_VERSION`].
    pub version: u32,
    /// Size of the Azure-defined attestation report.
    pub report_size: u32,
    /// Azure-specific usage. Expected value: [`ATTESTATION_REPORT_REQUEST_TYPE`].
    pub request_type: u32,
    /// Reserved status field.
    pub status: u32,
    /// Reserved bytes.
    pub reserved: [u8; 12],
}

impl AttestationReportHeader {
    /// Azure attestation report magic value for ASCII `HCLA`.
    pub const ATTESTATION_REPORT_SIGNATURE: u32 = 0x414c_4348;
    /// Azure attestation report header version.
    pub const ATTESTATION_REPORT_VERSION: u32 = 2;
    /// Azure attestation report request type.
    pub const ATTESTATION_REPORT_REQUEST_TYPE: u32 = 2;
    /// Azure attestation report header size in bytes.
    pub const ATTESTATION_REPORT_HEADER_SIZE: usize = 32;
    /// Azure hardware report payload size in bytes.
    pub const REPORT_PAYLOAD_SIZE: usize = 1184;
    /// AMD SEV-SNP hardware report size in bytes.
    pub const SEV_REPORT_PAYLOAD_SIZE: usize = 1184;
    /// Intel TDX hardware report size in bytes.
    pub const TDX_REPORT_PAYLOAD_SIZE: usize = 1024;
    /// Offset of runtime data in the Azure report.
    pub const RUNTIME_DATA_OFFSET: usize =
        Self::ATTESTATION_REPORT_HEADER_SIZE + Self::REPORT_PAYLOAD_SIZE;
}

/// Fixed runtime data header.
#[repr(C, packed)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
pub struct RuntimeDataHeader {
    /// Size of runtime data, including this header.
    pub data_size: u32,
    /// Format version. Expected value: [`RuntimeDataHeader::RUNTIME_DATA_VERSION`].
    pub version: u32,
    /// Hardware report type.
    pub report_type: u32,
    /// Runtime claims hash algorithm.
    pub hash_type: u32,
    /// Runtime claims JSON size.
    pub claim_size: u32,
}

impl RuntimeDataHeader {
    /// Azure runtime data header size in bytes.
    pub const RUNTIME_DATA_HEADER_SIZE: usize = 20;
    /// Azure runtime data version.
    pub const RUNTIME_DATA_VERSION: u32 = 1;
    /// AMD SEV-SNP hardware report type.
    pub const REPORT_TYPE_SEV: u32 = 2;
    /// Intel TDX hardware report type.
    pub const REPORT_TYPE_TDX: u32 = 4;
    /// SHA-256 runtime claims hash type.
    pub const HASH_TYPE_SHA256: u32 = 1;
    /// SHA-384 runtime claims hash type.
    pub const HASH_TYPE_SHA384: u32 = 2;
    /// SHA-512 runtime claims hash type.
    pub const HASH_TYPE_SHA512: u32 = 3;
}

/// Owned Azure attestation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Fixed Azure-defined report header.
    pub header: AttestationReportHeader,
    /// Hardware report payload.
    pub payload: HardwareReport,
    /// Runtime data and runtime claims.
    pub runtime: RuntimeData,
}

impl AttestationReport {
    /// Hashes the measured runtime claims JSON using the algorithm declared by
    /// [`RuntimeDataHeader::hash_type`].
    pub fn hash_runtime_data(&self) -> Result<Vec<u8>, AttestationReportError> {
        match self.runtime.header.hash_type {
            RuntimeDataHeader::HASH_TYPE_SHA256 => {
                Ok(Sha256::digest(&self.runtime.claims_json).to_vec())
            }
            RuntimeDataHeader::HASH_TYPE_SHA384 => {
                Ok(Sha384::digest(&self.runtime.claims_json).to_vec())
            }
            RuntimeDataHeader::HASH_TYPE_SHA512 => {
                Ok(Sha512::digest(&self.runtime.claims_json).to_vec())
            }
            hash_type => Err(AttestationReportError::UnsupportedHashType(hash_type)),
        }
    }
}

/// Owned hardware report payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareReport {
    /// Intel TDX hardware report payload.
    Tdx(Vec<u8>),
    /// AMD SEV-SNP hardware report payload.
    Sev(Vec<u8>),
}

/// Owned runtime data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeData {
    /// Fixed runtime data header.
    pub header: RuntimeDataHeader,
    /// Raw runtime claims JSON bytes.
    pub claims_json: Vec<u8>,
}

impl RuntimeData {
    /// Deserializes runtime claims from [`RuntimeData::claims_json`].
    pub fn claims(&self) -> Result<RuntimeClaims, AttestationReportError> {
        serde_json::from_slice(&self.claims_json).map_err(AttestationReportError::from)
    }
}

/// Measured JSON runtime claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeClaims {
    /// vTPM public keys in JWK format.
    pub keys: Vec<Jwk>,
    /// Selective Azure confidential VM configuration.
    #[serde(rename = "vm-configuration")]
    pub vm_configuration: VmConfiguration,
    /// 64-byte hex string read from TPM NV index `0x01400002`.
    #[serde(rename = "user-data")]
    pub user_data: String,
}

/// Selective Azure confidential VM configuration runtime claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmConfiguration {
    /// Root certificate thumbprint, when configured.
    #[serde(rename = "root-cert-thumbprint")]
    pub root_cert_thumbprint: String,
    /// Whether VM console access is enabled.
    #[serde(rename = "console-enabled")]
    pub console_enabled: bool,
    /// Whether secure boot is enabled.
    #[serde(rename = "secure-boot")]
    pub secure_boot: bool,
    /// Whether TPM is enabled.
    #[serde(rename = "tpm-enabled")]
    pub tpm_enabled: bool,
    /// Whether TPM state is persisted.
    #[serde(rename = "tpm-persisted")]
    pub tpm_persisted: bool,
    /// Azure VM unique ID.
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: String,
}

/// Deserializes an owned Azure attestation report from TPM NV index bytes.
pub fn deserialize_attestation_report(
    bytes: &[u8],
) -> Result<AttestationReport, AttestationReportError> {
    let header_bytes = bytes
        .get(..AttestationReportHeader::ATTESTATION_REPORT_HEADER_SIZE)
        .ok_or(AttestationReportError::Truncated {
            needed: AttestationReportHeader::ATTESTATION_REPORT_HEADER_SIZE,
            actual: bytes.len(),
        })?;
    let header = *AttestationReportHeader::ref_from_bytes(header_bytes)
        .map_err(|_| AttestationReportError::InvalidLayout("attestation report header"))?;

    let report_size = header.report_size as usize;
    if bytes.len() < report_size {
        return Err(AttestationReportError::Truncated {
            needed: report_size,
            actual: bytes.len(),
        });
    }

    let report = &bytes[..report_size];
    let payload_bytes = report
        .get(
            AttestationReportHeader::ATTESTATION_REPORT_HEADER_SIZE
                ..AttestationReportHeader::RUNTIME_DATA_OFFSET,
        )
        .ok_or(AttestationReportError::Truncated {
            needed: AttestationReportHeader::RUNTIME_DATA_OFFSET,
            actual: report.len(),
        })?;

    let runtime =
        deserialize_runtime_data(&report[AttestationReportHeader::RUNTIME_DATA_OFFSET..])?;
    let payload = match runtime.header.report_type {
        RuntimeDataHeader::REPORT_TYPE_TDX => HardwareReport::Tdx(
            payload_bytes[..AttestationReportHeader::TDX_REPORT_PAYLOAD_SIZE].to_vec(),
        ),
        RuntimeDataHeader::REPORT_TYPE_SEV => HardwareReport::Sev(
            payload_bytes[..AttestationReportHeader::SEV_REPORT_PAYLOAD_SIZE].to_vec(),
        ),
        report_type => return Err(AttestationReportError::UnsupportedReportType(report_type)),
    };

    Ok(AttestationReport {
        header,
        payload,
        runtime,
    })
}

fn deserialize_runtime_data(bytes: &[u8]) -> Result<RuntimeData, AttestationReportError> {
    let header_bytes = bytes
        .get(..RuntimeDataHeader::RUNTIME_DATA_HEADER_SIZE)
        .ok_or(AttestationReportError::Truncated {
            needed: RuntimeDataHeader::RUNTIME_DATA_HEADER_SIZE,
            actual: bytes.len(),
        })?;
    let header = *RuntimeDataHeader::ref_from_bytes(header_bytes)
        .map_err(|_| AttestationReportError::InvalidLayout("runtime data header"))?;

    let data_size = header.data_size as usize;
    if bytes.len() < data_size {
        return Err(AttestationReportError::Truncated {
            needed: data_size,
            actual: bytes.len(),
        });
    }

    let runtime_data = &bytes[..data_size];
    let claims_start = RuntimeDataHeader::RUNTIME_DATA_HEADER_SIZE;
    let claims_end = claims_start
        .checked_add(header.claim_size as usize)
        .ok_or(AttestationReportError::SizeOverflow)?;
    let claims_json = runtime_data
        .get(claims_start..claims_end)
        .ok_or(AttestationReportError::Truncated {
            needed: claims_end,
            actual: runtime_data.len(),
        })?
        .to_vec();
    Ok(RuntimeData {
        header,
        claims_json,
    })
}

/// Azure attestation report deserialization error.
#[derive(Debug, Error)]
pub enum AttestationReportError {
    /// The input ended before the requested section.
    #[error("truncated attestation report: needed {needed} bytes, got {actual}")]
    Truncated {
        /// Required byte count.
        needed: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// Bytes could not be viewed as the requested fixed layout.
    #[error("invalid {0} layout")]
    InvalidLayout(&'static str),
    /// Unsupported hardware report type.
    #[error("unsupported hardware report type: {0}")]
    UnsupportedReportType(u32),
    /// Unsupported runtime hash type.
    #[error("unsupported runtime hash type: {0}")]
    UnsupportedHashType(u32),
    /// Integer overflow while calculating a section boundary.
    #[error("section size calculation overflowed")]
    SizeOverflow,
    /// Runtime claims JSON could not be deserialized.
    #[error("invalid runtime claims: {0}")]
    RuntimeClaims(#[from] serde_json::Error),
}
