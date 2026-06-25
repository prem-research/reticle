use std::ops::Deref;

use libattest::error::Context;
use rsa::{BoxedUint, pkcs1v15::VerifyingKey};
use sha2::Sha256;
use tss_esapi::{
    abstraction::nv,
    handles::{KeyHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm, resource_handles::NvAuth, session_handles::AuthSession,
    },
    structures::{
        Attest, PcrSelectSize, PcrSelectionListBuilder, PcrSlot, Public, RsaExponent, Signature,
        SignatureScheme,
    },
};

use x509_cert::der::{Decode, SliceReader};

use crate::report::AttestationReport;

pub struct AzureTpmCtx {
    context: tss_esapi::Context,
}

impl AzureTpmCtx {
    pub fn new(context: tss_esapi::Context) -> Self {
        Self { context }
    }

    pub fn default_context() -> tss_esapi::Result<Self> {
        use tss_esapi::tcti_ldr::DeviceConfig;
        use tss_esapi::tcti_ldr::TctiNameConf;

        let mut context = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;

        context.set_sessions((Some(AuthSession::Password), None, None));

        Ok(Self { context })
    }

    const AK_CERT_IDX: u32 = 0x01C101D0;
    const VTPM_HCL_AKPUB_PERSISTENT_HANDLE: u32 = 0x81000003;
    const HARDWARE_REPORT_IDX: u32 = 0x01400001;

    pub const VTPM_DEFAULT_PCR_SLOTS: [PcrSlot; 24] = [
        PcrSlot::Slot0,
        PcrSlot::Slot1,
        PcrSlot::Slot2,
        PcrSlot::Slot3,
        PcrSlot::Slot4,
        PcrSlot::Slot5,
        PcrSlot::Slot6,
        PcrSlot::Slot7,
        PcrSlot::Slot8,
        PcrSlot::Slot9,
        PcrSlot::Slot10,
        PcrSlot::Slot11,
        PcrSlot::Slot12,
        PcrSlot::Slot13,
        PcrSlot::Slot14,
        PcrSlot::Slot15,
        PcrSlot::Slot16,
        PcrSlot::Slot17,
        PcrSlot::Slot18,
        PcrSlot::Slot19,
        PcrSlot::Slot20,
        PcrSlot::Slot21,
        PcrSlot::Slot22,
        PcrSlot::Slot23,
    ];

    fn tpm_read(&mut self, index: u32) -> Result<Vec<u8>, tss_esapi::Error> {
        let handle = NvIndexTpmHandle::new(index)?;
        let read = nv::read_full(&mut self.context, NvAuth::Owner, handle)?;

        Ok(read)
    }

    pub(super) fn hardware_report(&mut self) -> anyhow::Result<AttestationReport> {
        let read = self.tpm_read(Self::HARDWARE_REPORT_IDX)?;
        let report = crate::report::deserialize_attestation_report(&read)?;

        Ok(report)
    }

    pub(super) fn ak_cert(&mut self) -> anyhow::Result<x509_cert::Certificate> {
        let ak_cert = self
            .tpm_read(Self::AK_CERT_IDX)
            .context("unable to read ak_cert from tpm")?;

        let mut reader = SliceReader::new(&ak_cert)?;

        x509_cert::Certificate::decode(&mut reader)
            .context("unable to decode certificate from DER")
            .map_err(Into::into)
    }

    fn ak_handle(&mut self) -> Result<KeyHandle, tss_esapi::Error> {
        let handle = Self::VTPM_HCL_AKPUB_PERSISTENT_HANDLE.try_into()?;

        let public_key_handle = self
            .context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(handle))?
            .into();

        Ok(public_key_handle)
    }

    pub(super) fn ak(&mut self) -> anyhow::Result<VerifyingKey<Sha256>> {
        let public_key_handle = self.ak_handle()?;
        let (public, _, _) = self
            .context
            .execute_without_session(|ctx| ctx.read_public(public_key_handle))?;

        let Public::Rsa {
            unique, parameters, ..
        } = public
        else {
            anyhow::bail!("received public key that was not rsa");
        };

        let exponent = match parameters.exponent() {
            RsaExponent::ZERO_EXPONENT => 65537,
            exp => exp.value(),
        };

        rsa::RsaPublicKey::new(
            BoxedUint::from_be_slice_vartime(unique.deref()),
            exponent.into(),
        )
        .context("unable to decode public key components from tpm")
        .map(VerifyingKey::new)
        .map_err(Into::into)
    }

    pub(super) fn quote(mut self, nonce: impl AsRef<[u8]>) -> anyhow::Result<(Attest, Signature)> {
        let key_handle = self.ak_handle()?;

        let pcr_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &Self::VTPM_DEFAULT_PCR_SLOTS)
            .with_size_of_select(PcrSelectSize::default())
            .build()
            .unwrap();

        let res = self
            .context
            .quote(
                key_handle,
                nonce.as_ref().try_into()?,
                SignatureScheme::Null,
                pcr_list,
            )
            .context("unable to request quote from tpm")?;

        Ok(res)
    }
}
