use libattest::error::Context;
use rsa::RsaPublicKey;
use tss_esapi::{
    abstraction::nv,
    handles::{KeyHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm, resource_handles::NvAuth, session_handles::AuthSession,
    },
    structures::{
        Attest, PcrSelectSize, PcrSelectionListBuilder, PcrSlot, Public, Signature, SignatureScheme,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
};
use x509_cert::der::Decode;

struct AzureTpm {
    context: tss_esapi::Context,
}

impl AzureTpm {
    fn new(context: tss_esapi::Context) -> Self {
        Self { context }
    }

    const AK_CERT_IDX: u32 = 0x01C101D0;
    const VTPM_HCL_AKPUB_PERSISTENT_HANDLE: u32 = 0x81000003;

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

    pub fn ak_cert(&mut self) -> anyhow::Result<x509_cert::Certificate> {
        let ak_cert = self
            .tpm_read(Self::AK_CERT_IDX)
            .context("unable to read ak_cert from tpm")?;

        let cert = x509_cert::Certificate::from_der(&ak_cert)
            .context("unable to decode certificate from DER")?;

        Ok(cert)
    }

    fn ak_handle(&mut self) -> Result<KeyHandle, tss_esapi::Error> {
        let handle = Self::VTPM_HCL_AKPUB_PERSISTENT_HANDLE.try_into()?;

        let public_key_handle = self
            .context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(handle))?
            .into();

        Ok(public_key_handle)
    }

    pub fn ak(&mut self) -> anyhow::Result<RsaPublicKey> {
        let public_key_handle = self.ak_handle()?;
        let (public, _, _) = self.context.read_public(public_key_handle)?;

        let Public::Rsa { parameters, .. } = public else {
            anyhow::bail!("received public key that was not rsa");
        };

        let pk = rsa::RsaPublicKey::new(
            u16::from(parameters.key_bits()).into(),
            parameters.exponent().value().into(),
        )
        .context("unable to decode public key components from tpm")?;

        Ok(pk)
    }

    pub fn quote(mut self, nonce: impl Into<Vec<u8>>) -> anyhow::Result<(Attest, Signature)> {
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
                nonce.into().try_into()?,
                SignatureScheme::Null,
                pcr_list,
            )
            .context("unable to request quote from tpm")?;

        Ok(res)
    }
}

fn main() {
    // ContextGap
    let mut context =
        tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default())).unwrap();

    context.set_sessions((Some(AuthSession::Password), None, None));

    let mut tpm = AzureTpm::new(context);

    let cert = tpm.ak_cert().unwrap();
    let key = tpm.ak().unwrap();

    let quote = tpm.quote([0u8; 32]).unwrap();
    println!("{cert:?} {key:?} {quote:?}");
}
