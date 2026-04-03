use libattest::error::{AttestationError, Context};
use sev::firmware::host::TcbVersion;
use std::collections::HashMap;
use x509_parser::{der_parser::asn1_rs, prelude::X509Certificate};

// https://letsencrypt.org/it/docs/a-warm-welcome-to-asn1-and-der/

pub static EXT_KEY_USAGE: asn1_rs::Oid = asn1_rs::oid!(2.5.29.37);

pub mod tcg {
    use super::*;

    pub const KP_AIKCERTIFICATE: asn1_rs::Oid = asn1_rs::oid!(2.23.133.8.3);

    pub fn is_aik_certificate(ext_key_usage: &x509_parser::extensions::ExtendedKeyUsage) -> bool {
        ext_key_usage
            .other
            .iter()
            .any(|usage| usage == &KP_AIKCERTIFICATE)
    }
}

#[allow(dead_code)]
pub static STRUCT_VERSION: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.1);

/**
 * includes the specific silicon stepping corresponding to the supplied hwID

 * Milan-B0
 * Genoa-A0
*/
pub static PRODUCT_NAME: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.2);

// Security Patch Level
pub static BOOTLOADER: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.3.1);
pub static TEE: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.3.2);
pub static SNP: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.3.3);
pub static UCODE: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.3.8);
pub static FMC: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.3.9);
pub static HWID: asn1_rs::Oid = asn1_rs::oid!(1.3.6.1.4.1.3704.1.4);

// oid values are TLV formatted
pub fn check_cert_ext_byte(
    ext: &x509_parser::extensions::X509Extension,
    value: u8,
) -> libattest::Result<std::cmp::Ordering> {
    /*
    if ext.value.len() > 3 {
        return Err(anyhow!("invalid OID values."));
    }
    */

    if ext.value.first() != Some(&0x02) {
        return AttestationError::internal("invalid OID");
    }

    let Some(_) = ext.value.get(1) else {
        return AttestationError::internal("invalid OID length");
    };

    if let Some(byte_value) = ext.value.last() {
        // equal if local vcek VS attestation report
        // can be major if AMD KDS vcek VS attestation report
        //
        // ext needs to be up-to-date with AMD KDS SPL

        return Ok(value.cmp(byte_value));
    }

    AttestationError::internal("invalid oid data")
}

pub fn check_spl_byte_ver(
    ext: &x509_parser::extensions::X509Extension,
    value: u8,
) -> libattest::Result<bool> {
    Ok(check_cert_ext_byte(ext, value)?.is_ge())
}

pub fn compare_bytes(ext: &x509_parser::extensions::X509Extension, val: &[u8]) -> bool {
    ext.value.to_vec() == val
}

pub fn check_spl(
    tcb: TcbVersion,
    exts: &std::collections::HashMap<asn1_rs::Oid, &x509_parser::extensions::X509Extension>,
) -> libattest::Result<bool> {
    if !check_spl_byte_ver(
        exts.get(&BOOTLOADER)
            .context("missing BOOTLOADER version")?,
        tcb.bootloader,
    )
    .context("invalid bootloader version")?
    {
        return AttestationError::internal("invalid bootloader spl value");
    }

    if !check_spl_byte_ver(exts.get(&TEE).context("missing TEE version")?, tcb.tee)
        .context("invalid TEE version")?
    {
        return AttestationError::internal("invalid TEE spl value");
    }

    if !check_spl_byte_ver(exts.get(&SNP).context("missing SNP version")?, tcb.snp)
        .context("invalid SNP version")?
    {
        return AttestationError::internal("invalid SNP version spl value");
    }

    if !check_spl_byte_ver(
        exts.get(&UCODE).context("missing uCODE version")?,
        tcb.microcode,
    )
    .context("invalid uCODE version")?
    {
        return AttestationError::internal("invalid ucode version spl value");
    }

    // todo: add FMC for TURIN and beyond
    // check struct version is 1 || panic
    // TODO: add cmp order to check_cert_ext_byte

    if check_cert_ext_byte(
        exts.get(&STRUCT_VERSION)
            .context("missing struct version value")?,
        0x1,
    )?
    .is_le()
        && !check_spl_byte_ver(
            exts.get(&FMC).context("missing FMC version")?,
            tcb.fmc.context("could not get fmc from tbc")?,
        )
        .context("invalid FMC version")?
    {
        return AttestationError::internal("invalid FMC version spl value");
    }

    Ok(true)
}

// pub fn get_exts_A<'a>(
//     vek: &openssl::x509::X509,
// ) -> anyhow::Result<HashMap<asn1_rs::Oid<'a>, x509_parser::extensions::X509Extension<'a>>> {
//     let der = vek.to_der()?;
//     let (_, vek_x509) = x509_parser::certificate::X509Certificate::from_der(&der)?;

//     let mut map = std::collections::HashMap::new();
//     for ext in vek_x509.extensions() {
//         // SAFETY: The lifetime is tied to the struct's lifetime, which owns the buffer
//         let oid_static: asn1_rs::Oid<'a> = unsafe { std::mem::transmute(ext.oid.clone()) };
//         let ext_static: x509_parser::extensions::X509Extension<'a> =
//             unsafe { std::mem::transmute(ext.clone()) };
//         map.insert(oid_static, ext_static);
//     }

//     Ok(map)
// }

pub fn get_exts<'a>(
    vek: &'a X509Certificate,
) -> libattest::Result<HashMap<asn1_rs::Oid<'a>, &'a x509_parser::extensions::X509Extension<'a>>> {
    vek.extensions_map().map_err(Into::into)
}

pub fn get_key_usage<'a>(
    exts: &'a std::collections::HashMap<asn1_rs::Oid, x509_parser::extensions::X509Extension>,
) -> libattest::Result<&'a x509_parser::extensions::ExtendedKeyUsage<'a>> {
    let Some(key_usage) = exts.get(&EXT_KEY_USAGE) else {
        // return Err(anyhow!("missing Extended Key Usage"));
        return AttestationError::internal("missing Extended key usage");
    };
    let x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(parsed_key_usage) =
        key_usage.parsed_extension()
    else {
        // return Err(anyhow!("invalid ExtendedKeyUsage Extension"));
        return AttestationError::internal("invalid Extended key usage extension");
    };

    Ok(parsed_key_usage)
}
