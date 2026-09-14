pub mod ecdsa;
pub mod rsa;

use domain::{
    base::iana::SecurityAlgorithm,
    crypto::sign::{SignError, Signature},
};
use kmip_protocol::types::common::{
    CryptographicAlgorithm, HashingAlgorithm, PaddingMethod, RecommendedCurve,
};

use crate::oids::*;
use ecdsa::parse_ecdsa_sig_from_x962;

#[derive(Copy, Clone)]
pub struct EllipticCurveInfo {
    pub oid: &'static OidInfo,
    pub kmip_name: &'static str, // See https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027131
    pub alt_name: &'static str,
    pub kmip_recommend_curve: RecommendedCurve,
}

#[derive(Copy, Clone)]
pub struct AlgorithmInfo {
    pub oid: &'static OidInfo,
    pub len_range: Option<(u32, u32)>, // We don't use RangeExclusive because it doesn't implement Copy
    pub kmip_crypto_alg: CryptographicAlgorithm,
    pub kmip_hash_alg: HashingAlgorithm,
    pub kmip_padding_method: Option<PaddingMethod>,
    pub kmip_crypto_fixed_len: Option<u32>,
    pub elliptic_curve: Option<EllipticCurveInfo>,
    pub sig_parser: fn(Vec<u8>) -> Result<Signature, SignError>,
}

// const ALG_RSASHA1: AlgorithmInfo = AlgorithmInfo {
//     oid: &RSA_OID,
//     len_range: Some((512, 4096)), // RFC 3110 section 3
//     kmip_crypto_alg: CryptographicAlgorithm::RSA,
//     kmip_hash_alg: HashingAlgorithm::SHA1,
//     kmip_padding_method: Some(PaddingMethod::PKCS1_v1_5),
//     kmip_dsa: Some(DigitalSignatureAlgorithm::SHA1WithRSAEncryption_PKCS1_v1_5),
//     kmip_crypto_fixed_len: None,
//     elliptic_curve: None,
//     sig_parser: |sig| Ok(Signature::RsaSha1(sig.into_boxed_slice())),
// };

pub const ALG_RSASHA256: AlgorithmInfo = AlgorithmInfo {
    oid: &RSA_OID,
    len_range: Some((512, 4096)), // RFC 5702 section 2.1
    kmip_crypto_alg: CryptographicAlgorithm::RSA,
    kmip_hash_alg: HashingAlgorithm::SHA256,
    kmip_padding_method: Some(PaddingMethod::PKCS1_v1_5),
    kmip_crypto_fixed_len: None,
    elliptic_curve: None,
    sig_parser: |sig| Ok(Signature::RsaSha256(sig.into_boxed_slice())),
};

pub const ALG_RSASHA512: AlgorithmInfo = AlgorithmInfo {
    oid: &RSA_OID,
    len_range: Some((1024, 4096)), // RFC 5702 section 2.2
    kmip_crypto_alg: CryptographicAlgorithm::RSA,
    kmip_hash_alg: HashingAlgorithm::SHA512,
    kmip_padding_method: Some(PaddingMethod::PKCS1_v1_5),
    kmip_crypto_fixed_len: None,
    elliptic_curve: None,
    sig_parser: |sig| Ok(Signature::RsaSha512(sig.into_boxed_slice())),
};

pub const ALG_ECDSAP256SHA256: AlgorithmInfo = AlgorithmInfo {
    oid: &EC_OID,
    len_range: None,
    kmip_crypto_alg: CryptographicAlgorithm::ECDSA,
    kmip_hash_alg: HashingAlgorithm::SHA256,
    kmip_padding_method: None,
    kmip_crypto_fixed_len: Some(256),
    elliptic_curve: Some(EllipticCurveInfo {
        oid: &SECP256R1_OID,
        kmip_name: "P-256",
        alt_name: "SECP256R1",
        kmip_recommend_curve: RecommendedCurve::P_256,
    }),
    sig_parser: |sig| {
        Ok(Signature::EcdsaP256Sha256(parse_ecdsa_sig_from_x962(&sig)?))
    },
};

pub const ALG_ECDSAP384SHA384: AlgorithmInfo = AlgorithmInfo {
    oid: &EC_OID,
    len_range: None,
    kmip_crypto_alg: CryptographicAlgorithm::ECDSA,
    kmip_hash_alg: HashingAlgorithm::SHA384,
    kmip_padding_method: None,
    kmip_crypto_fixed_len: Some(384),
    elliptic_curve: Some(EllipticCurveInfo {
        oid: &SECP384R1_OID,
        kmip_name: "P-384",
        alt_name: "SECP384R1",
        kmip_recommend_curve: RecommendedCurve::P_384,
    }),
    sig_parser: |sig| {
        Ok(Signature::EcdsaP384Sha384(parse_ecdsa_sig_from_x962(&sig)?))
    },
};

// const ALG_ED25519: AlgorithmInfo = AlgorithmInfo {
//     oid: &ED25519_OID,
//     len_range: None,
//     kmip_crypto_alg: CryptographicAlgorithm::Ed25519,
//     kmip_hash_alg: HashingAlgorithm::SHA512,
//     kmip_padding_method: None,
//     kmip_crypto_fixed_len: None,
//     elliptic_curve: None,
//     sig_parser: |_sig| Err(SignError),
// };

const ALG_MAPPINGS: [(SecurityAlgorithm, &AlgorithmInfo); 4] = [
    // (SecurityAlgorithm::RSASHA1, &ALG_RSASHA1),
    // (SecurityAlgorithm::RSASHA1_NSEC3_SHA1, &ALG_RSASHA1),
    (SecurityAlgorithm::RSASHA256, &ALG_RSASHA256),
    (SecurityAlgorithm::RSASHA512, &ALG_RSASHA512),
    (SecurityAlgorithm::ECDSAP256SHA256, &ALG_ECDSAP256SHA256),
    (SecurityAlgorithm::ECDSAP384SHA384, &ALG_ECDSAP384SHA384),
    // (SecurityAlgorithm::ED25519, &ALG_ED25519),
];

pub fn get_alg_info(alg: SecurityAlgorithm) -> Option<&'static AlgorithmInfo> {
    ALG_MAPPINGS
        .iter()
        .find(|item| item.0 == alg)
        .map(|item| item.1)
}
