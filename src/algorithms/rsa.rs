use bcder::{BitString, Oid};
use domain::base::iana::SecurityAlgorithm;

use crate::{error::PublicKeyError, oids::RSA_OID, public_key::PublicKey};

/// Parse an RSA key encoded in the KMIP "X.509" format convention.
///
/// # Panics
///
/// Panics if the specified DNS security algorithm for the key does not use
/// RSA.
pub fn parse_rsa_from_x509(
    algorithm: SecurityAlgorithm,
    bytes: &[u8],
) -> Result<PublicKey, PublicKeyError> {
    // Ensure the specified algorithm uses RSA.
    assert!(matches!(
        algorithm,
        SecurityAlgorithm::RSASHA1
            | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
            | SecurityAlgorithm::RSASHA256
            | SecurityAlgorithm::RSASHA512
    ));

    // For an RSA key Fortanix DSM supplies: (from https://asn1js.eu/)
    //   SubjectPublicKeyInfo SEQUENCE (2 elem)
    //     algorithm AlgorithmIdentifier SEQUENCE (2 elem)
    //       algorithm OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
    //       parameter ANY NULL
    //     subjectPublicKey BIT STRING (2160 bit) 001100001000001000000001000010100000001010000010000000010000000100000…
    //       SEQUENCE (2 elem)
    //         INTEGER (2048 bit) 229677698057230630160769379936346719377896297586216888467726484346678…
    //         INTEGER 65537

    // TODO: Decode this manually, to avoid the 'bcder' dependency?
    let (modulus, public_exponent) =
            bcder::Mode::Der
                .decode(bytes, |cons| {
                    cons.take_sequence(|cons| {
                        cons.take_sequence(|cons| {
                            let algorithm = Oid::take_from(cons)?;
                            if algorithm != RSA_OID.bytes {
                                return Err(cons.content_err(
                                    format!("Expected ASN.1 SubjectPublicKeyInfo with algorithm OID '{}' (id: {}, bytes: {:?}) but found: {:?}",
                                        RSA_OID.dot_name, RSA_OID.asn1_object_identifier, RSA_OID.bytes, algorithm)
                                ));
                            }
                            cons.take_null()
                        })?;
                        let bit_string = BitString::take_from(cons)?;
                        bcder::Mode::Der.decode(bit_string.octet_slice().unwrap(), |cons| {
                            cons.take_sequence(|cons| {
                                let modulus = bcder::Unsigned::take_from(cons)?;
                                let public_exponent = bcder::Unsigned::take_from(cons)?;
                                Ok((modulus, public_exponent))
                            })
                        })
                    })
                })
                .map_err(|err| {
                    kmip_protocol::client::Error::DeserializeError(format!(
                        "Unable to parse raw RSASHA256 SubjectPublicKeyInfo: {err}"
                    ))
                })?;

    let public_key = domain::crypto::common::rsa_encode(
        public_exponent.as_slice(),
        modulus.as_slice(),
    );

    Ok(PublicKey {
        algorithm,
        public_key,
    })
}
/// Parse an RSA key encoded in the PKCS#1 format.
///
/// # Panics
///
/// Panics if the specified DNS security algorithm for the key does not use
/// RSA.
pub fn parse_rsa_from_pkcs1(
    algorithm: SecurityAlgorithm,
    bytes: &[u8],
) -> Result<PublicKey, PublicKeyError> {
    // Ensure the specified algorithm uses RSA.
    assert!(matches!(
        algorithm,
        SecurityAlgorithm::RSASHA1
            | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
            | SecurityAlgorithm::RSASHA256
            | SecurityAlgorithm::RSASHA512
    ));

    // PyKMIP outputs PKCS#1 ASN.1 DER encoded RSA public key data like so:
    //   RSAPublicKey::=SEQUENCE{
    //     modulus INTEGER, -- n
    //     publicExponent INTEGER -- e }

    // TODO: Decode this manually, to avoid the 'bcder' dependency?
    let (modulus, public_exponent) = bcder::Mode::Der
        .decode(bytes, |cons| {
            cons.take_sequence(|cons| {
                let modulus = bcder::Unsigned::take_from(cons)?;
                let public_exponent = bcder::Unsigned::take_from(cons)?;
                Ok((modulus, public_exponent))
            })
        })
        .map_err(|err| {
            kmip_protocol::client::Error::DeserializeError(format!(
                "Unable to parse DER encoded PKCS#1 RSAPublicKey: {err}"
            ))
        })?;

    let public_key = domain::crypto::common::rsa_encode(
        public_exponent.as_slice(),
        modulus.as_slice(),
    );

    Ok(PublicKey {
        algorithm,
        public_key,
    })
}
