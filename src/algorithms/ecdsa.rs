use bcder::{BitString, Oid};
use domain::{
    base::iana::SecurityAlgorithm, crypto::sign::SignError, utils::base16,
};
use tracing::error;

use crate::{
    algorithms::get_alg_info, error::PublicKeyError, public_key::PublicKey,
};

/// Parse an ECDSA signature from the X9.62 ASN.1 DER format.
pub fn parse_ecdsa_sig_from_x962<const LEN: usize>(
    bytes: &[u8],
) -> Result<Box<[u8; LEN]>, SignError> {
    // ECDSA signature received from Fortanix DSM, decoded
    // using this command:
    //
    //   $ echo '<hex encoded signature data>' | xxd -r -p | dumpasn1 -
    //     0  69: SEQUENCE {
    //     2  33:   INTEGER
    //          :     00 C6 A7 D1 2E A1 0C B4 96 BD D9 A5 48 2C 9B F4
    //          :     0C EC 9F FC EF 1A 0D 59 BB B9 24 F3 FE DA DC F8
    //          :     9E
    //    37  32:   INTEGER
    //          :     4B A7 22 69 F2 F8 65 88 63 D0 25 D3 A9 D5 92 4F
    //          :     A2 21 BD 59 CD 27 60 6D 16 C3 79 EF B4 0A CA 33
    //          :   }
    //
    // Where the two integer values are known as 'r' and 's'.
    let (r, s) = bcder::Mode::Der
        .decode(bytes, |cons| {
            cons.take_sequence(|cons| {
                let r = bcder::Unsigned::take_from(cons)?;
                let s = bcder::Unsigned::take_from(cons)?;
                Ok((r, s))
            })
        })
        .map_err(|err| {
            error!("Unable to parse DER encoded X9.62 ASN.1 signature: {err}");
            SignError
        })?;
    let (mut r, mut s) = (r.as_slice(), s.as_slice());

    let mut signature = Box::new([0u8; LEN]);
    let half_len = signature.len() >> 1;

    // In DER, there can be at most one leading zero byte,
    // because the high bit might be set and that would
    // otherwise indicate a negative integer.  Strip it.
    for x in [&mut r, &mut s] {
        *x = match *x {
            [0, 0x80..=0xFF, ..] => &x[1..],
            // Badly formatted signature.
            [0, _, ..] => {
                error!("Leading zeros in ECDSA signature integer");
                return Err(SignError);
            }
            x => x,
        };

        if x.len() > half_len {
            error!(
                "Overly long ECDSA signature integer: {} > {}",
                x.len(),
                half_len
            );
            return Err(SignError);
        }
    }

    signature[half_len - r.len()..half_len].copy_from_slice(r);
    signature[LEN - s.len()..LEN].copy_from_slice(s);
    Ok(signature)
}

/// Parse an ECDSA key encoded in the KMIP "raw" format convention.
///
/// # Panics
///
/// Panics if the specified DNS security algorithm for the key does not use
/// ECDSA.
pub fn parse_ecdsa_key_from_x509(
    dns_algorithm: SecurityAlgorithm,
    bytes: &[u8],
) -> Result<PublicKey, PublicKeyError> {
    // Ensure the specified algorithm uses ECDSA.
    // TODO: Support ECDSAP384SHA384.
    assert!(matches!(
        dns_algorithm,
        SecurityAlgorithm::ECDSAP256SHA256 | SecurityAlgorithm::ECDSAP384SHA384
    ));
    let alg_info = get_alg_info(dns_algorithm).ok_or_else(|| {
        kmip_protocol::client::Error::DeserializeError(
            format!("Unable to parse SubjectPublicKeyInfo for DNSSEC algorithm {dns_algorithm}: unsupported")
        )
    })?;
    let curve = alg_info.elliptic_curve.unwrap();
    let value_byte_len = alg_info.kmip_crypto_fixed_len.unwrap() / 8;

    // For an ECDSA key Fortanix DSM supplies: (from https://asn1js.eu/)
    //   SubjectPublicKeyInfo SEQUENCE @0+89 (constructed): (2 elem)
    //     algorithm AlgorithmIdentifier SEQUENCE @2+19 (constructed): (2 elem)
    //       algorithm OBJECT_IDENTIFIER @4+7: 1.2.840.10045.2.1|ecPublicKey|ANSI X9.62 public key type
    //       parameters ANY OBJECT_IDENTIFIER @13+8: 1.2.840.10045.3.1.7|prime256v1|ANSI X9.62 named elliptic curve
    //     subjectPublicKey BIT_STRING @23+66: (520 bit)
    //
    // From: https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1
    //   The parameter for id-ecPublicKey is as follows and MUST always be
    //   present:
    //
    //     ECParameters ::= CHOICE {
    //       namedCurve         OBJECT IDENTIFIER
    //       -- implicitCurve   NULL
    //       -- specifiedCurve  SpecifiedECDomain
    //     }
    //       -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
    //       -- Details for SpecifiedECDomain can be found in [X9.62].
    //       -- Any future additions to this CHOICE should be coordinated
    //       -- with ANSI X9.
    //
    let bits = bcder::Mode::Der
        .decode(bytes, |cons| {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    let algorithm = Oid::take_from(cons)?;
                    if algorithm != alg_info.oid.bytes {
                        return Err(cons.content_err(
                            format!("Expected ASN.1 SubjectPublicKeyInfo with algorithm OID '{}' (id: {}, bytes: {:?}) but found: {:?}",
                                alg_info.oid.dot_name, alg_info.oid.asn1_object_identifier, alg_info.oid.bytes, algorithm)
                        ));
                    }
                    let named_curve = Oid::take_from(cons)?;
                    if named_curve != curve.oid.bytes {
                       return Err(cons.content_err(
                           format!("Expected ASN.1 SubjectPublicKeyInfo with named curve OID '{}' (id: {}, bytes: {:?}, KMIP name: {}, alt name: {}) but found: {}",
                           curve.oid.dot_name, curve.oid.asn1_object_identifier, curve.oid.bytes, curve.kmip_name, curve.alt_name, named_curve)
                       ));
                    }
                    Ok(())
                })?;
                let bits = BitString::take_from(cons)?;
                Ok(bits)
            })
        }).map_err(|err| {
            kmip_protocol::client::Error::DeserializeError(
                format!("Unable to parse SubjectPublicKeyInfo as {}: {err}", alg_info.oid.asn1_object_identifier)
            )
        })?;

    // compression flag byte, X value, Y value
    let num_expected_bytes = 1 + value_byte_len + value_byte_len;

    // https://www.rfc-editor.org/rfc/rfc5480#section-2.2
    //   "The subjectPublicKey from SubjectPublicKeyInfo
    //    is the ECC public key. ECC public keys have the
    //    following syntax:
    //
    //        ECPoint ::= OCTET STRING
    //    ...
    //    The first octet of the OCTET STRING indicates
    //    whether the key is compressed or uncompressed.
    //    The uncompressed form is indicated by 0x04 and
    //    the compressed form is indicated by either 0x02
    //    or 0x03 (see 2.3.3 in [SEC1]).  The public key
    //    MUST be rejected if any other value is included
    //    in the first octet."
    let Some(octets) = bits.octet_slice() else {
        return Err(kmip_protocol::client::Error::DeserializeError(format!(
            "Unable to parse SubjectPublicKeyInfo {} (aka {}) curve bit string: missing octets",
            curve.kmip_name, curve.alt_name
        )))?;
    };

    // Note: OpenDNSSEC doesn't support the compressed
    // form either.
    let compression_flag = octets[0];
    if compression_flag != 0x04 {
        Err(kmip_protocol::client::Error::DeserializeError(format!(
            "Unable to parse SubjectPublicKeyInfo {} (aka {}) curve bit string: unknown compression flag {compression_flag:?}",
            curve.kmip_name, curve.alt_name
        )))?
    }

    if octets.len() != num_expected_bytes as usize {
        Err(kmip_protocol::client::Error::DeserializeError(format!(
            "Unable to parse SubjectPublicKeyInfo {} (aka {}) curve bit string: expected [<compression flag byte>, <{value_byte_len}-byte X value>, <{value_byte_len}-byte Y value>]i but found: {} ({} bytes)",
            curve.kmip_name,
            curve.alt_name,
            base16::encode_display(octets),
            octets.len()
        )))?
    }

    // Expect octet string to be X | Y (| denotes
    // concatenation) where X and Y are each 32 bytes
    // (because P-256 uses 256 bit values and 256 bits are
    // 32 bytes). Skip the compression flag.
    let public_key = octets[1..].to_vec();

    Ok(PublicKey {
        algorithm: dns_algorithm,
        public_key,
    })
}
