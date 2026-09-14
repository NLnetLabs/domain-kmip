use domain::{
    base::iana::SecurityAlgorithm, crypto::common::rsa_encode, rdata::Dnskey,
    utils::base16,
};
use kmip_protocol::{
    client::pool::{KmipConn, SyncConnPool},
    types::{
        common::{KeyFormatType, KeyMaterial, TransparentRSAPublicKey},
        response::ManagedObject,
    },
};
use tracing::{debug, error};

use crate::{
    algorithms::{
        ecdsa::parse_ecdsa_key_from_x509,
        rsa::{parse_rsa_from_pkcs1, parse_rsa_from_x509},
    },
    error::PublicKeyError,
    key_url::KeyUrl,
};

//------------ PublicKey -----------------------------------------------------

/// A public key retrieved from a KMIP server.
pub struct PublicKey {
    /// The DNSSEC algorithm for use with this public key.
    pub(crate) algorithm: SecurityAlgorithm,

    /// The public key octets.
    pub(crate) public_key: Vec<u8>,
}

impl PublicKey {
    pub fn new(algorithm: SecurityAlgorithm, public_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            public_key,
        }
    }

    /// Create a public key from a key stored on a KMIP server.
    ///
    /// The public key details will be retrieved from the KMIP server.
    ///
    /// The DNSSEC algorithm is needed in order for [`Self::dnskey()`] to
    /// generate a [`Dnskey`] and must match the cryptographic algorithm of
    /// the key stored on the KMIP server.
    ///
    /// Note: This function will block while awaiting the response from the
    /// KMIP server.
    ///
    /// If the KMIP operation fails an error or the response cannot be parsed
    /// an error will be returned.
    ///
    /// If the cryptographic algorithm of the retrieved key does not match
    /// the given DNSSEC algorithm an error will be returned.
    pub fn for_key_id_and_dnssec_algorithm(
        public_key_id: &str,
        algorithm: SecurityAlgorithm,
        conn_pool: SyncConnPool,
    ) -> Result<Self, PublicKeyError> {
        let client = conn_pool
            .get()
            .inspect_err(|err| error!("{err}"))
            .map_err(|err| {
                kmip_protocol::client::Error::ServerError(format!(
                    "Error while attempting to acquire KMIP connection from pool: {err}"
                ))
            })?;

        let res = Self::do_for_key_id_and_dnssec_algorithm(
            public_key_id,
            algorithm,
            &client,
        );

        if res.is_err() {
            debug!(
                "Last KMIP request:\n{}",
                client.last_req_diag_str().unwrap_or_default()
            );
            debug!(
                "Last KMIP response:\n{}",
                client.last_res_diag_str().unwrap_or_default()
            );
        }

        res
    }

    fn do_for_key_id_and_dnssec_algorithm(
        public_key_id: &str,
        algorithm: SecurityAlgorithm,
        client: &KmipConn,
    ) -> Result<Self, PublicKeyError> {
        // https://datatracker.ietf.org/doc/html/rfc5702#section-2
        // Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource
        // Records for DNSSEC
        //
        // 2.  DNSKEY Resource Records
        //   "The format of the DNSKEY RR can be found in [RFC4034]. [RFC3110]
        //   describes the use of RSA/SHA-1 for DNSSEC signatures."
        //                          |
        //                          |
        //                          v
        // https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.4
        // Resource Records for the DNS Security Extensions
        // 2.  The DNSKEY Resource Record
        // 2.1.4.  The Public Key Field
        //   "The Public Key Field holds the public key material.  The
        //    format depends on the algorithm of the key being stored and is
        //    described in separate documents."
        //                          |
        //                          |
        //                          v
        // https://datatracker.ietf.org/doc/html/rfc3110#section-2
        // RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)
        // 2. RSA Public KEY Resource Records
        //   "... The structure of the algorithm specific portion of the RDATA
        //    part of such RRs is as shown below.
        //
        //    Field             Size
        //    -----             ----
        //    exponent length   1 or 3 octets (see text)
        //    exponent          as specified by length field
        //    modulus           remaining space
        //
        // For interoperability, the exponent and modulus are each limited to
        // 4096 bits in length.  The public key exponent is a variable length
        // unsigned integer.  Its length in octets is represented as one octet
        // if it is in the range of 1 to 255 and by a zero octet followed by
        // a two octet unsigned length if it is longer than 255 bytes.  The
        // public key modulus field is a multiprecision unsigned integer.  The
        // length of the modulus can be determined from the RDLENGTH and the
        // preceding RDATA fields including the exponent.  Leading zero octets
        // are prohibited in the exponent and modulus.

        // Note: OpenDNSSEC queries the public key ID, _unless_ it was
        // configured not the public key in the HSM (by setting CKA_TOKEN
        // false) in which case there is no public key and so it uses the
        // private key object handle instead.
        let res = client
            .get_key(public_key_id)
            .inspect_err(|err| error!("{err}"))?;
        let ManagedObject::PublicKey(public_key) = res.cryptographic_object
        else {
            return Err(kmip_protocol::client::Error::DeserializeError(
                format!(
                    "Fetched KMIP object was expected to be a PublicKey but was instead: {}",
                    res.cryptographic_object
                ),
            ))?;
        };

        // https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027125
        //   "“Raw” key format is intended to be applied to symmetric keys
        //    and not asymmetric keys"
        //
        // As we deal in asymmetric keys (RSA, ECDSA), not symmetric keys,
        // we should not encounter public_key.key_block.key_format_type
        // == KeyFormatType::Raw. However, Fortanix DSM returns
        // KeyFormatType::Raw when fetching key data for an ECDSA public key.

        match public_key.key_block.key_value.key_material {
            KeyMaterial::Bytes(bytes) => {
                debug!(
                    "Cryptographic Algorithm: {:?}",
                    public_key.key_block.cryptographic_algorithm
                );
                debug!(
                    "Cryptographic Length: {:?}",
                    public_key.key_block.cryptographic_length
                );
                debug!(
                    "Key Format Type: {:?}",
                    public_key.key_block.key_format_type
                );
                debug!(
                    "Key Compression Type: {:?}",
                    public_key.key_block.key_compression_type
                );
                debug!("Key bytes as hex: {}", base16::encode_display(&bytes));

                match (algorithm, public_key.key_block.key_format_type) {
                    (
                        SecurityAlgorithm::RSASHA1
                        | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
                        | SecurityAlgorithm::RSASHA256
                        | SecurityAlgorithm::RSASHA512,
                        KeyFormatType::PKCS1,
                    ) => parse_rsa_from_pkcs1(algorithm, &bytes),

                    (
                        SecurityAlgorithm::RSASHA1
                        | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
                        | SecurityAlgorithm::RSASHA256
                        | SecurityAlgorithm::RSASHA512,
                        KeyFormatType::Raw,
                    ) => parse_rsa_from_x509(algorithm, &bytes),

                    (
                        SecurityAlgorithm::RSASHA1
                        | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
                        | SecurityAlgorithm::RSASHA256
                        | SecurityAlgorithm::RSASHA512,
                        KeyFormatType::X509,
                    ) => parse_rsa_from_x509(algorithm, &bytes),

                    // Both Securosys and Fortanix DSM return a DER-encoded
                    // ASN.1 X.509 object but Fortanix sets Key Format Type to
                    // Raw while the Securosys sets it to X.509.
                    (
                        SecurityAlgorithm::ECDSAP256SHA256,
                        KeyFormatType::Raw | KeyFormatType::X509,
                    ) => parse_ecdsa_key_from_x509(algorithm, &bytes),

                    (
                        SecurityAlgorithm::ECDSAP384SHA384,
                        KeyFormatType::Raw | KeyFormatType::X509,
                    ) => parse_ecdsa_key_from_x509(algorithm, &bytes),

                    (expected, key_format_type) => {
                        let alg = public_key
                            .key_block
                            .cryptographic_algorithm
                            .map(|a| a.to_string())
                            .unwrap_or("unknown algorithm".to_string());
                        let len = public_key
                            .key_block
                            .cryptographic_length
                            .map(|l| l.to_string())
                            .unwrap_or("unknown length".to_string());
                        let actual =
                            format!("{alg} ({len}) as {key_format_type}");
                        Err(PublicKeyError::AlgorithmMismatch {
                            expected,
                            actual,
                        })
                    }
                }
            }

            KeyMaterial::TransparentRSAPublicKey(
                // cascade-hsm-bridge
                TransparentRSAPublicKey {
                    modulus,
                    public_exponent,
                },
            ) => Ok(Self {
                algorithm,
                public_key: rsa_encode(&public_exponent, &modulus),
            }),

            mat => Err(kmip_protocol::client::Error::DeserializeError(format!(
                "Fetched KMIP object has unsupported key material type: {mat}"
            ))
            .into()),
        }
    }

    /// Create a public key from a key stored on a KMIP server.
    ///
    /// This is a thin wrapper around
    /// [`Self::for_key_id_and_dnssec_algorithm`].
    pub fn for_key_url(
        public_key_url: KeyUrl,
        conn_pool: SyncConnPool,
    ) -> Result<Self, PublicKeyError> {
        Self::for_key_id_and_dnssec_algorithm(
            public_key_url.key_id(),
            public_key_url.algorithm(),
            conn_pool,
        )
    }

    /// The DNSSEC algorithm of the key.
    pub fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    /// Generate a DNSKEY RR or this public key.
    pub fn dnskey(&self, flags: u16) -> Dnskey<Vec<u8>> {
        // SAFETY: The key came from a KMIP server and was validated to have
        // the expected length when the KMIP server response was parsed by
        // fetch_public_key().
        Dnskey::new(flags, 3, self.algorithm, self.public_key.clone()).unwrap()
    }
}
