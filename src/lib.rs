//! KMIP HSM signing support for [`domain`].
//!
//! An implementation of a [`domain::crypto::sign`] compatible backend for
//! DNSSEC signing using an OASIS KMIP compliant HSM backend.
//!
//! This backend aims to support the same subset of DNSSEC signing algorithms
//! as [`domain::crypto::sign::SecretKeyBytes`] can represent which at the
//! time of writing are:
//!
//!   -  8: RSA/SHA-256
//!   - 10: RSA/SHA-512
//!   - 13: ECDSA Curve P-256 with SHA-256
//!   - 14: ECDSA Curve P-384 with SHA-384
//!   - 15: Ed25519 - Coming soon
//!   - 16: Ed448 - Coming soon
//!
//! Unlike [`domain::crypto::sign::SecretKeyBytes`] this crate has no type
//! for secret key material as the secret key should be generated, owned by
//! and not normally leave the HSM (except perhaps for HSM <-> HSM syncing
//! operations or for migration from one HSM to another).
//!
//! <div class="warning">Working with Ed25519 and Ed448 keys requires an
//! HSM that supports v2.x or higher of the OASIS KMIP specification.</div>
//!
//! # Creating a connection pool
//!
//! Connections to the KMIP HSM are made using [`SyncConnPool`]. Some high
//! level operations actually require multiple exchanges with the KMIP HSM
//! and by using a connection pool we do not have to deal with expired
//! sessions or closed connections, such situations are handled transparently
//! by the connection pool.
//!
//! # Importing keys
//!
//! A [`KeyPair`] type for using a public-private key pair stored in a KMIP
//! HSM can be constructed using an HSM connection and the appropriate key
//! identifiers.
//!
//! ```ignore
//! # use crate::key_pair::KeyPair;
//! # use domain::base::iana::SecurityAlgorithm;
//! // Construct a KeyPaiar that represents an HSM stored ECDSAP256SHA256 key
//! // pair with public id  'aaa' and private id 'bbb'. As the HSM is not
//! // DNSSEC aware we must supply the DNSKEY flags (257 in this case) to
//! // associate with the key pair, that information is not stored in the HSM.
//! let key_pair = KeyPair::from_metadata(
//!     SecurityAlgorithm::ECDSAP256SHA256,
//!     257,
//!     "aaa",
//!     "bbb",
//!     hsm_conn_pool).unwrap();
//!
//! // Check that the algorithm and key tag match expectations.
//! assert_eq!(key_pair.algorithm(), SecurityAlgorithm::ECDSAP256SHA256);
//! assert_eq!(key_pair.dnskey().key_tag(), 56037);
//! ```
//!
//! # Generating keys
//!
//! Keys can also be generated.
//!
//! ```ignore
//! # use domain::crypto::sign::GenerateParams;
//! # use crate::generate;
//! // Generate a new ECDSAP256SHA256 key.
//! let params = GenerateParams::EcdsaP256Sha256;
//! let key_pair = generate(&params, 257).unwrap();
//! ```
//!
//! # Signing data
//!
//! Given some data and a key, the data can be signed with the key.
//!
//! ```ignore
//! let sig = key_pair.sign_raw(b"Hello, World!").unwrap();
//! println!("{:?}", sig);
//! ```
//!
//! # Additional operations
//!
//! In addition to the operations supported by [`domain::crypto::sign`], KMIP
//! keys support some additional operations. See [`KeyPair`] for more
//! information.
//!
mod algorithms;
mod oids;

#[cfg(test)]
mod tests;

/// Dependency re-exports
pub mod dep {
    pub use domain;
    pub use kmip_protocol;
}

pub mod error;
pub mod key_pair;
pub mod key_url;
pub mod public_key;

use domain::crypto::sign::GenerateParams;
use kmip_protocol::client::{Error, pool::SyncConnPool};
use kmip_protocol::types::common::{
    AttributeIndex, AttributeName, CryptographicDomainParameters,
    CryptographicUsageMask,
};
use kmip_protocol::types::request::{
    Attribute, CommonTemplateAttribute, PrivateKeyTemplateAttribute,
    PublicKeyTemplateAttribute, RequestPayload,
};
use kmip_protocol::types::response::{
    CreateKeyPairResponsePayload, ResponsePayload,
};
use tracing::{debug, error, trace};

use crate::algorithms::*;
use crate::error::{DestroyError, GenerateError};
use crate::key_pair::KeyPair;

//----------- generate() -------------------------------------------------

/// Generate a new key pair for a given algorithm using a specified HSM.
pub fn generate(
    public_key_name: String,
    private_key_name: String,
    params: GenerateParams,
    flags: u16,
    conn_pool: SyncConnPool,
) -> Result<KeyPair, GenerateError> {
    let algorithm = params.algorithm();

    // Note: Strictly speaking KMIP requires that each key, including
    // public and private "halves" of the same key "pair", have a unique
    // name within the HSM namespace. We don't enforce that here, e.g.
    // maybe you know that your backend is actually a KMIP to PKCS#11
    // gateway and PKCS#11 doesn't have the same restriction and you
    // want keys to be named as you are used to with your PKCS#11 HSM. We
    // also don't intefere with names by making them unique as that would
    // change any max name length calculations performed by the caller
    // to avoid known issues with backend name limitations for their
    // particular HSM (the PKCS#11 and KMIP specifications are silent on
    // name limits but implementations definitely have limits, and not all
    // the same).

    // Note: We do NOT set the ActivationDate attribute because at
    // least one HSM KMIP implementation (PyKMIP) doesn't support it, and
    // another (Fortanix DSM) requires the date to be in the
    // future, setting the timestamp to now in order to activate the key
    // immediately will not work as the HSM returns an error in that case.
    // We could add a small offset to the timestamp but then the offset
    // could be too small and the error will occur, or the offset could
    // be too large and subsequent attempts to sign with the key would
    // fail because the key is not yet active. Instead we just perform a
    // separate activation step after creating the key pair.

    // Note: Neither PyKMIP nor Fortanix DSM support KMIP "Cryptographic
    // Parameters" so we do not attempt to supply it.

    let mut common_attrs = vec![];
    let priv_key_attrs = vec![
        // Note: Fortanix DSM requires a name for at least the private
        // key.
        // Note: Securoys seems to be ignoring the given name.
        Attribute::Name(private_key_name),
        Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
    ];
    let pub_key_attrs = vec![
        // Note: Fortanix DSM requires a name for at least the private
        // key.
        Attribute::Name(public_key_name),
        // Note: PyKMIP requires a Cryptographic Usage Mask for the public
        // key.
        Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
    ];

    let (alg, bits) = match params {
        GenerateParams::RsaSha256 { bits } => (&ALG_RSASHA256, Some(bits)),
        GenerateParams::RsaSha512 { bits } => (&ALG_RSASHA512, Some(bits)),
        GenerateParams::EcdsaP256Sha256 => (&ALG_ECDSAP256SHA256, None),
        GenerateParams::EcdsaP384Sha384 => (&ALG_ECDSAP384SHA384, None),
        // GenerateParams::Ed25519 => (&ALG_ED25519, None),
        GenerateParams::Ed25519 => {
            return Err(GenerateError::UnsupportedAlgorithm);
        }
        GenerateParams::Ed448 => {
            return Err(GenerateError::UnsupportedAlgorithm);
        }
    };

    common_attrs.push(Attribute::CryptographicAlgorithm(alg.kmip_crypto_alg));

    // Use the variable number of bits supplied by the caller if available,
    // or that specifieid for the algorithm, if defined.
    if let Some(len) = bits.or(alg.kmip_crypto_fixed_len) {
        // If the algorithm mandates a range of permitted length values
        // enforce those limits here.
        if let Some((min, max)) = alg.len_range
            && !(min..=max).contains(&len)
        {
            return Err(GenerateError::UnsupportedAlgorithm);
        }

        common_attrs
            .push(Attribute::CryptographicLength(len.try_into().unwrap()));
    }

    let request = RequestPayload::CreateKeyPair(
        Some(CommonTemplateAttribute::new(common_attrs.clone())),
        Some(PrivateKeyTemplateAttribute::new(priv_key_attrs.clone())),
        Some(PublicKeyTemplateAttribute::new(pub_key_attrs.clone())),
    );

    // Execute the request and capture the response
    let client = conn_pool.get().map_err(|err| {
        crate::error::GenerateError::Kmip(format!(
            "Key generation failed: Cannot connect to KMIP server {}: {err}",
            conn_pool.server_id()
        ))
    })?;

    let mut response = client.do_request(request);

    if let Err(Error::ServerError(err)) = &response {
        // Some HSM KMIP implementations require Cryptographic Domain
        // Parameters (e.g. Securosys with ECDSA-SHA256 needs to know
        // which curve to use) while others have the opposite behaviour
        // such that they return an error if Cryptographic Domain
        // Parameters are supplied (e.g. Fortanix DSM with ECDSA-SHA256).
        // Try first without, and if that fails, try with.
        if let Some(curve) = alg.elliptic_curve {
            debug!(
                "Create Key Pair operation failed with error: {err}. Some HSMs require that the elliptic curve to use be specified explicity, retrying with an explicit elliptic curve"
            );
            common_attrs.push(Attribute(
                AttributeName("Cryptographic Domain Parameters".into()),
                Option::<AttributeIndex>::None,
                CryptographicDomainParameters::default()
                    .with_recommended_curve(curve.kmip_recommend_curve)
                    .into(),
            ));
            let request = RequestPayload::CreateKeyPair(
                Some(CommonTemplateAttribute::new(common_attrs)),
                Some(PrivateKeyTemplateAttribute::new(priv_key_attrs)),
                Some(PublicKeyTemplateAttribute::new(pub_key_attrs)),
            );

            // Execute the request and capture the response
            response = client.do_request(request);
        }
    }

    let response = response.map_err(|err| {
        error!("KMIP Create Key Pair request failed: {err}");
        GenerateError::Kmip(err.to_string())
    })?;

    trace!("Key generation operation complete");

    // Drop the KMIP client so that it will be returned to the pool and
    // thus be available below when KeyPair::new() is invoked and tries to
    // fetch the details needed to determine the DNSKEY RR.
    drop(client);

    // Process the successful response
    let ResponsePayload::CreateKeyPair(payload) = response else {
        error!("KMIP request failed: Wrong response type received!");
        return Err(GenerateError::Kmip(
            "Unable to parse KMIP response: payload should be CreateKeyPair"
                .to_string(),
        ));
    };

    let CreateKeyPairResponsePayload {
        private_key_unique_identifier,
        public_key_unique_identifier,
    } = payload;

    trace!("Creating KeyPair with DNSKEY");

    let key_pair = KeyPair::from_metadata(
        algorithm,
        flags,
        private_key_unique_identifier.as_str(),
        public_key_unique_identifier.as_str(),
        conn_pool.clone(),
    )
    .map_err(|err| GenerateError::Kmip(err.to_string()))?;

    // Activate the key if not already, otherwise it cannot be used for
    // signing.
    let client = conn_pool.get().map_err(|err| {
        GenerateError::Kmip(format!(
            "Key generation failed: Cannot connect to KMIP server {}: {err}",
            conn_pool.server_id()
        ))
    })?;
    let request = RequestPayload::Activate(Some(private_key_unique_identifier));

    // Execute the request and capture the response
    trace!("Activating KMIP key...");
    let response = client.do_request(request).map_err(|err| {
        eprintln!("KMIP activate private key request failed: {err}");
        eprintln!(
            "KMIP last request: {}",
            client.last_req_diag_str().unwrap_or_default()
        );
        eprintln!(
            "KMIP last response: {}",
            client.last_res_diag_str().unwrap_or_default()
        );
        GenerateError::Kmip(err.to_string())
    })?;
    trace!("Activate operation complete");

    // Process the successful response
    let ResponsePayload::Activate(_) = response else {
        error!("KMIP request failed: Wrong response type received!");
        return Err(GenerateError::Kmip(
            "Unable to parse KMIP response: payload should be Activate"
                .to_string(),
        ));
    };

    Ok(key_pair)
}

//----------- destroy() --------------------------------------------------

/// Destroy a KMIP key by ID using a given KMIP server connection pool.
///
/// As a KMIP key cannot be destroyed if it is active, this function first
/// attempts to revoke the key and then destroy it.
pub fn destroy(
    key_id: &str,
    conn_pool: SyncConnPool,
) -> Result<(), DestroyError> {
    let client = conn_pool.get().map_err(|err| {
        DestroyError::Kmip(format!(
            "Key destruction failed: Cannot connect to KMIP server {}: {err}",
            conn_pool.server_id()
        ))
    })?;

    client
        .revoke_key(key_id)
        .map_err(|err| DestroyError::Kmip(err.to_string()))?;
    client
        .destroy_key(key_id)
        .map_err(|err| DestroyError::Kmip(err.to_string()))
}
