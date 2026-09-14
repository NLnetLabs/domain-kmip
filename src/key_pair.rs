use std::string::{String, ToString};
use std::vec::Vec;

use kmip_protocol::client::pool::SyncConnPool;
use kmip_protocol::types::common::{
    CryptographicParameters, Data, UniqueBatchItemID, UniqueIdentifier,
};
use kmip_protocol::types::request::{BatchItem, RequestPayload};
use kmip_protocol::types::response::ResponsePayload;
use tracing::{error, trace};
use url::Url;
use uuid::Uuid;

use domain::base::iana::SecurityAlgorithm;
use domain::crypto::sign::{SignError, SignRaw, Signature};
use domain::rdata::Dnskey;
use domain::utils::base16;

use crate::algorithms::get_alg_info;
use crate::error::{GenerateError, KeyUrlParseError};
use crate::key_url::KeyUrl;
use crate::public_key::PublicKey;

//----------- KeyPair ----------------------------------------------------

/// A reference to a key pair stored in an [OASIS KMIP] compliant HSM
/// server.
///
/// Allows operations to be performed on and using the key pair.
///
/// Operations common to key pairs irrespective of the underlying crypto
/// backend are offered via the [`SignRaw`] trait impl.
///
/// Operations specifc to KMIP key pairs are offered via methods specific
/// to this type, e.g. batching support via [`Self::sign_raw_enqueue()`]
/// and [`Self::sign_raw_submit_queue()`].
///
/// See [`Self::from_metadata()`] and [`Self::from_urls()`] to construct
/// a [`KeyPair`] from individual public and private KMIP keys.
///
/// To generate a KMIP key pair see [`crate::generate()`].
///
/// To destroy individual KMIP keys see [`crate::destroy()`].
///
/// [OASIS KMIP]: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// The algorithm used by the key.
    algorithm: SecurityAlgorithm,

    /// The KMIP ID of the private key.
    private_key_id: String,

    /// The KMIP ID of the public key.
    public_key_id: String,

    /// The connection pool for connecting to the KMIP server.
    // TODO: Should this be T that impl's a Connection trait, why should
    // it know that it's a pool rather than a single connection?
    conn_pool: SyncConnPool,

    /// Cached DNSKEY RR for the public key.
    dnskey: Dnskey<Vec<u8>>,

    /// Flags from [`Dnskey`].
    flags: u16,
}

//--- Constructors

impl KeyPair {
    /// Construct a reference to a KMIP HSM held key pair using key
    /// metadata.
    pub fn from_metadata(
        algorithm: SecurityAlgorithm,
        flags: u16,
        private_key_id: &str,
        public_key_id: &str,
        conn_pool: SyncConnPool,
    ) -> Result<Self, GenerateError> {
        let dnskey = PublicKey::for_key_id_and_dnssec_algorithm(
            public_key_id,
            algorithm,
            conn_pool.clone(),
        )
        .map_err(|err| GenerateError::Kmip(err.to_string()))?
        .dnskey(flags);

        Ok(Self {
            algorithm,
            private_key_id: private_key_id.to_string(),
            public_key_id: public_key_id.to_string(),
            conn_pool,
            flags,
            dnskey,
        })
    }

    /// Construct a reference to a KMIP HSM held key pair using key URLs.
    pub fn from_urls(
        priv_key_url: KeyUrl,
        pub_key_url: KeyUrl,
        conn_pool: SyncConnPool,
    ) -> Result<Self, GenerateError> {
        if priv_key_url.algorithm() != pub_key_url.algorithm() {
            Err(GenerateError::Kmip(format!(
                "Private and public key URLs have different algorithms: {} vs {}",
                priv_key_url.algorithm(),
                pub_key_url.algorithm()
            )))
        } else if priv_key_url.flags() != pub_key_url.flags() {
            Err(GenerateError::Kmip(format!(
                "Private and public key URLs have different flags: {} vs {}",
                priv_key_url.flags(),
                pub_key_url.flags()
            )))
        } else if priv_key_url.server_id() != pub_key_url.server_id() {
            Err(GenerateError::Kmip(format!(
                "Private and public key URLs have different server IDs: {} vs {}",
                priv_key_url.server_id(),
                pub_key_url.server_id()
            )))
        } else if priv_key_url.server_id() != conn_pool.server_id() {
            Err(GenerateError::Kmip(format!(
                "Key URLs have different server ID to the KMIP connection pool: {} vs {}",
                priv_key_url.server_id(),
                conn_pool.server_id()
            )))
        } else {
            Self::from_metadata(
                priv_key_url.algorithm(),
                priv_key_url.flags(),
                priv_key_url.key_id(),
                pub_key_url.key_id(),
                conn_pool,
            )
        }
    }
}

//--- Accessors

impl KeyPair {
    /// Get the KMIP HSM ID for the private half of this key pair.
    pub fn private_key_id(&self) -> &str {
        &self.private_key_id
    }

    /// Get the KMIP HSM ID for the public half of this key pair.
    pub fn public_key_id(&self) -> &str {
        &self.public_key_id
    }

    /// Get a KMIP URL for the private half of this key pair.
    pub fn private_key_url(&self) -> Url {
        //
        self.mk_key_url(&self.private_key_id).unwrap()
    }

    /// Get a KMIP URL for the public half of this key pair.
    pub fn public_key_url(&self) -> Url {
        self.mk_key_url(&self.public_key_id).unwrap()
    }

    /// Get a reference to the KMIP HSM connection pool for this key pair.
    pub fn conn_pool(&self) -> &SyncConnPool {
        &self.conn_pool
    }
}

//--- Operations

impl KeyPair {
    /// Enqueue a KMIP signing operation using this key pair on the given
    /// data.
    ///
    /// Like [`SignRaw::sign_raw()`] but deferred until
    /// [`KeyPair::sign_raw_submit_queue()`] is called.
    pub fn sign_raw_enqueue(
        &self,
        queue: &mut SignQueue,
        data: &[u8],
    ) -> Result<Option<Signature>, SignError> {
        let request = self.sign_pre(data)?;
        let operation = request.operation();
        let batch_item_id =
            UniqueBatchItemID(Uuid::new_v4().into_bytes().to_vec());
        let batch_item = BatchItem(operation, Some(batch_item_id), request);
        queue.0.push(batch_item);
        Ok(None)
    }

    /// Submit the given signing queue as a batch to the KMIP HSM.
    //
    // TODO: Should the queue store the KMIP connection pool reference and
    // should submit() be a method on the queue?
    // TODO: What happens if the same queue is used with
    // sign_raw_enqueue() but with keys that are held by different KMIP
    // HSMs and thus have different KMIP connection pools?
    pub fn sign_raw_submit_queue(
        &self,
        queue: &mut SignQueue,
    ) -> Result<Vec<Signature>, SignError> {
        // Execute the request and capture the response.
        let client = self.conn_pool.get().map_err(|err| {
            error!("Error while obtaining KMIP pool connection: {err}");
            SignError
        })?;

        // Drain the queue.
        let q_size = queue.0.capacity();
        let mut empty = Vec::with_capacity(q_size);
        std::mem::swap(&mut queue.0, &mut empty);
        let queue = empty;

        // This will block which could be problematic if executed from an
        // async task handler thread as it will block execution of other
        // tasks while waiting for the remote KMIP server to respond.
        let res = client.do_requests(queue).map_err(|err| {
            error!("Error while sending KMIP request: {err}");
            SignError
        })?;

        let mut sigs = Vec::with_capacity(q_size);
        for res in res {
            let res = res.map_err(|err| {
                error!("{err}");
                SignError
            })?;
            let sig = self.sign_post(res.payload.unwrap())?;
            sigs.push(sig);
        }

        Ok(sigs)
    }
}

//--- Internal details

impl KeyPair {
    /// Make a KMIP URL for this key using the given KMIP ID.
    fn mk_key_url(&self, key_id: &str) -> Result<Url, KeyUrlParseError> {
        // We have to store the algorithm in the URL because the DNSSEC
        // algorithm (e.g. 5 and 7) don't necessarily correspond to the
        // cryptographic algorithm of the key known to the HSM. And we
        // have to store the flags in the URL because these are not known
        // to the HSM, they say someting about the use to which the key
        // will be put of which the HSM is unaware.
        let url = format!(
            "kmip://{}/keys/{}?algorithm={}&flags={}",
            self.conn_pool.server_id(),
            key_id,
            self.algorithm,
            self.flags
        );

        let url = Url::parse(&url).map_err(|err| {
            KeyUrlParseError(format!("unable to parse {url} as URL: {err}"))
        })?;

        Ok(url)
    }

    /// Prepare a KMIP signing operation request to sign the given data
    /// using this key pair.
    fn sign_pre(&self, data: &[u8]) -> Result<RequestPayload, SignError> {
        let Some(alg_info) = get_alg_info(self.algorithm) else {
            error!(
                "Algorithm not supported for KMIP signing: {}",
                self.algorithm
            );
            return Err(SignError);
        };

        let mut cryptographic_parameters = CryptographicParameters::default()
            .with_hashing_algorithm(alg_info.kmip_hash_alg)
            .with_cryptographic_algorithm(alg_info.kmip_crypto_alg);

        if let Some(padding_method) = alg_info.kmip_padding_method {
            cryptographic_parameters =
                cryptographic_parameters.with_padding_method(padding_method);
        }

        let request = RequestPayload::Sign(
            Some(UniqueIdentifier(self.private_key_id.clone())),
            Some(cryptographic_parameters),
            Data(data.as_ref().to_vec()),
        );
        Ok(request)
    }

    /// Process a KMIP HSM signing operation response for this key pair.
    fn sign_post(&self, res: ResponsePayload) -> Result<Signature, SignError> {
        trace!("Checking sign payload");
        let ResponsePayload::Sign(signed) = res else {
            unreachable!();
        };

        trace!(
            "Algorithm: {}, Signature Data: {}",
            self.algorithm,
            base16::encode_display(&signed.signature_data)
        );

        let Some(alg_info) = get_alg_info(self.algorithm) else {
            error!(
                "KMIP signature parsing not implemented for algorithm: {}",
                self.algorithm,
            );
            return Err(SignError);
        };

        (alg_info.sig_parser)(signed.signature_data)
    }
}

//----------- SignQueue --------------------------------------------------

/// A queue of KMIP signing operations pending batch submission.
#[derive(Debug, Default)]
pub struct SignQueue(Vec<BatchItem>);

impl SignQueue {
    /// Constructs a new empty signing queue.
    pub fn new() -> Self {
        Self(vec![])
    }
}

impl SignRaw for KeyPair {
    fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    fn dnskey(&self) -> Dnskey<Vec<u8>> {
        self.dnskey.clone()
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
        let request = self.sign_pre(data)?;

        // Execute the request and capture the response.
        let client = self.conn_pool.get().map_err(|err| {
            error!("Error while obtaining KMIP pool connection: {err}");
            SignError
        })?;

        // This will block which could be problematic if executed from an
        // async task handler thread as it will block execution of other
        // tasks while waiting for the remote KMIP server to respond.
        let res = client.do_request(request).map_err(|err| {
            error!("Error while sending KMIP request: {err}");
            SignError
        })?;

        self.sign_post(res)
    }
}
