//------------ KeyUrl --------------------------------------------------------

use std::{fmt, str::FromStr};

use domain::base::iana::SecurityAlgorithm;
use url::Url;

/// A URL that represents a key stored in a KMIP compatible HSM.
///
/// The URL structure is:
///
/// ```text
/// kmip://<server_id>/keys/<key_id>?algorithm=<algorithm>&flags=<flags>
/// ````
///
/// The algorithm and flags must be stored in the URL because they are DNSSEC
/// specific and not properties of the key itself and thus not known to or
/// stored by the HSM.
///
/// While algorithm may seem to be something known to and stored by the HSM,
/// DNSSEC complicates that by aliasing multiple algorithm numbers to the
/// same cryptographic algorithm, and we need to know when using the key which
/// _DNSSEC_ algorithm number to use.
///
/// The `server_id` could be the actual address of the target, but does not have
/// to be. There are multiple reasons for this:
///
///   - In a highly available clustered deployment across multiple subnets
///     it could be that the clustered HSM is available to the clustered
///     application via different names/IP addresses in different subnets of
///     the deployment. Using an abstract server_id which is mapped via local
///     configuration in the subnet to the correct hostname/FQDN/IP address
///     for that subnet allows the correct target address to be determined at
///     the point of access.
///   - Using the actual hostname/FQDN/IP address may make it confusing for
///     an operator trying to understand where the key is actually stored.
///     This can happen for example if the product name for the HSM is say
///     Fortanix DSM, while the domain name used to access the HSM might be
///     eu.smartkey.io, which having no mention of the name Fortanix in the
///     FQDN is not immediately obvious that it has any relationship with
///     Fortanix.
///   - If the same HSM is used for different use cases via use of HSM
///     partitions, referring to the HSM by its address may not make it clear
///     which partition is being used, so using a more meaningful name like
///     'testing' or such could make it clearer where the key is actually
///     being stored.
///   - Storing the username and password in the key URL will cause many
///     copies of those credentials to be stored, one per key, which is harder
///     to secure than if they are only in a single location and looked up on
///     actual access.
///   - Storing the username and password in the key URL would cause the URL
///     to become unusable if the credentials were rotated even though the
///     location at which the key is stored has not changed.
///   - Even if the FQDN, port number, username and password are all correct,
///     there may need to be more settings specified in order to connect to
///     the HSM some of which would not fit easily into a URL such as TLS
///     client certficate details and whether or not to require the server
///     TLS certificate to be valid (which can be inconvenient in test setups
///     using self-signed certificates).
///
/// Thus an abstract `server_id` is stored in the key URL and it is the
/// responsibility of the user of the key URL to map the server id to the full
/// set of settings required to successfully connect to the HSM to make use of
/// the key.
pub struct KeyUrl {
    /// The original URL from which this KeyUrl was parsed.
    url: Url,

    /// The KMIP server ID. Produced by the application.
    server_id: String,

    /// The KMIP key ID. Produced by the KMIP server.
    key_id: String,

    /// The DNSSEC algorithm this key is to be used for.
    algorithm: SecurityAlgorithm,

    /// The DNSSEC flags that apply to this key.
    flags: u16,
}

//--- Accessors

impl KeyUrl {
    /// The KMIP server ID.
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// The KMIP key ID.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The DNSSEC algorithm identifier for the key.
    pub fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    /// The DNSSEC flags for the key.
    pub fn flags(&self) -> u16 {
        self.flags
    }
}

//--- impl Deref

impl std::ops::Deref for KeyUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.url
    }
}

//--- Conversions

impl From<KeyUrl> for Url {
    fn from(key_url: KeyUrl) -> Self {
        key_url.url
    }
}

impl TryFrom<Url> for KeyUrl {
    type Error = String;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let server_id = url
            .host_str()
            .ok_or(format!("Key URL lacks hostname component: {url}"))?
            .to_string();

        let url_path = url.path().to_string();
        let key_id = url_path
            .strip_prefix("/keys/")
            .ok_or(format!("Key URL lacks /keys/ path component: {url}"))?;

        let key_id = key_id.to_string();
        let mut flags = None;
        let mut algorithm = None;
        for (k, v) in url.query_pairs() {
            match &*k {
                "flags" => {
                    flags = Some(v.parse::<u16>().map_err(|err| {
                        format!("Key URL flags value is invalid: {err}")
                    })?)
                }
                "algorithm" => {
                    algorithm = Some(SecurityAlgorithm::from_str(&v).map_err(
                        |err| {
                            format!("Key URL algorithm value is invalid: {err}")
                        },
                    )?)
                }
                unknown => Err(format!(
                    "Key URL contains unknown query parameter: {unknown}"
                ))?,
            }
        }
        let algorithm = algorithm
            .ok_or(format!("Key URL lacks algorithm query parameter: {url}"))?;
        let flags = flags
            .ok_or(format!("Key URL lacks flags query parameter: {url}"))?;

        Ok(Self {
            url,
            server_id,
            key_id,
            algorithm,
            flags,
        })
    }
}

//--- impl Display

impl fmt::Display for KeyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.url.fmt(f)
    }
}
