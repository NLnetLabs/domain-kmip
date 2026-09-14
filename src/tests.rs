use core::time::Duration;

use std::fs::File;
use std::io::{BufReader, Read};
use std::string::ToString;
use std::time::SystemTime;
use std::vec::Vec;

use domain::base::iana::SecurityAlgorithm;
use kmip_protocol::client::ConnectionSettings;
use kmip_protocol::client::pool::ConnectionManager;

use domain::crypto::sign::SignRaw;

use crate::algorithms::ecdsa::parse_ecdsa_key_from_x509;
use crate::algorithms::ecdsa::parse_ecdsa_sig_from_x962;
use crate::algorithms::rsa::parse_rsa_from_pkcs1;
use crate::generate;

fn init_logging() {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        // Useful sometimes:
        // .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .init();
}

#[test]
fn test_parse_rsa_key_from_pkcs1() {
    // TODO: Find real-world samples.
    let bytes = [48, 6, 2, 1, 127, 2, 1, 42];
    let key =
        parse_rsa_from_pkcs1(SecurityAlgorithm::RSASHA256, &bytes).unwrap();
    assert_eq!(key.algorithm, SecurityAlgorithm::RSASHA256);
    assert_eq!(key.public_key, [1, 42, 127]);
}

#[test]
fn test_parse_ecdsa_key_from_x509() {
    // TODO: Find real-world samples.
    let bytes = [
        48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
        206, 61, 3, 1, 7, 3, 66, 0, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    let key =
        parse_ecdsa_key_from_x509(SecurityAlgorithm::ECDSAP256SHA256, &bytes)
            .unwrap();
    assert_eq!(key.algorithm, SecurityAlgorithm::ECDSAP256SHA256);
    assert_eq!(
        key.public_key,
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn test_parse_ecdsa_sig_from_x962() {
    // TODO: Find real-world samples.
    let bytes = [48, 6, 2, 1, 21, 2, 1, 47];
    let signature = parse_ecdsa_sig_from_x962(&bytes).unwrap();
    assert_eq!(
        *signature,
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47
        ]
    );
}

#[test]
#[ignore = "Requires running PyKMIP"]
fn pykmip_connect() {
    init_logging();
    let mut cert_bytes = Vec::new();
    let file =
        File::open("/home/ximon/docker_data/pykmip/pykmip-data/selfsigned.crt")
            .unwrap();
    let mut reader = BufReader::new(file);
    reader.read_to_end(&mut cert_bytes).unwrap();

    let mut key_bytes = Vec::new();
    let file =
        File::open("/home/ximon/docker_data/pykmip/pykmip-data/selfsigned.key")
            .unwrap();
    let mut reader = BufReader::new(file);
    reader.read_to_end(&mut key_bytes).unwrap();

    let conn_settings = ConnectionSettings {
        host: "localhost".to_string(),
        port: 5696,
        insecure: true,
        client_cert: Some(
            kmip_protocol::client::ClientCertificate::SeparatePem {
                cert_bytes,
                key_bytes,
            },
        ),
        ..Default::default()
    };

    eprintln!("Creating pool...");
    let pool = ConnectionManager::create_connection_pool(
        "Test server".to_string(),
        conn_settings.into(),
        16384,
        Some(Duration::from_secs(60)),
        Some(Duration::from_secs(60)),
    )
    .unwrap();

    eprintln!("Connecting...");
    let client = pool.get().unwrap();

    eprintln!("Connected");
    let res = client.query();
    dbg!(&res);
    res.unwrap();

    let pub_key_name = format!(
        "{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let pri_key_name = format!(
        "{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let res = generate(
        pub_key_name,
        pri_key_name,
        domain::crypto::sign::GenerateParams::RsaSha256 { bits: 2048 },
        // crate::crypto::sign::GenerateParams::EcdsaP256Sha256,
        256,
        pool,
    );
    dbg!(&res);
    let key = res.unwrap();

    eprintln!("DNSKEY: {}", key.dnskey());
}

/// FORTANIX_USER and FORTANIX_PASS should be set to values obtained from
/// https://eu.smartkey.io/#/apps page after creating an "app" with API
/// key based authentication then using the username and password that are
/// generated for that API key.
#[test]
#[ignore = "Requires Fortanix credentials"]
fn fortanix_dsm_test() {
    init_logging();

    let conn_settings = ConnectionSettings {
        host: "eu.smartkey.io".to_string(),
        port: 5696,
        username: Some(std::env::var("FORTANIX_USER").unwrap().to_string()),
        password: Some(std::env::var("FORTANIX_PASS").unwrap().to_string()),
        insecure: true,
        connect_timeout: Some(Duration::from_secs(3)),
        read_timeout: Some(Duration::from_secs(30)),
        write_timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    };

    eprintln!("Creating pool...");
    let pool = ConnectionManager::create_connection_pool(
        "Test server".to_string(),
        conn_settings.into(),
        16384,
        Some(Duration::from_secs(60)),
        Some(Duration::from_secs(60)),
    )
    .unwrap();

    eprintln!("Connecting...");
    let mut client = pool.get().unwrap();
    let new_rc = client.reader_config().clone().with_sensitive_capture();
    client.set_reader_config(new_rc);

    eprintln!("Connected");
    let res = client.query();
    dbg!(&res);
    res.unwrap();

    let pub_key_name = format!(
        "{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let pri_key_name = format!(
        "{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let res = generate(
        pub_key_name,
        pri_key_name,
        domain::crypto::sign::GenerateParams::RsaSha256 { bits: 1024 },
        // crate::crypto::sign::GenerateParams::EcdsaP256Sha256,
        256,
        pool,
    );
    let key = res.unwrap();
    eprintln!("Generated public key with id: {}", key.public_key_id());
    eprintln!("Generated private key with id: {}", key.private_key_id());

    // sleep(Duration::from_secs(5));

    eprintln!("DNSKEY: {}", key.dnskey());

    // client.activate_key(key.public_key_id()).unwrap();

    // Fortanix: Activating the public key also activates the private key.
    // Attempting to then activate the private key fails as it is already
    // active. Yet signing fails with "Object is not yet active"...
    // client.activate_key(key.private_key_id()).unwrap();

    // // This works round the not yet active yet error.
    // sleep(Duration::from_secs(5));

    // let request = RequestPayload::Sign(
    //     Some(UniqueIdentifier(key.private_key_id().to_string())),
    //     // While the KMIP 1.2 spec says crypto parameters are optional and
    //     // if not specified those of the key will be used, Fortanix
    //     // complains about "No cryptographic parameters specified" if this
    //     // is None, and "Must specicify HashingAlgorithm" if that is not
    //     // specified.
    //     Some(
    //         CryptographicParameters::default()
    //             // .with_padding_method(PaddingMethod::)
    //             .with_hashing_algorithm(HashingAlgorithm::SHA256)
    //             .with_cryptographic_algorithm(
    //                 CryptographicAlgorithm::RSA,
    //                 //CryptographicAlgorithm::ECDSA,
    //             ),
    //     ),
    //     Data("Message for ECDSA signing".as_bytes().to_vec()),
    // );

    // // Execute the request and capture the response
    // let res = client.do_request(request).unwrap();

    // dbg!(&res);

    // let ResponsePayload::Sign(signed) = res else {
    //     unreachable!();
    // };

    // // let signature =
    // //     openssl::ecdsa::EcdsaSig::from_der(&signed.signature_data)
    // //         .unwrap();

    // // dbg!(signature.r().to_vec_padded(32));
    // // dbg!(signature.s().to_vec_padded(32));

    // // dbg!(response);
}
