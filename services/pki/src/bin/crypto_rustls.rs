use std::fs::File;
use std::io::{Read, Write};
use std::ops::Add;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};

use rcgen::KeyPair;
use rustls::pki_types::{CertificateRevocationListDer, PrivatePkcs8KeyDer};
use rustls::server::{Acceptor, ClientHello, ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;
use serde::Deserialize;

pub fn create_root_store(ca_cert: &rcgen::Certificate) -> RootCertStore {
    // Create a root cert store that includes the CA certificate.
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    roots
}

pub fn mk_client_certificate(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (KeyPair, rcgen::Certificate) {
    // Create a client end entity cert issued by the CA.
    let mut client_ee_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    client_ee_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example Client");
    client_ee_params.is_ca = rcgen::IsCa::NoCa;
    client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    client_ee_params.serial_number = Some(rcgen::SerialNumber::from(vec![0xC0, 0xFF, 0xEE]));
    let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let client_cert = client_ee_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    (client_key, client_cert)
}

pub fn mk_server_certificate(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (KeyPair, rcgen::Certificate) {
    // Create a server end entity cert issued by the CA.
    let mut server_ee_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let ee_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let server_cert = server_ee_params
        .signed_by(&ee_key, &ca_cert, &ca_key)
        .unwrap();
    (ee_key, server_cert)
}

pub fn mk_issuer_ca() -> (KeyPair, rcgen::Certificate) {
    // Create an issuing CA cert.
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    (ca_key, ca_cert)
}

fn main() {
    env_logger::Builder::new().parse_filters("trace").init();

    let write_pem = |path: &str, pem: &str| {
        let mut file = File::create(path).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
    };

    // Create a test PKI with:
    // * An issuing CA certificate.
    // * A server certificate issued by the CA.
    let test_pki = Arc::new(TestPki::new());

    // Write out the parts of the test PKI a client will need to connect:
    // * The CA certificate for validating the server certificate.
    // * The client certificate and key for its presented mTLS identity.
    write_pem("ca-cert.pem", &test_pki.ca_cert.cert.pem());
    // write_pem("client-cert.pem", &test_pki.client_cert.cert.pem());
    // write_pem(
    //     "client-key.pem",
    //     &test_pki.client_cert.key_pair.serialize_pem(),
    // );

    // Write out an initial DER CRL that has no revoked certificates.
    let update_seconds = 5;
    let crl_path = "crl.der";
    let mut crl_der = File::create(crl_path).unwrap();
    crl_der
        .write_all(&test_pki.crl(Vec::default(), update_seconds))
        .unwrap();

    // Start a TLS server accepting connections as they arrive.
    let listener = std::net::TcpListener::bind(format!("[::]:{}", 8000)).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        // Read TLS packets until we've consumed a full client hello and are ready to accept a
        // connection.
        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();

            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    alert.write_all(&mut stream).unwrap();
                    panic!("error accepting connection: {e}");
                }
            }
        };

        // Generate a server config for the accepted connection, optionally customizing the
        // configuration based on the client hello.
        let config = test_pki.server_config(&crl_path, accepted.client_hello());
        let mut conn = match accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((e, mut alert)) => {
                alert.write_all(&mut stream).unwrap();
                panic!("error completing accepting connection: {e}");
            }
        };

        // Proceed with handling the ServerConnection
        // Important: We do no error handling here, but you should!
        _ = conn.complete_io(&mut stream);
    }
}

/// A test PKI with a CA certificate, server certificate, and client certificate.
struct TestPki {
    roots: Arc<RootCertStore>,
    ca_cert: rcgen::CertifiedKey,
    server_cert: rcgen::CertifiedKey,
}

impl TestPki {
    /// Create a new test PKI using `rcgen`.
    fn new() -> Self {
        let (ca_key, ca_cert) = mk_issuer_ca();
        let (ee_key, server_cert) = mk_server_certificate(&ca_cert, &ca_key);
        let roots = create_root_store(&ca_cert);
        Self {
            roots: roots.into(),
            ca_cert: rcgen::CertifiedKey {
                cert: ca_cert,
                key_pair: ca_key,
            },
            server_cert: rcgen::CertifiedKey {
                cert: server_cert,
                key_pair: ee_key,
            },
        }
    }

    /// Generate a server configuration for the client using the test PKI.
    ///
    /// Importantly this creates a new client certificate verifier per-connection so that the server
    /// can read in the latest CRL content from disk.
    ///
    /// Since the presented client certificate is not available in the `ClientHello` the server
    /// must know ahead of time which CRLs it cares about.
    fn server_config(&self, crl_path: &str, _hello: ClientHello) -> Arc<ServerConfig> {
        // Read the latest CRL from disk. The CRL is being periodically updated by the crl_updater
        // thread.
        let mut crl_file = File::open(crl_path).unwrap();
        let mut crl = Vec::default();
        crl_file.read_to_end(&mut crl).unwrap();

        // Construct a fresh verifier using the test PKI roots, and the updated CRL.
        let verifier = WebPkiClientVerifier::builder(self.roots.clone())
            .with_crls([CertificateRevocationListDer::from(crl)])
            .build()
            .unwrap();

        // Build a server config using the fresh verifier. If necessary, this could be customized
        // based on the ClientHello (e.g. selecting a different certificate, or customizing
        // supported algorithms/protocol versions).
        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.server_cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(self.server_cert.key_pair.serialize_der()).into(),
            )
            .unwrap();

        // Allow using SSLKEYLOGFILE.
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }

    /// Issue a certificate revocation list (CRL) for the revoked `serials` provided (may be empty).
    /// The CRL will be signed by the test PKI CA and returned in DER serialized form.
    fn crl(
        &self,
        serials: Vec<rcgen::SerialNumber>,
        next_update_seconds: u64,
    ) -> CertificateRevocationListDer {
        // In a real use-case you would want to set this to the current date/time.
        let now = rcgen::date_time_ymd(2023, 1, 1);

        // For each serial, create a revoked certificate entry.
        let revoked_certs = serials
            .into_iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: serial,
                revocation_time: now,
                reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();

        // Create a new CRL signed by the CA cert.
        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: now.add(Duration::from_secs(next_update_seconds)),
            crl_number: rcgen::SerialNumber::from(1234),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        crl_params
            .signed_by(&self.ca_cert.cert, &self.ca_cert.key_pair)
            .unwrap()
            .into()
    }
}
