#![cfg(mls_build_async)]

use std::error::Error;

use mls_rs::crypto::SignaturePublicKey;
use mls_rs::identity::x509::CertificateChain;
use mls_rs::identity::x509::X509IdentityError;
use mls_rs::time::MlsTime;
use mls_rs_crypto_webcrypto::WebCryptoProvider as TestCryptoProvider;

use mls_rs::group::proposal::Proposal;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::CipherSuiteProvider;
use mls_rs::ExtensionList;
use mls_rs::Group;
use mls_rs::MlsMessage;
use mls_rs::ProtocolVersion;
use mls_rs::{
    client_builder::MlsConfig,
    error::MlsError,
    identity::basic::{BasicCredential, BasicIdentityProvider},
    mls_rules::{CommitOptions, DefaultMlsRules},
    CipherSuite, Client, CryptoProvider,
};

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

pub async fn make_client(name: &str) -> Result<Client<impl MlsConfig>, MlsError> {
    let crypto_provider = mls_rs_crypto_webcrypto::WebCryptoProvider::default();
    let cipher_suite = crypto_provider.cipher_suite_provider(CIPHERSUITE).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite
        .signature_key_generate()
        .await
        .expect("should generate the keys");

    // Create a basic credential for the session.
    // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
    // X.509 credentials are recommended.
    let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider)
        .mls_rules(
            DefaultMlsRules::new()
                .with_commit_options(CommitOptions::new().with_path_required(true)),
        )
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .build())
}
