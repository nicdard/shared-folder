// Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
use rcgen::{
    CertificateParams, CertificateSigningRequest, CertificateSigningRequestParams, KeyPair,
};
use rustls::RootCertStore;
use x509_parser::{certificate::X509Certificate, der_parser::asn1_rs::FromDer};

/// Create a root cert store that includes the CA certificate.
pub fn create_root_store(ca_cert: &rcgen::Certificate) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    roots
}

/// Create a client certificate and private key signed by the given CA.
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
    let client_key = mk_ee_key_pair();
    let client_cert = client_ee_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    (client_key, client_cert)
}

/// Create a server certificate and private key signed by the given CA.
pub fn mk_server_certificate(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (KeyPair, rcgen::Certificate) {
    // Create a server end entity cert issued by the CA.
    let mut server_ee_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let ee_key = mk_ee_key_pair();
    let server_cert = server_ee_params
        .signed_by(&ee_key, &ca_cert, &ca_key)
        .unwrap();
    (ee_key, server_cert)
}

/// Create an issuing CA certificate and private key.
pub fn mk_issuer_ca() -> (KeyPair, rcgen::Certificate) {
    let ca_key = mk_ee_key_pair();
    let ca_cert = mk_issuer_ca_from_keys(&ca_key);
    (ca_key, ca_cert)
}

pub fn mk_issuer_ca_from_keys(key_pair: &KeyPair) -> rcgen::Certificate {
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
    let ca_cert = ca_params.self_signed(key_pair).unwrap();
    ca_cert
}

/// Create a new client certificate request with the given email address.
pub fn mk_client_certificate_request_params(email: &str) -> (KeyPair, CertificateSigningRequest) {
    let key_pair = mk_ee_key_pair();
    let params = CertificateParams::new(vec![email.to_string()]).unwrap();
    let certificate_request = params.serialize_request(&key_pair).unwrap();
    (key_pair, certificate_request)
}

pub fn mk_ee_key_pair() -> KeyPair {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
}

/// Sign the given certificate signing request.
pub fn sign_request(
    signing_request: CertificateSigningRequest,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> rcgen::Certificate {
    let params =
        CertificateSigningRequestParams::from_pem(&signing_request.pem().unwrap()).unwrap();
    params.signed_by(ca_cert, ca_key).unwrap()
}

/// Sing the given certificate signing request from a PEM string.
pub fn sign_request_from_pem(
    signing_request_pem: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> rcgen::Certificate {
    let params = CertificateSigningRequestParams::from_pem(signing_request_pem).unwrap();
    params.signed_by(ca_cert, ca_key).unwrap()
}

/// Check if the signature of the certificate is valid. Both the certificate and the issuer are in PEM format.
pub fn check_signature(certificate: &str, issuer: &str) -> bool {
    let der = pem::parse(certificate).unwrap();
    let (_, cert) = X509Certificate::from_der(der.contents()).unwrap();
    let issuer_der = pem::parse(issuer).unwrap();
    let (_, issuer) = X509Certificate::from_der(issuer_der.contents()).unwrap();

    cert.verify_signature(Some(issuer.public_key())).is_ok()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_valid_signed_cert() -> () {
        let (ca_key_pair, ca_cert) = mk_issuer_ca();

        let (client_key_pair, certificate_signing_request) =
            mk_client_certificate_request_params("test@test.com");
        let cert = sign_request(certificate_signing_request, &ca_cert, &ca_key_pair);

        assert!(check_signature(&cert.pem(), &ca_cert.pem()));
    }
}
