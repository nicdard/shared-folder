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
    Certificate, CertificateParams, CertificateSigningRequest, CertificateSigningRequestParams,
    CertifiedKey, Error, KeyPair, SanType,
};
use x509_parser::{
    certificate::X509Certificate, der_parser::asn1_rs::FromDer, extensions::GeneralName,
};

/// Load a CA certificate and key pair from PEM strings.
/// This can be used to load the CA certificate and key pair from files to maintain the state of the CA after the server is restarted.
/// See [`from_ca_cert_der`](rcgen::CertificateParams::from_ca_cert_der) for more details.
/// In general this function only extracts the information needed for signing.
/// Other attributes of the [`Certificate`] may be left as defaults.
pub fn load_ca_and_sign_cert(
    ca_cert_pem: &str,
    ca_key_pair_pem: &str,
) -> Result<CertifiedKey, Error> {
    let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_key_pair = KeyPair::from_pem(ca_key_pair_pem)?;
    let cert = params.self_signed(&ca_key_pair)?;
    Ok(CertifiedKey {
        key_pair: ca_key_pair,
        cert,
    })
}

/// Create a client certificate and private key signed by the given CA.
pub fn mk_client_certificate(ca_certified_key: &CertifiedKey) -> Result<CertifiedKey, Error> {
    // Create a client end entity cert issued by the CA.
    let mut client_ee_params = rcgen::CertificateParams::new(Vec::new())?;
    client_ee_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example Client");
    client_ee_params.is_ca = rcgen::IsCa::NoCa;
    client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    // TODO: Set the serial number to respect uniqueness requirements: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
    client_ee_params.serial_number = Some(rcgen::SerialNumber::from(vec![0xC0, 0xFF, 0xEE]));
    let client_key = mk_ee_key_pair()?;
    let client_cert = client_ee_params.signed_by(
        &client_key,
        &ca_certified_key.cert,
        &ca_certified_key.key_pair,
    )?;
    Ok(CertifiedKey {
        key_pair: client_key,
        cert: client_cert,
    })
}

/// Create a server certificate and private key signed by the given CA.
pub fn mk_server_certificate(ca_certified_key: &CertifiedKey) -> Result<CertifiedKey, Error> {
    // Create a server end entity cert issued by the CA.
    let mut server_ee_params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])?;
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let ee_key = mk_ee_key_pair()?;
    let server_cert =
        server_ee_params.signed_by(&ee_key, &ca_certified_key.cert, &ca_certified_key.key_pair)?;
    Ok(CertifiedKey {
        key_pair: ee_key,
        cert: server_cert,
    })
}

/// Create an issuing CA certificate and private key.
pub fn mk_issuer_ca() -> Result<CertifiedKey, Error> {
    let ca_key = mk_ee_key_pair()?;
    let ca_cert = mk_issuer_ca_from_keys(&ca_key)?;
    Ok(CertifiedKey {
        key_pair: ca_key,
        cert: ca_cert,
    })
}

/// Create an issuing CA certificate from the given key pair.
pub fn mk_issuer_ca_from_keys(key_pair: &KeyPair) -> Result<Certificate, Error> {
    // Create an issuing CA cert.
    let mut ca_params = rcgen::CertificateParams::new(Vec::new())?;
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
    let ca_cert = ca_params.self_signed(key_pair)?;
    Ok(ca_cert)
}

/// Create a new client certificate request with the given email address.
/// The email is represented in the certificate as a Subject alt name as in RFC5280.
/// See [`Rfc822Name`](rcgen::SanType::Rfc822Name) for more details.
pub fn mk_client_certificate_request_params(
    email: &str,
) -> Result<(KeyPair, CertificateSigningRequest), Error> {
    let key_pair = mk_ee_key_pair()?;
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::Rfc822Name(email.try_into()?)];
    let certificate_request = params.serialize_request(&key_pair)?;
    Ok((key_pair, certificate_request))
}

pub fn mk_ee_key_pair() -> Result<KeyPair, Error> {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
}

/// Sign the given certificate signing request.
pub fn sign_request(
    signing_request: CertificateSigningRequest,
    ca_certified_key: &CertifiedKey,
) -> Result<Certificate, Error> {
    let params = CertificateSigningRequestParams::from_pem(&signing_request.pem()?)?;
    params.signed_by(&ca_certified_key.cert, &ca_certified_key.key_pair)
}

/// Sing the given certificate signing request from a PEM string.
pub fn sign_request_from_pem(
    signing_request_pem: &str,
    ca_certified_key: &CertifiedKey,
) -> Result<Certificate, Error> {
    let params = CertificateSigningRequestParams::from_pem(signing_request_pem)?;
    params.signed_by(&ca_certified_key.cert, &ca_certified_key.key_pair)
}

/// Sign the given certificate signing request from a PEM string and check if the email is valid.
/// The email is checked against the Subject alt names in the certificate signing request.
pub fn sign_request_from_pem_and_check_email(
    signing_request_pem: &str,
    ca_certified_key: &CertifiedKey,
    email: &str,
) -> Result<Certificate, Error> {
    let params = CertificateSigningRequestParams::from_pem(signing_request_pem)?;
    let validate_email = params.params.subject_alt_names.iter().any(|san| {
        if let SanType::Rfc822Name(s) = san {
            return s.as_str() == email;
        }
        false
    });
    if !validate_email {
        return Err(Error::InvalidNameType);
    } else {
        sign_request_from_pem(signing_request_pem, ca_certified_key)
    }
}

/// Retrieves all emails from a PEM-encoded Certificate (using [`x509_parser`]).
pub fn retrieve_emails_from_certificate(pem_certificate: &str) -> Result<Vec<String>, String> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem_certificate.as_bytes()).map_err(|e| e.to_string())?;
    let x509_certificate = pem.parse_x509().map_err(|e| e.to_string())?;
    let emails = retrieve_emails_from_x509_certificate(x509_certificate);
    Ok(emails)
}

/// Retrieves all emails from a Certificate (using [`x509_parser`]).
pub fn retrieve_emails_from_x509_certificate(x509_certificate: X509Certificate) -> Vec<String> {
    x509_certificate
        .subject_alternative_name()
        .iter()
        .filter_map(|san| match san {
            Some(san) => Some(san.value.general_names.iter().filter_map(
                |gn: &GeneralName| match gn {
                    GeneralName::RFC822Name(email) => Some(email),
                    _ => None,
                },
            )),
            None => None,
        })
        .flatten()
        .map(|e| e.to_string())
        .collect()
}

/// Check if the signature of the certificate is valid. Both the certificate and the issuer are in PEM format.
pub fn check_signature(
    certificate: &str,
    issuer: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let der = pem::parse(certificate)?;
    let (_, cert) = X509Certificate::from_der(der.contents())?;
    let issuer_der = pem::parse(issuer)?;
    let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

    Ok::<bool, Box<dyn std::error::Error>>(cert.verify_signature(Some(issuer.public_key())).is_ok())
}

pub fn retrieve_der_pk_from_certificate(pem_certificate: &str) -> Result<Vec<u8>, String> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem_certificate.as_bytes()).map_err(|e| e.to_string())?;
    let x509_certificate = pem.parse_x509().map_err(|e| e.to_string())?;
    Ok(retrieve_der_pk_from_x509_certificate(x509_certificate))
}

pub fn retrieve_der_pk_from_x509_certificate(x509_certificate: X509Certificate) -> Vec<u8> {
    let pk = x509_certificate.public_key().raw;
    pk.to_vec()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_valid_signed_cert() -> Result<(), Error> {
        let issuer = mk_issuer_ca()?;

        let (_, certificate_signing_request) =
            mk_client_certificate_request_params("test@test.com")?;
        let cert = sign_request(certificate_signing_request, &issuer)?;

        assert!(check_signature(&cert.pem(), &issuer.cert.pem()).is_ok());
        Ok(())
    }

    #[test]
    fn check_signature_with_loaded_ca_cert() -> Result<(), Error> {
        let ca_certified_key = mk_issuer_ca()?;
        // Load the CA cert and key pair from PEM strings.
        let loaded_ca_cert = load_ca_and_sign_cert(
            &ca_certified_key.cert.pem(),
            &ca_certified_key.key_pair.serialize_pem(),
        )?;
        // Sign a client certificate with the original CA cert and key pair.
        let client_cert = mk_client_certificate(&ca_certified_key)?;
        let server_cert = mk_server_certificate(&ca_certified_key)?;

        assert!(check_signature(&client_cert.cert.pem(), &loaded_ca_cert.cert.pem()).is_ok());
        assert!(check_signature(&server_cert.cert.pem(), &loaded_ca_cert.cert.pem()).is_ok());
        Ok(())
    }

    #[test]
    fn sign_with_loaded_ca_cert() -> Result<(), Error> {
        let ca_certified_key = mk_issuer_ca()?;
        // Load the CA cert and key pair from PEM strings.
        let loaded_ca_cert = load_ca_and_sign_cert(
            &ca_certified_key.cert.pem(),
            &ca_certified_key.key_pair.serialize_pem(),
        )?;
        // Sign a client certificate with the loaded CA cert and key pair.
        let client_cert = mk_client_certificate(&loaded_ca_cert)?;
        let server_cert = mk_server_certificate(&loaded_ca_cert)?;

        assert!(check_signature(&client_cert.cert.pem(), &ca_certified_key.cert.pem()).is_ok());
        assert!(check_signature(&server_cert.cert.pem(), &ca_certified_key.cert.pem()).is_ok());
        Ok(())
    }
}
