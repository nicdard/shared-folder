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
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    encrypt::{Decrypter, Encrypter},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private, Public},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509,
    },
};

/// The number of bits for the RSA key pair.
const RSA_BITS: u32 = 2048;

/// (Asymmetric) Decrypt the given data using the given private key.
pub fn decrypt(from: &[u8], key_pair: &PKey<Private>) -> Result<Vec<u8>, ErrorStack> {
    let decrypter = Decrypter::new(&key_pair)?;
    let plain_text_len = decrypter.decrypt_len(&from)?;
    let mut plain_text = vec![0u8; plain_text_len];
    let decrypted_len = decrypter.decrypt(&from, &mut plain_text)?;
    Ok(plain_text[..decrypted_len].to_vec())
}

/// (Asymmetric) Encrypt the given data using the given public key.
pub fn encrypt(from: &[u8], key_pair: &PKey<Public>) -> Result<Vec<u8>, ErrorStack> {
    let encrypter = Encrypter::new(&key_pair)?;
    let cipher_text_len = encrypter.encrypt_len(&from)?;
    let mut cipher_text = vec![0u8; cipher_text_len];
    let encrypted_len = encrypter.encrypt(&from, &mut cipher_text)?;
    Ok(cipher_text[..encrypted_len].to_vec())
}

/// Make a CA certificate and private key
/// Taken from: https://github.com/sfackler/rust-openssl/blob/master/openssl/examples/mk_certs.rs
pub fn mk_ca_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let key_pair = mk_asymmetric_key_pair()?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some CA organization")?;
    x509_name.append_entry_by_text("CN", "ca test")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;
    // Set that this is the certificate of a CA.
    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

/// Make a certificate from a certificate request signed by the given CA cert.
/// Inspired from: https://github.com/sfackler/rust-openssl/blob/master/openssl/examples/mk_certs.rs
pub fn mk_ca_signed_cert(
    ca_cert: &X509Ref,
    ca_key_pair: &PKeyRef<Private>,
    cert_request: X509Req,
) -> Result<X509, ErrorStack> {
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(cert_request.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    // Extract the public key from the request.
    let key_pair = cert_request.public_key()?;
    cert_builder.set_pubkey(key_pair.as_ref())?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    // Set a default expiration date of 1 year.
    // let not_after = Asn1Time::days_from_now(365)?;
    // cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    // let subject_alt_name = SubjectAlternativeName::new()
    //     .email(subject_email)
    //     .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    // cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

/// Make a X509 request with the given private key
/// Inspired from: https://github.com/sfackler/rust-openssl/blob/master/openssl/examples/mk_certs.rs
pub fn mk_request(key_pair: &PKey<Private>, email_address: &str) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;

    let mut x509_name = X509NameBuilder::new()?;
    // Add a fiex country code, state, organization and common name
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some organization")?;
    x509_name.append_entry_by_text("CN", "www.baseline.com")?;
    x509_name.append_entry_by_text("emailAddress", email_address)?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

pub fn mk_asymmetric_key_pair() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(RSA_BITS)?;
    PKey::from_rsa(rsa)
}

#[cfg(test)]
mod tests {

    use openssl::x509::X509VerifyResult;

    use super::*;

    #[test]
    fn test_valid_signed_cert() -> Result<(), ErrorStack> {
        let (ca_cert, ca_key_pair) = mk_ca_cert()?;
        let key_pair = mk_asymmetric_key_pair()?;
        let request = mk_request(&key_pair, "test@test.com")?;
        let cert = mk_ca_signed_cert(&ca_cert, &ca_key_pair, request)?;

        // Verify that this cert was issued by this ca
        match ca_cert.issued(&cert) {
            X509VerifyResult::OK => println!("Certificate verified!"),
            ver_err => println!("Failed to verify certificate: {}", ver_err),
        };

        Ok(())
    }
}
