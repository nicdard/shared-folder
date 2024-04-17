use std::error::Error;

use base64::{engine::general_purpose, Engine as _};
use openssl::{pkey::PKey, rsa::Rsa};
use pki::crypto::{encrypt, mk_request};

fn main() -> Result<(), Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;
    let request = mk_request(&key_pair, "test@test.com")?;
    let request_pem = request.to_pem()?;
    let ca_pk_pem = std::fs::read("public/ca_public_key.pem")?;
    let ca_pk = PKey::public_key_from_pem(&ca_pk_pem)?;
    let encrypted_request_pem = encrypt(&request_pem, &ca_pk)?;
    let base64_encoded_request = general_purpose::STANDARD.encode(&encrypted_request_pem);
    std::fs::write("public/test_request", base64_encoded_request)?;
    Ok(())
}
