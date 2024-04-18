use std::error::Error;

use base64::{engine::general_purpose, Engine as _};
use openssl::{pkey::PKey, rsa::Rsa};
use pki::crypto::mk_request;

fn main() -> Result<(), Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;
    let request = mk_request(&key_pair, "test@test.com")?;
    let request_pem = request.to_pem()?;
    let base64_encoded_request = general_purpose::STANDARD.encode(&request_pem);
    std::fs::write("public/test_request", base64_encoded_request)?;
    Ok(())
}
