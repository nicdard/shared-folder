use std::error::Error;

use log::info;
use pki::crypto::mk_client_certificate_request_params;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let (key_pair, signing_request) = mk_client_certificate_request_params("test@test.com")?;
    info!("Generated key pair: {:?}", key_pair);
    info!("Generated signing request: {:?}", signing_request.pem()?);
    Ok(())
}
