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
use std::sync::{Arc, Mutex};

use log::debug;
use pki::{
    crypto::{mk_issuer_ca, mk_server_certificate},
    server,
};
use rocket::config::{MutualTls, TlsConfig};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// The following constants are used to store the CA certificate and key pair,
/// which are used to sign the certificates.
/// The path to the CA certificate file. It will be created if it does not exist.
const CA_CERT_FILE_PATH: &str = "private/ca/ca_cert.pem";
/// The path to the CA key file. It will be created if it does not exist.
const CA_KEY_FILE_PATH: &str = "private/ca/ca_keys.rsa";

#[rocket::launch]
async fn rocket() -> _ {
    env_logger::init();

    let (ca_key_pair, ca_cert) = mk_issuer_ca();
    let ca_cert_pem = ca_cert.pem();
    // Write the CA certificate and key pair to the file system.
    std::fs::write(CA_CERT_FILE_PATH, &ca_cert_pem).unwrap();
    std::fs::write(CA_KEY_FILE_PATH, &ca_key_pair.serialize_pem()).unwrap();

    let (server_key_pair, server_cert) = mk_server_certificate(&ca_cert, &ca_key_pair);
    let state = server::PkiState::new_server_state(rcgen::CertifiedKey {
        cert: ca_cert,
        key_pair: ca_key_pair,
    });

    debug!(
        "CA certificate and key pair loaded, server TLS keys ready: {}",
        server_cert.pem()
    );

    let shared_state = Arc::new(Mutex::new(state));

    // Set the server TLS configuration to use the certificate signed by our CA for the server.
    // In production, we should request a certificate by let'sencrypt and use our CA only for the clients.
    // Also set our CA certificate as the CA for the mutual TLS.
    let tls_config = TlsConfig::from_bytes(
        server_cert.pem().as_bytes(),
        server_key_pair.serialize_pem().as_bytes(),
    )
    .with_mutual(MutualTls::from_bytes(ca_cert_pem.as_bytes()));
    let figment = rocket::Config::figment()
        .merge((rocket::Config::PORT, 8000))
        .merge((rocket::Config::TLS, tls_config));

    rocket::custom(figment)
        .manage(shared_state)
        .mount(
            "/",
            SwaggerUi::new("/swagger-ui/<_..>")
                .url("/api-docs/openapi.json", server::OpenApiDoc::openapi()),
        )
        .mount(
            "/",
            rocket::routes![
                server::openapi,
                server::get_ca_credential,
                server::get_credential,
                server::register,
                server::verify,
            ],
        )
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use base64::{engine::general_purpose, Engine as _};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use pki::server::{RegisterRequest, RegisterResponse, VerifyRequest};
    use warp::http::StatusCode;
    use warp::test::request;

    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[tokio::test]
    async fn test_wrong_register_format() {
        init();
        //let (ca_cert, ca_key_pair) = mk_ca_cert().unwrap();
        //let server_key_pair = mk_asymmetric_key_pair().unwrap();
        //let cert_request = mk_request(&server_key_pair, "ca-server@test.com").unwrap();
        //let server_cert = mk_ca_signed_cert(&ca_cert, &ca_key_pair, cert_request, true).unwrap();
        //let state =
        //    server::PkiState::new_server_state(ca_cert, ca_key_pair, server_cert, server_key_pair);
        //let shared_state = Arc::new(Mutex::new(state));
        //let config = Arc::new(Config::from("/api-doc.json"));
        //
        //let api = server::handlers(shared_state, config);
        //let in_certificate = "wrong@email.com";
        //let email = "test@test.com";
        //let register_request = certificate_request(in_certificate, email).unwrap();
        //
        //let resp = request()
        //    .method("POST")
        //    .path("/ca/register")
        //    .json(&register_request)
        //    .reply(&api)
        //    .await;
        //
        //assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_and_verify() {
        //init();
        //let (ca_cert, ca_key_pair) = mk_ca_cert().unwrap();
        //let server_key_pair = mk_asymmetric_key_pair().unwrap();
        //let cert_request = mk_request(&server_key_pair, "ca-server@test.com").unwrap();
        //let server_cert = mk_ca_signed_cert(&ca_cert, &ca_key_pair, cert_request, true).unwrap();
        //let state =
        //    server::PkiState::new_server_state(ca_cert, ca_key_pair, server_cert, server_key_pair);
        //let shared_state = Arc::new(Mutex::new(state));
        //let config = Arc::new(Config::from("/api-doc.json"));
        //
        //        let api = server::handlers(shared_state, config);
        //let email = "test@test.com";
        //let register_request = certificate_request(&email, &email).unwrap();
        //
        //        let resp = request()
        //    .method("POST")
        //    .path("/ca/register")
        //    .json(&register_request)
        //    .reply(&api)
        //    .await;
        //let v = resp.body().to_vec();
        //let register_response = serde_json::from_slice::<RegisterResponse>(&v).unwrap();
        //
        //        assert_eq!(resp.status(), StatusCode::CREATED);
        //
        //        let resp = request()
        //    .method("POST")
        //    .path("/ca/verify")
        //    .json(&VerifyRequest {
        //        certificate: register_response.certificate,
        //    })
        //    .reply(&api)
        //    .await;
        //
        //        assert_eq!(resp.status(), StatusCode::OK);
    }

    // fn certificate_request(
    //     in_certificate: &str,
    //     email: &str,
    // ) -> Result<RegisterRequest, Box<dyn Error>> {
    //     let rsa = Rsa::generate(2048)?;
    //     let key_pair = PKey::from_rsa(rsa)?;
    //     let request = mk_request(&key_pair, in_certificate)?;
    //     let request_pem = request.to_pem()?;
    //     Ok(RegisterRequest {
    //         certificate_request: general_purpose::STANDARD.encode(&request_pem),
    //         email: String::from(email),
    //     })
    // }
}
