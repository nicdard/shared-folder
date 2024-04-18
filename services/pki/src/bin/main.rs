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
use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use log::info;
use openssl::{pkey::PKey, x509::X509};
use pki::crypto::mk_ca_cert;
use pki::server::{self, new_server_state};
use tokio::{signal::ctrl_c, sync::oneshot};
use utoipa_swagger_ui::Config;

/// The path to the CA certificate file. It will be created if it does not exist.
const CA_CERT_FILE_PATH: &str = "private/ca_cert.pem";
/// The path to the CA private key file. It will be created if it does not exist.
const CA_KEY_FILE_PATH: &str = "private/ca_key.rsa";
/// The path to the CA public key file. It will be created if it does not exist.
const CA_PUBLIC_KEY_FILE_PATH: &str = "public/ca_public_key.pem";

// https://github.com/Azure/warp-openssl/blob/main/examples/server.rs
#[tokio::main]
async fn main() -> () {
    env_logger::init();

    let existing_ca = std::fs::read(Path::new(CA_CERT_FILE_PATH));
    let state = match existing_ca {
        Ok(ca_cert_pem) => {
            let ca_cert = X509::from_pem(&ca_cert_pem).unwrap();
            let ca_key_pair =
                PKey::private_key_from_pem(&std::fs::read(Path::new(CA_KEY_FILE_PATH)).unwrap())
                    .unwrap();
            new_server_state(ca_cert, ca_key_pair)
        }
        Err(_) => {
            let (ca_cert, ca_key_pair) = mk_ca_cert().unwrap();
            let ca_cert_pem = ca_cert.to_pem().unwrap();
            let ca_key_pem = ca_key_pair.private_key_to_pem_pkcs8().unwrap();
            let ca_pk_key_pem = ca_key_pair.public_key_to_pem().unwrap();
            // std::fs::create_dir_all("private").unwrap();
            // std::fs::create_dir_all("public").unwrap();
            std::fs::write(CA_CERT_FILE_PATH, ca_cert_pem).unwrap();
            std::fs::write(CA_KEY_FILE_PATH, ca_key_pem).unwrap();
            std::fs::write(CA_PUBLIC_KEY_FILE_PATH, ca_pk_key_pem).unwrap();
            new_server_state(ca_cert, ca_key_pair)
        }
    };

    //info!("CA certificate and key pair loaded {state:?}");

    let config = Arc::new(Config::from("/api-doc.json"));
    let ca_cert = state.ca_cert.clone();
    let ca_key_pair = state.ca_key_pair.clone();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    let shared_state = Arc::new(Mutex::new(state));

    let server = warp_openssl::serve(server::handlers(shared_state, config))
        .cert(ca_cert.to_pem().unwrap())
        .key(&ca_key_pair.private_key_to_pem_pkcs8().unwrap());

    let (tx, rx) = oneshot::channel::<()>();
    let (addr, server) = server
        .bind_with_graceful_shutdown(addr, async move {
            rx.await.ok();
        })
        .unwrap();
    let server = tokio::spawn(async move {
        server.await;
    });

    info!("Server listening on {}. Press a key to exit", addr);
    ctrl_c().await.unwrap();

    tx.send(()).unwrap();
    server.await.unwrap();
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use base64::{engine::general_purpose, Engine as _};
    use openssl::rsa::Rsa;
    use pki::crypto::mk_request;
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
        let (ca_cert, ca_key_pair) = mk_ca_cert().unwrap();
        let state = new_server_state(ca_cert, ca_key_pair);
        let shared_state = Arc::new(Mutex::new(state));
        let config = Arc::new(Config::from("/api-doc.json"));

        let api = server::handlers(shared_state, config);
        let in_certificate = "wrong@email.com";
        let email = "test@test.com";
        let register_request = certificate_request(in_certificate, email).unwrap();

        let resp = request()
            .method("POST")
            .path("/ca/register")
            .json(&register_request)
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_and_verify() {
        init();
        let (ca_cert, ca_key_pair) = mk_ca_cert().unwrap();
        let state = new_server_state(ca_cert, ca_key_pair);
        let shared_state = Arc::new(Mutex::new(state));
        let config = Arc::new(Config::from("/api-doc.json"));

        let api = server::handlers(shared_state, config);
        let email = "test@test.com";
        let register_request = certificate_request(&email, &email).unwrap();

        let resp = request()
            .method("POST")
            .path("/ca/register")
            .json(&register_request)
            .reply(&api)
            .await;
        let v = resp.body().to_vec();
        let register_response = serde_json::from_slice::<RegisterResponse>(&v).unwrap();

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = request()
            .method("POST")
            .path("/ca/verify")
            .json(&VerifyRequest {
                certificate: register_response.certificate,
            })
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn certificate_request(
        in_certificate: &str,
        email: &str,
    ) -> Result<RegisterRequest, Box<dyn Error>> {
        let rsa = Rsa::generate(2048)?;
        let key_pair = PKey::from_rsa(rsa)?;
        let request = mk_request(&key_pair, in_certificate)?;
        let request_pem = request.to_pem()?;
        Ok(RegisterRequest {
            certificate_request: general_purpose::STANDARD.encode(&request_pem),
            email: String::from(email),
        })
    }
}
