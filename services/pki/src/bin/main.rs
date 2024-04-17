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
use std::{net::SocketAddr, path::Path, sync::Arc};

use axum::{
    routing::{get, post},
    Error, Router,
};
use openssl::{pkey::PKey, x509::X509};
use pki::server::{get_ca_credential, get_credential, register, verify, OpenApiDoc};
use pki::{crypto::mk_ca_cert, server::ServerState};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// The path to the CA certificate file. It will be created if it does not exist.
const CA_CERT_FILE_PATH: &str = "private/ca_cert.pem";
/// The path to the CA private key file. It will be created if it does not exist.
const CA_KEY_FILE_PATH: &str = "private/ca_key.pem";
/// The path to the CA public key file. It will be created if it does not exist.
const CA_PUBLIC_KEY_FILE_PATH: &str = "public/ca_public_key.pem";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let existing_ca = std::fs::read(Path::new(CA_CERT_FILE_PATH));
    let state = match existing_ca {
        Ok(ca_cert_pem) => ServerState {
            ca_cert: X509::from_pem(&ca_cert_pem).unwrap(),
            ca_key_pair: PKey::private_key_from_pem(
                &std::fs::read(Path::new(CA_KEY_FILE_PATH)).unwrap(),
            )
            .unwrap(),
        },
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
            ServerState {
                ca_cert,
                ca_key_pair,
            }
        }
    };

    let shared_state = Arc::new(state);

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "CA here!" }))
        .route("/register", post(register))
        .route("/get_credential", get(get_credential))
        .route("/verify", post(verify))
        .route("/get_ca_credential", get(get_ca_credential))
        .with_state(shared_state)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", OpenApiDoc::openapi()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
