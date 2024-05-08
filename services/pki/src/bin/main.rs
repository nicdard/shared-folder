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

use pki::{db, get_pki_server_credential_paths, init_ca, init_ds_server, init_pki_server, server};
use rocket::{
    config::{MutualTls, TlsConfig},
    figment::providers::{Format, Toml},
};
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_db_pools::Database;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// The entry point of the CA server.
/// The server is a REST API that allows clients to register and verify their certificates.
/// It requires TLS and can be configured with some endpoints protected with mutual TLS.
/// See [`Certificate`](rocket::mtls::Certificate) for more information.
#[rocket::launch]
fn rocket() -> _ {
    env_logger::init();
    // Generate the CA certificate and key pair. Those are used to sign the certificates.
    // The server tries to store those certificates in the file system to be able to recover them
    // if the server is restarted.
    let ca_ck = init_ca();
    let ca_cert_pem = ca_ck.cert.pem();

    // Generate the server certificate and key pair. Those are used to setup the TLS connection.
    // The server certificate is signed by the CA certificate and can be lost if the server is restarted.
    init_pki_server(&ca_ck);

    // Generate the DS (Delivery Service) server keys.
    init_ds_server(&ca_ck);

    // The CA server needs the CA certificate and key pair to sign the certificates and verify them.
    let state = server::PkiState::new(ca_ck);

    // Create the state for the server to be used in the handlers. This holds the CA certificates as well
    // as the storage for the certificates that are issued by the CA.
    let shared_state = Arc::new(Mutex::new(state));

    // Set the server TLS configuration to use the certificate signed by our CA for the server.
    // In production, we should request a certificate by let'sencrypt and use our CA only for the clients.
    // Also set our CA certificate as the CA for the mutual TLS.
    let (pki_server_cert_path, pki_server_keys_path) = get_pki_server_credential_paths();
    let tls_config = TlsConfig::from_paths(pki_server_cert_path, pki_server_keys_path)
        .with_mutual(MutualTls::from_bytes(ca_cert_pem.as_bytes()));
    let figment = rocket::Config::figment()
        // Load the configuration file for the PKI server.
        .merge(Toml::file("PKI_Rocket.toml").nested())
        .merge((rocket::Config::TLS, tls_config));

    // TODO: configure through env variables.
    let other_servers = vec![
        "https://localhost:8000",
        "https://localhost:8001",
        "http://localhost:3000",
    ];
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::some_exact(&other_servers))
        .to_cors()
        .expect("The CORS configuration is invalid.");

    // Initialise the rocket server also mounting the swagger-ui.
    rocket::custom(figment)
        .attach(cors)
        .attach(db::DbConn::init())
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
