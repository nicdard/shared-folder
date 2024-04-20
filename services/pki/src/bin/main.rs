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
    path::PathBuf,
    sync::{Arc, Mutex},
};

use pki::{
    crypto::{load_ca_and_sign_cert, mk_issuer_ca, mk_server_certificate},
    db, server,
};
use rcgen::CertifiedKey;
use rocket::{
    config::{MutualTls, TlsConfig},
    figment::providers::{Format, Toml},
};
use rocket_db_pools::Database;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// The following constants are used to store the CA certificate and key pair,
/// which are used to sign the certificates.
/// The path to the CA certificate file. It will be created if it does not exist.
const CA_CERT_FILE_PATH: &str = "private/ca/ca_cert.pem";
/// The path to the CA key file. It will be created if it does not exist.
const CA_KEY_FILE_PATH: &str = "private/ca/ca_keys.rsa";

/// Initialise the CA certificate and key pair.
/// If the files are present, load the CA certificate and key pair from the files.
/// If the files are not present, generate a new CA certificate and key pair.
fn init_ca() -> CertifiedKey {
    // Check for existing CA certificate and key pair.
    let ca_cert_pem = std::fs::read_to_string(CA_CERT_FILE_PATH).inspect_err(|e| {
        log::info!(
            "Couldn't read the CA certificate from file `{}`: `{}`",
            CA_CERT_FILE_PATH,
            e
        )
    });
    let ca_key_pair_pem = std::fs::read_to_string(CA_KEY_FILE_PATH).inspect_err(|e| {
        log::info!(
            "Couldn't read the CA key pair from file `{}`: `{}`",
            CA_KEY_FILE_PATH,
            e
        )
    });
    let (ca_ck, fresh_certificate) = match (ca_cert_pem, ca_key_pair_pem) {
        (Ok(ca_cert_pem), Ok(ca_key_pair_pem)) => {
            load_ca_and_sign_cert(&ca_cert_pem, &ca_key_pair_pem).inspect_err(|e| {
                log::error!("Couldn't load the old CA certificate and key pair: `{}`, generate a new pair. 
                If you need them to debug, a backup of the files has been made and saved in the same location (.bkp)", e);
                let mut path = PathBuf::from(CA_CERT_FILE_PATH);
                path.push(".bkp");
                let _ = std::fs::write(path, &ca_cert_pem);
            })
            .map(|ca_ck| (ca_ck, false))
            .unwrap_or((mk_issuer_ca().expect("Error generating fresh CA certificate and key pair!"), true))
        }
        _ => {
            log::info!("Generating a new CA certificate and key pair.");
            (mk_issuer_ca().expect("Error generating the CA certificate and key pair!"), true)
        }
    };
    // Write the CA certificate and key pair to the file system. It's not considered a fatal error if the
    // files cannot be written to disk as we can still obtain the CA certificate from the REST endpoint.
    if fresh_certificate {
        log::debug!("Writing the new CA certificate and key pair to the files.");
        let r2 = std::fs::write(CA_CERT_FILE_PATH, ca_ck.cert.pem());
        let r1 = std::fs::write(CA_KEY_FILE_PATH, ca_ck.key_pair.serialize_pem());
        if r1.is_err() || r2.is_err() {
            log::warn!("Couldn't write the new CA credentials to the files, after restarting the server all the certficates issued to the clients' will become invalid!",);
        }
    } else {
        log::debug!(
            "The CA certificate and key pair were loaded from the files `{}` `{}`.",
            CA_CERT_FILE_PATH,
            CA_KEY_FILE_PATH
        );
    }
    ca_ck
}

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
    let server_ck = mk_server_certificate(&ca_ck)
        .expect("Error generating the server certificate and key pair!");
    let server_cert_pem = server_ck.cert.pem();
    let server_key_pair_pem = server_ck.key_pair.serialize_pem();
    log::debug!(
        "Server certificate and key pair created and signed by local CA: `{}`,`{}`",
        server_cert_pem,
        server_key_pair_pem
    );

    // The CA server needs the CA certificate and key pair to sign the certificates and verify them.
    let state = server::PkiState::new(ca_ck);

    // Create the state for the server to be used in the handlers. This holds the CA certificates as well
    // as the storage for the certificates that are issued by the CA.
    let shared_state = Arc::new(Mutex::new(state));

    // Set the server TLS configuration to use the certificate signed by our CA for the server.
    // In production, we should request a certificate by let'sencrypt and use our CA only for the clients.
    // Also set our CA certificate as the CA for the mutual TLS.
    let tls_config =
        TlsConfig::from_bytes(server_cert_pem.as_bytes(), server_key_pair_pem.as_bytes())
            .with_mutual(MutualTls::from_bytes(ca_cert_pem.as_bytes()));
    let figment = rocket::Config::figment()
        // Load the configuration file for the PKI server.
        .merge(Toml::file("PKI_Rocket.toml").nested())
        .merge((rocket::Config::PORT, 8000))
        .merge((rocket::Config::TLS, tls_config));

    // Initialise the rocket server also mounting the swagger-ui.
    rocket::custom(figment)
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
