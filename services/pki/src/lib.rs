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

use std::path::{self};

use common::crypto::mk_server_certificate;
use common::pki::write_file;
use rcgen::CertifiedKey;

pub mod db;
pub mod server;

/// The path to the server certificate file. It will be created if it does not exist.
const PKI_SERVER_CERT_FILE_PATH: &str = "private/server/server_cert.pem";
/// The path to the server key file. It will be created if it does not exist.
const PKI_SERVER_KEY_FILE_PATH: &str = "private/server/server_keys.pem";

/// The path to the DS (Delivery Service) server certificate file. It will be created if it does not exist.
const DS_CERT_FILE_PATH: &str = "private/ds/ds_cert.pem";
/// The path to the DS (Delivery Service) server key file. It will be created if it does not exist.
const DS_KEY_FILE_PATH: &str = "private/ds/ds_keys.pem";

/// Create and persist the PKI server certificate and key pair.
/// The server certificate is signed by the CA certificate.
/// If the files are present, this is a no-op.
pub fn init_pki_server(ca_ck: &CertifiedKey) {
    init_server(
        ca_ck,
        PKI_SERVER_CERT_FILE_PATH,
        PKI_SERVER_KEY_FILE_PATH,
        "PKI",
    );
}

/// Create and persist the DS (Delivery Service) server certificate and key pair.
/// The server certificate is signed by the CA certificate.
/// If the files are present, this is a no-op.
pub fn init_ds_server(ca_ck: &CertifiedKey) {
    init_server(ca_ck, DS_CERT_FILE_PATH, DS_KEY_FILE_PATH, "DS");
}

fn init_server(
    ca_ck: &CertifiedKey,
    server_cert_file_path: &str,
    server_key_file_path: &str,
    server_name: &str,
) {
    if path::Path::new(server_cert_file_path).exists()
        && path::Path::new(server_key_file_path).exists()
    {
        log::info!(
            "`{}` server certificate found, skipping the generation of the server certificate.",
            server_name
        );
        return;
    } else {
        log::info!("Generating the server certificate for `{}`.", server_name);
    }
    let server_ck = mk_server_certificate(&ca_ck)
        .expect(&format!("Error generating the server `{}` certificate and key pair, cannot proceed without a valid certificate to be used for TLS!", server_name));
    let server_cert_pem = server_ck.cert.pem();
    let server_key_pair_pem = server_ck.key_pair.serialize_pem();
    log::debug!(
        "`{}` server certificate and key pair created and signed by local CA: `{}`,`{}`",
        server_name,
        server_cert_pem,
        server_key_pair_pem
    );
    write_file(server_cert_file_path, &server_cert_pem).expect(&format!(
        "Error writing the server `{}` certificate to the file system.",
        server_name
    ));
    write_file(server_key_file_path, &server_key_pair_pem).expect(&format!(
        "Error writing the server `{}` key pair to the file system.",
        server_name
    ));
}

/// Returns the paths to the PKI server certificate and key pair.
pub fn get_pki_server_credential_paths() -> (String, String) {
    (
        PKI_SERVER_CERT_FILE_PATH.to_string(),
        PKI_SERVER_KEY_FILE_PATH.to_string(),
    )
}

/// Returns the paths to the DS (Delivery Service) server certificate and key pair.
pub fn get_ds_server_credential_paths() -> (String, String) {
    (DS_CERT_FILE_PATH.to_string(), DS_KEY_FILE_PATH.to_string())
}
