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
    error, fs,
    path::{self, PathBuf},
};

use rcgen::CertifiedKey;

use crate::crypto::{load_ca_and_sign_cert, mk_issuer_ca};

/// The following constants are used to store the CA certificate and key pair,
/// which are used to sign the certificates.
/// The path to the CA certificate file. It will be created if it does not exist.
const CA_CERT_FILE_PATH: &str = "private/ca/ca_cert.pem";
/// The path to the CA key file. It will be created if it does not exist.
const CA_KEY_FILE_PATH: &str = "private/ca/ca_keys.pem";

/// Initialise the CA certificate and key pair.
/// If the files are present, load the CA certificate and key pair from the files.
/// If the files are not present, generate a new CA certificate and key pair.
pub fn init_ca() -> CertifiedKey {
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
                let _ = backup_file(CA_CERT_FILE_PATH);
                let _ = backup_file(CA_KEY_FILE_PATH);
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
        let r2 = write_file(CA_CERT_FILE_PATH, &ca_ck.cert.pem());
        let r1 = write_file(CA_KEY_FILE_PATH, &ca_ck.key_pair.serialize_pem());
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

/// Backup the file at the given path.
/// The backup file will be created in the same directory as the original file, with the same name, and the added extension `.bkp`.
pub fn backup_file(file_path: &str) -> Result<(), Box<dyn error::Error>> {
    // Backup the file
    let mut path = PathBuf::from(file_path);
    path.push(".bkp");
    write_file(file_path, &fs::read_to_string(file_path)?)?;
    Ok(())
}

/// Write the content to the file at the given path creating all intermediate folders.
pub fn write_file(file_path: &str, content: &str) -> Result<(), Box<dyn error::Error>> {
    let file_path = path::PathBuf::from(file_path);
    let dir = file_path.parent().expect("Couln't remove the file name.");
    fs::create_dir_all(dir)?;
    fs::write(file_path, content)?;
    Ok(())
}

/// Returns the paths to the CA certificate and key pair.
pub fn get_ca_credential_paths() -> (String, String) {
    (CA_CERT_FILE_PATH.to_string(), CA_KEY_FILE_PATH.to_string())
}
