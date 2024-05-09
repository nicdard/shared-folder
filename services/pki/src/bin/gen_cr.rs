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
use std::{env, error::Error, fs};

use log::info;
use pki::crypto::mk_client_certificate_request_params;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let (key_pair, signing_request) = mk_client_certificate_request_params("test@test.com")?;
    info!("Generated key pair: {:?}", key_pair.serialize_pem());
    info!("Generated signing request: {:?}", signing_request.pem()?);
    let _ = env::var("SAVE_TO_FILE").map(|_| {
        fs::write("private/client/key.pem", key_pair.serialize_pem()).unwrap();
        fs::write("private/client/request.pem", signing_request.pem().unwrap()).unwrap();
    });
    Ok(())
}
