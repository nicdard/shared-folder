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
use cfg_if::cfg_if;
use rcgen::{CertificateParams, KeyPair, SanType};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

mod utils;

// Less efficient allocator than the default one which however is super small, only 1K in code size (compared to ~10K)
cfg_if! {
    if #[cfg(feature = "wee_alloc")] {
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

/// Represent a client certificate request with the private key that was used to generate it.
#[wasm_bindgen(getter_with_clone)]
pub struct ClientCertificateRequest {
    #[wasm_bindgen(js_name = keyPair)]
    pub key_pair: String,
    #[wasm_bindgen(js_name = signingRequest)]
    pub signing_request: String,
}

#[wasm_bindgen(js_name = mkClientCertificateRequestParams)]
/// Create a new client certificate request with the given email address.
/// The email is represented in the certificate as a Subject alt name as in RFC882.
/// See [`Rfc822Name`](rcgen::SanType::Rfc822Name) for more details.
pub fn mk_client_certificate_request_params(email: &str) -> ClientCertificateRequest {
    set_panic_hook();
    let key_pair = mk_ee_key_pair();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::Rfc822Name(
        email.try_into().expect("Invalid email"),
    )];
    let certificate_request = params
        .serialize_request(&key_pair)
        .expect("Failed to serialize request")
        .pem()
        .expect("Failed to serialize request to PEM");
    ClientCertificateRequest {
        key_pair: key_pair.serialize_pem(),
        signing_request: certificate_request,
    }
}

fn mk_ee_key_pair() -> KeyPair {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("Failed to generate key pair using ECDSA_P256_SHA256")
}
