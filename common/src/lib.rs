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
use crypto::{
    check_signature, mk_client_certificate_request_params, retrieve_der_pk_from_certificate,
    retrieve_emails_from_certificate,
};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

pub mod crypto;
pub mod pki;
mod utils;

// Less efficient allocator than the default one which however is super small, only 1K in code size (compared to ~10K)
cfg_if! {
    if #[cfg(feature = "wee_alloc")] {
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

/*
#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);
}
*/

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
pub fn mk_client_certificate_request_params_binding(
    email: &str,
) -> Result<ClientCertificateRequest, String> {
    set_panic_hook();
    let (key_pair, params) =
        mk_client_certificate_request_params(email).map_err(|e| e.to_string())?;
    let signing_request = params.pem().map_err(|e| e.to_string())?;
    Ok(ClientCertificateRequest {
        key_pair: key_pair.serialize_pem(),
        signing_request,
    })
}

#[wasm_bindgen(js_name = verifyCertificate)]
/// Validate a certificate against an issuer certificate (A CA certificate).
pub fn verify_certificate(certificate: &str, issuer: &str) -> bool {
    set_panic_hook();
    let is_valid = check_signature(certificate, issuer).map_err(|e| e.to_string());
    if let Ok(valid) = is_valid {
        valid
    } else {
        false
    }
}

#[wasm_bindgen(js_name = parseEmailsFromCertificate)]
/// Retrieves all emails from a certificate. Can throw exception if a deserialization error occours.
pub fn parse_email_from_certificate(certificate: &str) -> Result<Vec<String>, String> {
    set_panic_hook();
    retrieve_emails_from_certificate(certificate)
}

#[wasm_bindgen(js_name = parseDERPkFromCertificate)]
/// Retrieves the public key raw bytes.
/// A raw unparsed PKIX, ASN.1 DER form (see RFC 5280, Section 4.1).
pub fn parse_der_pk_from_certificate(certificate: &str) -> Result<Vec<u8>, String> {
    set_panic_hook();
    retrieve_der_pk_from_certificate(certificate)
}
