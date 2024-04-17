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
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose, Engine as _};
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::crypto::{decrypt, mk_ca_signed_cert};

/// The state of the server, maintains the CA certificate and CA key pair.
pub struct ServerState {
    /// The CA certificate.
    pub ca_cert: X509,
    /// The CA key pair.
    pub ca_key_pair: PKey<Private>,
}

/// Documentation in OpenAPI format.
#[derive(OpenApi)]
#[openapi(
    paths(openapi, register, get_ca_credential, get_credential, verify),
    components(schemas(RegisterRequest, GetCredentialRequest, VerifyRequest))
)]
pub struct OpenApiDoc;

impl OpenApiDoc {
    /// Return the OpenAPI schema.
    pub fn generate() -> String {
        OpenApiDoc::openapi().to_yaml().unwrap()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    email: String,
    /// Base64 encoded certificate request.
    certificate_request: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GetCredentialRequest {
    email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyRequest {
    email: String,
    /// Base64 encoded certificate.
    certificate: String,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Base64 encoded certificate.
    certificate: String,
}

/// Return JSON version of an OpenAPI schema
#[utoipa::path(
    get,
    path = "/api-docs/openapi.json",
    responses(
        (status = 200, description = "JSON file")
    )
)]
pub async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(OpenApiDoc::openapi())
}

/// Register a new client's pk with the CA.
/// The client sends a certificate request, which is decrypted using the CA's private key.
/// The CA verifies that the certificate request contains the email address for which the registration is requested.
/// If the verification is successful, the CA signs the certificate request and returns the signed certificate.
#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registered client."),
        (status = BAD_REQUEST, description = "Client registration failed.", body = RegisterResponse) // Do not specify that the CA contained email address is the problem.
    )
)]
pub async fn register(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let certificate_request = general_purpose::STANDARD
        .decode(&request.certificate_request)
        .unwrap();
    let decrypted_request = decrypt(&certificate_request, &state.ca_key_pair).unwrap();
    let cert_request = X509Req::from_pem(&decrypted_request).unwrap();
    let email: &str = &request.email;
    let contains_email = cert_request.subject_name().entries().any(|entry| {
        if let Ok(data) = entry.data().as_utf8() {
            data.eq(email)
        } else {
            false
        }
    });
    // Verify that the certificate request contains the email address for which the registration is requested.
    if !contains_email {
        return Err(StatusCode::BAD_REQUEST);
    }
    let cert = mk_ca_signed_cert(&state.ca_cert, &state.ca_key_pair, cert_request).unwrap();
    let cert_pem = cert.to_pem().unwrap();
    let response = RegisterResponse {
        certificate: general_purpose::STANDARD.encode(&cert_pem),
    };
    // TODO: Store the certificate in a database or OpenSSL store.
    Ok(Json(response))
}

/// Return the CA's credential.
#[utoipa::path(
    get,
    path = "/get_ca_credential",
    responses(
        (status = 200, description = "CA certificate")
    )
)]
pub async fn get_ca_credential(State(state): State<Arc<ServerState>>) -> Json<Vec<u8>> {
    Json(state.ca_cert.to_pem().unwrap())
}

/// Return the client's credential.
#[utoipa::path(
    get,
    path = "/get_credential",
    responses(
        (status = 200, description = "credential")
    )
)]
pub async fn get_credential() -> Json<Vec<u8>> {
    Json(vec![1, 2, 3])
}

/// Verify a client's credential.
#[utoipa::path(
    post,
    path = "/verify",
    responses(
        (status = 200, description = "Successfully Verified", body = ())
    )
)]
pub async fn verify() -> () {}
