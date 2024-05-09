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

use common::crypto::{check_signature, sign_request_from_pem_and_check_email};
use rocket::{
    get, post,
    response::status::{BadRequest, Conflict, Created, NotFound},
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::db::{get_certificate_by_email, insert_certificate, DbConnection};

/// The state of the server, maintains the CA certificate and CA key pair.
pub struct PkiState {
    /// The CA certificate and key pair used to sign and verify the clients' certificates.
    pub(crate) ca_cert: rcgen::CertifiedKey,
}

/// Implementation of the ServerState.
impl PkiState {
    /// Create a new server state. Consume the CA certificate and key pair permissions.
    pub fn new(ca_cert: rcgen::CertifiedKey) -> Self {
        PkiState { ca_cert }
    }
}

/// The type of the server state wrapped in an Arc and a Mutex.
pub type ServerStateArc = Arc<Mutex<PkiState>>;

/// Documentation in OpenAPI format.
#[derive(OpenApi)]
#[openapi(
    paths(openapi, register, get_ca_credential, get_credential, verify),
    components(schemas(
        RegisterRequest,
        GetCredentialRequest,
        GetCredentialResponse,
        RegisterResponse,
        VerifyRequest,
        VerifyResponse,
    ))
)]
pub struct OpenApiDoc;

impl OpenApiDoc {
    /// Return the OpenAPI schema.
    pub fn generate() -> String {
        OpenApiDoc::openapi().to_yaml().unwrap()
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// PEM encoded certificate request.
    pub certificate_request: String,
    /// The email contained in the [certificate_request].
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GetCredentialRequest {
    /// The email of the client for which to get the credential.
    email: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct VerifyRequest {
    /// PEM encoded client certificate.
    pub certificate: String,
}

#[derive(Serialize, ToSchema)]
pub struct GetCredentialResponse {
    /// PEM encoded certificate.
    certificate: String,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct RegisterResponse {
    /// PEM encoded certificate.
    pub certificate: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyResponse {
    /// Whether the certificate is valid.
    valid: bool,
}

/// Return JSON version of an OpenAPI schema
#[utoipa::path(
    get,
    path = "/api-doc.json",
    responses(
        (status = 200, description = "JSON file")
    )
)]
#[get("/api-doc.json")]
pub fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(OpenApiDoc::openapi())
}

/// Return the CA's credential.
#[utoipa::path(
    get,
    path = "/ca/credential",
    responses(
        (status = 200, description = "CA certificate", body = GetCredentialResponse)
    )
)]
#[get("/ca/credential")]
pub fn get_ca_credential(state: &State<ServerStateArc>) -> Json<GetCredentialResponse> {
    let state = state.lock().unwrap();
    Json(GetCredentialResponse {
        certificate: state.ca_cert.cert.pem(),
    })
}

/// Return the client's credential bound to the email in the request.
#[utoipa::path(
    post, // As we are sending the email in the body, to avoid other users to understand who we are looking for
    path = "/credential",
    request_body = GetCredentialRequest,
    responses(
        (status = 200, description = "client certificate", body = GetCredentialResponse),
        (status = 404, description = "Not Found")
    )
)]
#[post("/credential", data = "<request>")]
pub async fn get_credential(
    request: Json<GetCredentialRequest>,
    db: DbConnection,
) -> Result<Json<GetCredentialResponse>, NotFound<String>> {
    get_certificate_by_email(&request.email, db)
        .await
        .map_or_else(
            |e| {
                log::debug!(
                    "Couldn't find a certificate for `{}` in the DB: {:?}",
                    &request.email,
                    e
                );
                Err(NotFound(format!(
                    "Requested client `{}` not yet registered",
                    &request.email
                )))
            },
            |cert| {
                Ok(Json(GetCredentialResponse {
                    certificate: cert.certificate,
                }))
            },
        )
}

/// Register a new client's public key with the CA.
/// The client sends a certificate request in PEM format.
/// The CA checks that the email in the certificate request is the same as the email in the register request.
#[utoipa::path(
    post,
    path = "/ca/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registered client.", body = RegisterResponse),
        (status = 400, description = "Bad Request"),
        (status = 409, description = "Conflict"),
    )
)]
#[post("/ca/register", data = "<request>")]
pub async fn register(
    request: Json<RegisterRequest>,
    state: &State<ServerStateArc>,
    db: DbConnection,
) -> Result<Created<Json<RegisterResponse>>, Result<Conflict<String>, BadRequest<String>>> {
    // Shorten the lifetime of the state lock to not hold across the await boundaries.
    let response = {
        let state = state.lock().unwrap();
        log::debug!("Received certificate request for email {:?}", request.email);
        let cert = match sign_request_from_pem_and_check_email(
            &request.certificate_request,
            &state.ca_cert,
            &request.email,
        ) {
            Ok(cert) => cert,
            Err(e) => {
                log::error!("Error signing the certificate: {:?}", e);
                return Err(Err(BadRequest("Error signing the certificate".to_string())));
            }
        };
        let response = RegisterResponse {
            certificate: cert.pem(),
        };
        response
    };
    let r = insert_certificate(&request.email, &response.certificate, db)
        .await
        .map_or_else(
            |e| {
                // Since we already performed validation on the request, we can assume the error is due to a duplicate email.
                // The db schema should have a unique constraint on the email field.
                log::error!("Error inserting the certificate in the DB: {:?}", e);
                Err(Ok(Conflict("Client already registered".to_string())))
            },
            |_| {
                log::debug!(
                    "Registered client with email: `{}`, certificate `{:?}`",
                    &request.email,
                    response
                );
                let create_response = Created::new("https://localhost:8000/credential");
                Ok(Created::body(create_response, Json(response)))
            },
        );
    r
}

/// Verify a client's certificate.
/// The client sends a certificate to be verified in PEM format.
#[utoipa::path(
    post,
    path = "/ca/verify",
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Whether the client's certificate is valid or not.", body = VerifyResponse),
    )
)]
#[post("/ca/verify", data = "<request>")]
pub async fn verify(
    request: Json<VerifyRequest>,
    state: &State<ServerStateArc>,
) -> Json<VerifyResponse> {
    let state = state.lock().unwrap();
    log::debug!(
        "Received certificate for verification: {:?}",
        &request.certificate
    );
    let verified = match check_signature(&request.certificate, &state.ca_cert.cert.pem()) {
        Ok(verified) => verified,
        Err(e) => {
            log::error!("Error verifying the certificate: {:?}", e);
            false
        }
    };
    Json(VerifyResponse { valid: verified })
}
