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
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use openssl::{
    base64,
    pkey::{PKey, Private},
    x509::{X509Req, X509VerifyResult, X509},
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::Config;
use warp::{
    filters::path::{FullPath, Tail},
    http::Uri,
    hyper::{Response, StatusCode},
    Filter, Rejection, Reply,
};

use crate::crypto::mk_ca_signed_cert;

/// The state of the server, maintains the CA certificate and CA key pair.
#[derive(Debug, Clone)]
pub struct ServerState {
    /// The CA certificate.
    pub ca_cert: X509,
    /// The CA key pair.
    pub ca_key_pair: PKey<Private>,
    /// The list of registered clients' certificates.
    /// This should be stored in a database.
    /// The key is the email of the client.
    /// The value is the certificate of the client.
    registered_clients: HashMap<String, X509>,
}

pub fn new_server_state(ca_cert: X509, ca_key_pair: PKey<Private>) -> ServerState {
    ServerState {
        ca_cert,
        ca_key_pair,
        registered_clients: HashMap::new(),
    }
}

/// The type of the server state wrapped in an Arc and a Mutex.
pub type ServerStateArc = Arc<Mutex<ServerState>>;

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
    /// Base64 encoded certificate request.
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
    /// Base64 encoded client certificate.
    pub certificate: String,
}

#[derive(Serialize, ToSchema)]
pub struct GetCredentialResponse {
    /// Base64 encoded certificate.
    certificate: String,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct RegisterResponse {
    /// Base64 encoded certificate.
    pub certificate: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyResponse {
    /// Whether the certificate is valid.
    valid: bool,
}

/// A filter that injects the ServerState in all other filters.
fn with_state(
    state: ServerStateArc,
) -> impl warp::Filter<Extract = (ServerStateArc,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

/// The handlers for the server. They are used to create the routes.
/// Takes the server state as input.
pub fn handlers(
    state: ServerStateArc,
    swagger_config: Arc<Config<'static>>,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let api_doc = warp::path("api-doc.json")
        .and(warp::path::end())
        .and(warp::get())
        .map(openapi);
    let get_credential = warp::path("credential")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::query())
        .and(with_state(state.clone()))
        .and_then(get_credential);
    let get_ca_credential = warp::path("ca")
        .and(warp::path("credential"))
        .and(warp::path::end())
        .and(warp::get())
        .and(with_state(state.clone()))
        .and_then(get_ca_credential);
    let register = warp::path("ca")
        .and(warp::path("register"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(register);
    let verify = warp::path("ca")
        .and(warp::path("verify"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(verify);
    let swagger_ui = warp::path("swagger-ui")
        .and(warp::get())
        .and(warp::path::full())
        .and(warp::path::tail())
        .and(warp::any().map(move || swagger_config.clone()))
        .and_then(serve_swagger);
    api_doc
        .or(swagger_ui)
        .or(get_credential)
        .or(get_ca_credential)
        .or(register)
        .or(verify)
}

/// Return JSON version of an OpenAPI schema
#[utoipa::path(
    get,
    path = "/api-doc.json",
    responses(
        (status = 200, description = "JSON file")
    )
)]
fn openapi() -> Result<impl Reply, Infallible> {
    Ok(warp::reply::json(&OpenApiDoc::openapi()))
}

/// Return the CA's credential.
#[utoipa::path(
    get,
    path = "/ca/credential",
    responses(
        (status = 200, description = "CA certificate", body = GetCredentialResponse)
    )
)]
async fn get_ca_credential(state: ServerStateArc) -> Result<impl Reply, Infallible> {
    Ok(warp::reply::json(&GetCredentialResponse {
        certificate: base64::encode_block(&state.lock().unwrap().ca_cert.to_pem().unwrap()),
    }))
}

/// Return the client's credential.
#[utoipa::path(
    post, // As we are sending the email in the body, to avoid other users to understand who we are looking for
    path = "/credential",
    request_body = GetCredentialRequest,
    responses(
        (status = 200, description = "client certificate", body = GetCredentialResponse),
        (status = 404, description = "Not Found")
    )
)]
async fn get_credential(
    request: GetCredentialRequest,
    state: ServerStateArc,
) -> Result<Box<dyn Reply>, Infallible> {
    let state = state.lock().unwrap();
    if let Some(client_certificate) = state.registered_clients.get(&request.email) {
        Ok(Box::new(warp::reply::json(&GetCredentialResponse {
            certificate: base64::encode_block(&client_certificate.to_pem().unwrap()),
        })))
    } else {
        Ok(Box::new(StatusCode::NOT_FOUND))
    }
}

/// Register a new client's public key with the CA.
/// The client sends a certificate request in base64 format.
#[utoipa::path(
    post,
    path = "/ca/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registered client.", body = RegisterResponse),
        (status = 400, description = "Bad Request"),
        (status = 409, description = "Conflict", body = RegisterResponse),
    )
)]
async fn register(
    request: RegisterRequest,
    state: ServerStateArc,
) -> Result<Box<dyn Reply>, Infallible> {
    let mut state = state.lock().unwrap();
    // TODO properly handle errors
    let certificate_request = base64::decode_block(&request.certificate_request).unwrap();
    log::debug!("Received certificate request for email {:?}", request.email);
    let cert_request = X509Req::from_pem(&certificate_request).unwrap();
    // Verify that the certificate request contains the email address for which the registration is requested.
    let email: &str = &request.email;
    let contains_email = cert_request.subject_name().entries().any(|entry| {
        if let Ok(data) = entry.data().as_utf8() {
            data.eq(email)
        } else {
            false
        }
    });
    if !contains_email {
        return Ok(Box::new(StatusCode::BAD_REQUEST));
    }

    if state.registered_clients.contains_key(email) {
        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&RegisterResponse {
                certificate: base64::encode_block(
                    &state
                        .registered_clients
                        .get(email)
                        .unwrap()
                        .to_pem()
                        .unwrap(),
                ),
            }),
            StatusCode::CONFLICT,
        )));
    }

    let cert = mk_ca_signed_cert(&state.ca_cert, &state.ca_key_pair, cert_request).unwrap();
    let cert_pem = cert.to_pem().unwrap();
    let response = RegisterResponse {
        certificate: base64::encode_block(&cert_pem),
    };
    // TODO: Store the certificate in a database or OpenSSL store.
    state.registered_clients.insert(email.to_string(), cert);
    log::debug!(
        "Registered client with email: {}, certificate {:?}",
        email,
        response
    );

    Ok(Box::new(warp::reply::with_status(
        warp::reply::json(&response),
        StatusCode::CREATED,
    )))
}

/// Verify a client's certificate.
/// The client sends a certificate to be verified in base64 format.
#[utoipa::path(
    post,
    path = "/ca/verify",
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Whether the client's certificate is valid or not.", body = VerifyResponse),
    )
)]
async fn verify(request: VerifyRequest, state: ServerStateArc) -> Result<impl Reply, Infallible> {
    let state = state.lock().unwrap();
    let certificate = base64::decode_block(&request.certificate).unwrap();
    log::debug!(
        "Received certificate for verification: {:?}",
        String::from_utf8(certificate.clone()).unwrap()
    );
    let certificate = X509::from_pem(&certificate).unwrap();
    match state.ca_cert.issued(&certificate) {
        X509VerifyResult::OK => Ok(warp::reply::json(&VerifyResponse { valid: true })),
        ver_err => {
            log::error!("Certificate verification error: {:?}", ver_err);
            Ok(warp::reply::json(&VerifyResponse { valid: false }))
        }
    }
}

/// Serve the Swagger UI.
async fn serve_swagger(
    full_path: FullPath,
    tail: Tail,
    config: Arc<Config<'static>>,
) -> Result<Box<dyn Reply + 'static>, Rejection> {
    if full_path.as_str() == "/swagger-ui" {
        return Ok(Box::new(warp::redirect::found(Uri::from_static(
            "/swagger-ui/",
        ))));
    }

    let path = tail.as_str();
    match utoipa_swagger_ui::serve(path, config) {
        Ok(file) => {
            if let Some(file) = file {
                Ok(Box::new(
                    Response::builder()
                        .header("Content-Type", file.content_type)
                        .body(file.bytes),
                ))
            } else {
                Ok(Box::new(StatusCode::NOT_FOUND))
            }
        }
        Err(error) => Ok(Box::new(
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(error.to_string()),
        )),
    }
}
