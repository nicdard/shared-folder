use rocket::{
    get,
    http::Status,
    mtls::{self, x509::GeneralName, Certificate},
    outcome::try_outcome,
    patch, post,
    request::{FromRequest, Outcome},
    response::Responder,
    serde::json::Json,
    Request,
};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use sqlx::Acquire;
use utoipa::{OpenApi, ToSchema};

use crate::db::{
    self, get_folder_by_id, get_users_by_emails, insert_folder_and_relation, insert_user, DbConn,
    UserEntity,
};

/// Documentation in OpenAPI format.
#[derive(OpenApi)]
#[openapi(
    paths(openapi, create_user, create_folder, list_users, list_folders_for_user),
    components(schemas(
        CreateUserRequest,
        CreateFolderRequest,
        ListUsersResponse,
        ListFolderResponse,
        FolderResponse,
    ))
)]
pub struct OpenApiDoc;

impl OpenApiDoc {
    /// Return the OpenAPI schema.
    pub fn generate() -> String {
        OpenApiDoc::openapi().to_yaml().unwrap()
    }
}

/// Return JSON version of an OpenAPI schema
#[utoipa::path(
    get,
    path = "/api-doc.json",
    responses(
        (status = 200, description = "Openapi spec of this server")
    )
)]
#[get("/api-doc.json")]
pub fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(OpenApiDoc::openapi())
}

/// The type of an empty response, to simplify development with the [`SSFResponder`].
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct EmptyResponse {}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// The email contained in the associated credentials sent through mTLS.
    pub email: String,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct ListUsersResponse {
    /// The emails of the users.
    pub emails: Vec<String>,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct CreateFolderRequest {
    /// The folder name.
    pub name: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct CreateFolderResponse {
    /// The folders.
    pub id: u64,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct FolderResponse {
    pub id: u64,
    pub name: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ListFolderResponse {
    pub folders: Vec<FolderResponse>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ShareFolderRequest {
    /// The emails of the users to share the folder with. The id is extracted from the path.
    pub emails: Vec<String>,
}

/// Custom responder.
#[derive(Responder, Debug)]
pub enum SSFResponder<R> {
    #[response(status = 200, content_type = "json")]
    Ok(Json<R>),
    #[response(status = 201, content_type = "json")]
    Created(Json<R>),
    #[response(status = 201, content_type = "plain")]
    EmptyCreated(String),
    #[response(status = 400, content_type = "plain")]
    BadRequest(String),
    #[response(status = 401, content_type = "plain")]
    Unauthorized(String),
    #[response(status = 404, content_type = "plain")]
    NotFound(String),
    #[response(status = 409, content_type = "plain")]
    Conflict(String),
    #[response(status = 500, content_type = "plain")]
    InternalServerError(String),
}

/// Create a new user checking that the client certificate contains the email that is used to create the account.
#[utoipa::path(
    post,
    path = "/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "New account created."),
        (status = 400, description = "Bad request."),
        (status = 401, description = "Unauthorized user, please, set a valid client credential."),
        (status = 409, description = "Conflict.")
    )
)]
#[post("/users", format = "application/json", data = "<request>")]
pub async fn create_user(
    client_certificate: CertificateWithEmails<'_>,
    db: Connection<DbConn>,
    request: Json<CreateUserRequest>,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to create user with email `{}`",
        &request.email
    );
    if !client_certificate.emails.contains(&request.email) {
        log::debug!("The client certificate is not containing the email to register as user");
        return SSFResponder::BadRequest("The email you want to register with is not bound to the client certificate you authenticated with."
            .to_string());
    }
    match insert_user(&request.email, db).await {
        Ok(_) => {
            log::debug!("Created user with email `{}`", &request.email);
            SSFResponder::EmptyCreated("Created".to_string())
        }
        Err(e) => {
            log::debug!("Error inserting the user in the db: `{}`", e);
            SSFResponder::Conflict("User already registered".to_string())
        }
    }
}

/// List all the users.
#[utoipa::path(
    get,
    path = "/users",
    responses(
        (status = 200, description = "List of users using the SSF.", body = GetUsersResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[get("/users")]
pub async fn list_users(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
) -> SSFResponder<ListUsersResponse> {
    log::debug!(
        "Received client certificate to retrieve users, with emails `{:?}`",
        &client_certificate.emails
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let users = db::list_users(db).await;
    match users {
        Err(e) => {
            log::error!("Couldn't retrieve the users from the DB: `{}`", e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
        Ok(users) => SSFResponder::Ok(Json(ListUsersResponse {
            emails: users.iter().map(|u| u.user_email.clone()).collect(),
        })),
    }
}

/// Create a new folder and link it to the user.
#[utoipa::path(
    post,
    path = "/folders",
    request_body = CreateFolderRequest,
    responses(
        (status = 201, description = "New folder created."),
        (status = 400, description = "Bad Request."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 409, description = "Conflict.")
    )
)]
#[post("/folders", data = "<request>")]
pub async fn create_folder(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    request: Json<CreateFolderRequest>,
) -> SSFResponder<CreateFolderResponse> {
    log::debug!(
        "Received client certificate to create a folder, user emails `{:?}`",
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    match insert_folder_and_relation(&request.name, &known_user.unwrap().user_email, db).await {
        Ok(result) => SSFResponder::Created(Json(CreateFolderResponse { id: result })),
        Err(e) => {
            log::error!("Couldn't create a new folder with name `{}", e);
            SSFResponder::Conflict("Please use a valid folder name".to_string())
        }
    }
}

#[utoipa::path(
    get,
    path = "/folders",
    responses(
        (status = 200, description = "List of folders.", body = ListFolderResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[get("/folders")]
pub async fn list_folders_for_user(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
) -> SSFResponder<ListFolderResponse> {
    log::debug!(
        "Received client certificate to retrieve folders, with emails `{:?}`",
        &client_certificate.emails
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let folders = db::list_folders(&known_user.unwrap().user_email, db).await;
    match folders {
        Err(e) => {
            log::error!("Couldn't retrieve the folders from the DB: `{}`", e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
        Ok(folders) => SSFResponder::Ok(Json(ListFolderResponse {
            folders: folders
                .iter()
                .map(|f| FolderResponse {
                    id: f.folder_id,
                    name: f.folder_name.clone(),
                })
                .collect(),
        })),
    }
}

/// List all the users.
#[utoipa::path(
    get,
    path = "/folders/<folder_id>",
    responses(
        (status = 200, description = "The requested folder.", body = FolderResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Folder not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[get("/folders/<folder_id>")]
pub async fn get_folder(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
) -> SSFResponder<FolderResponse> {
    log::debug!(
        "Received client certificate to retrieve folder with id `{}`",
        folder_id
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let folder = get_folder_by_id(&known_user.unwrap().user_email, folder_id, db).await;
    match folder {
        Ok(folder) => SSFResponder::Ok(Json(FolderResponse {
            id: folder.folder_id,
            name: folder.folder_name,
        })),
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found", folder_id);
            SSFResponder::NotFound("Folder not found".to_string())
        }
        Err(e) => {
            log::error!("Couldn't retrieve the folder from the DB: `{}`", e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
    }
}

/// Share a folder with other users.
/// If some of the users already can see the folder, they will be ignored.
#[utoipa::path(
    patch, 
    path = "/folders/<folder_id>", 
    request_body = ShareFolderRequest,
    responses(
        (status = 200, description = "Folder shared."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[patch("/folders/<folder_id>", data = "<request>")]
pub async fn share_folder(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    request: Json<ShareFolderRequest>,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to share folder with id `{}`",
        folder_id
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let result = db::insert_folder_users_relations(folder_id, &known_user.unwrap().user_email, &request.emails, db).await;
    match result {
        Ok(_) => SSFResponder::Ok(Json(EmptyResponse {})),
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found", folder_id);
            SSFResponder::NotFound("Folder not found".to_string())
        }
        Err(e) => {
            log::error!("Couldn't share the folder with id `{}`: `{}`", folder_id, e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
    }
}

/// A request guard that authenticates and authorize a client using it's TLS client certificate, extracting the emails.
/// If no emails are found in the Certificate, send back an [`Status::Unauthorized`] request.    
/// This is a wrapper around the [`Certificate`] guard.
pub struct CertificateWithEmails<'r> {
    cert: Certificate<'r>,
    emails: Vec<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CertificateWithEmails<'r> {
    type Error = mtls::Error;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cert = try_outcome!(req.guard::<Certificate<'r>>().await);
        let emails: Vec<String> = cert
            .subject_alternative_name()
            .iter()
            .filter_map(|san| match san {
                Some(san) => Some(san.value.general_names.iter().filter_map(|gn| match gn {
                    GeneralName::RFC822Name(email) => Some(email),
                    _ => None,
                })),
                None => None,
            })
            .flatten()
            .map(|e| e.to_string())
            .collect();
        if emails.len() > 0 {
            Outcome::Success(CertificateWithEmails { cert, emails })
        } else {
            Outcome::Forward(Status::Unauthorized)
        }
    }
}

async fn get_known_user_or_unauthorized<R>(
    client_certificate: CertificateWithEmails<'_>,
    db: &mut Connection<DbConn>,
) -> Result<UserEntity, SSFResponder<R>> {
    get_known_user(client_certificate, db).await.map_err(|_| {
        SSFResponder::Unauthorized(
            "Client identity check failed, please check your TLS certificate.".to_string(),
        )
    })
}

/// Returns the user entity associated with the client certificate from mTLS or an error.
async fn get_known_user(
    client_certificate: CertificateWithEmails<'_>,
    db: &mut Connection<DbConn>,
) -> Result<UserEntity, sqlx::Error> {
    let users = get_users_by_emails(
        &client_certificate
            .emails
            .iter()
            .map(AsRef::as_ref)
            .collect(),
            db,
    )
    .await?;
    log::debug!(
        "Authenticating user for emails: `{:?}`. Found users: `{:?}`",
        &client_certificate.emails,
        users.iter().map(|u| &u.user_email)
    );
    if users.len() == 1 {
        Ok(users.get(0).unwrap().clone())
    } else {
        log::debug!("Trying to get the client from the db, found `{:?}`", users);
        Err(sqlx::Error::RowNotFound)
    }
}
