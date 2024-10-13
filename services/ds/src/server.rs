use std::sync::Arc;

use rocket::{
    delete, form::Form, get, http::Status, mtls::{self, x509::GeneralName, Certificate}, outcome::try_outcome, patch, post, request::{FromRequest, Outcome}, response::{stream::{Event, EventStream}, Responder}, serde::json::Json, FromForm, Request, Shutdown, State
};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use utoipa::{OpenApi, ToResponse, ToSchema};
use rocket::tokio::sync::broadcast::{Sender, error::RecvError};
use rocket::tokio::select;

use crate::{db::{
    self, consume_key_package, get_first_message_by_folder_and_user, get_folder_by_id, get_users_by_emails, insert_application_message, insert_folder_and_relation, insert_key_package, insert_message, insert_user, DbConn, FolderEntity, UserEntity
}, storage::{self, DynamicStore, WriteInput}};

/// The syncronized store to be used as managed state in Rocket.
/// This will protect
pub type SyncStore = Arc<Mutex<DynamicStore>>;

#[derive(Debug, Clone)]
pub struct Notification {
    folder_id: Option<u64>,
    receiver: String,
}
pub type SenderSentEventQueue = Sender::<Notification>;

/// Documentation in OpenAPI format.
#[derive(OpenApi)]
#[openapi(
    paths(openapi, 
        create_user, 
        create_folder, 
        list_users, 
        list_folders_for_user, 
        share_folder, 
        remove_self_from_folder, 
        get_folder, 
        upload_file,
        get_file,
        get_metadata,
        post_metadata,
        publish_key_package,
        fetch_key_package,
        try_publish_proposal,
        get_pending_proposal,
        try_publish_application_msg,
        v2_share_folder,
        ack_message
    ),
    components(schemas(
        CreateUserRequest,
        ListUsersResponse,
        ListFolderResponse,
        FolderResponse,
        CreateFolderRequest,
        ShareFolderRequest,
        Upload,
        UploadFileResponse,
        MetadataUpload,
        FolderFileResponse,
        CreateKeyPackageRequest,
        FetchKeyPackageRequest,
        FetchKeyPackageResponse,
        CreateKeyPackageResponse,
        ProposalMessageRequest,
        GroupMessage,
        ShareFolderRequestWithProposal,
        ApplicationMessageRequest,
        ProposalResponse
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

/// Create a key package for a user.
#[derive(FromForm, ToSchema, Debug)]
pub struct CreateKeyPackageRequest<'r> {
    /// The metadata file to upload.
    pub key_package: &'r [u8],
}

#[derive(ToResponse, ToSchema, Serialize, Deserialize, Debug)]
pub struct CreateKeyPackageResponse {
    /// The id of the created key package.
    pub key_package_id: u64,
}

/// Create the folder with the initial Metadata file.
#[derive(FromForm, ToSchema, Debug)]
pub struct CreateFolderRequest<'r> {
    /// The metadata file to upload.
    pub metadata: &'r [u8],
}


/// Retrieves a key package of another user.
#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct FetchKeyPackageRequest {
    /// The user email
    pub user_email: String,
}

/// Upload a file to the server.
#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct FetchKeyPackageResponse {
    /// The payload.
    pub payload: Vec<u8>,
}

/// Create a proposal.
#[derive(FromForm, ToSchema, Debug)]
pub struct ProposalMessageRequest<'r> {
    /// The proposal to upload.
    pub proposal: &'r [u8],
}

/// Patch a proposal, publishing an application message.
#[derive(FromForm, ToSchema, Debug)]
pub struct ApplicationMessageRequest<'r> {
    /// The proposal to upload.
    pub payload: &'r [u8],
    /// The message ids to which the application message is related.
    pub message_ids: Vec<u64>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct GroupMessage {
    /// The folder the group is sharing.
    pub message_id: u64,
    /// The folder id.
    pub folder_id: u64,
    /// The payload of the GRaPPA message.
    pub payload: Vec<u8>,
    /// The application that should handle the message.
    pub application_payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct ListUsersResponse {
    /// The emails of the users.
    pub emails: Vec<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct FolderResponse {
    /// The id of the folder.
    pub id: u64,
    // The etag of the metadata file.
    pub etag: Option<String>,
    // The version of the metadata file, at least one of etag or version should be present.
    pub version: Option<String>,
    // The optional content of the metadata file.
    pub metadata_content: Option<Vec<u8>>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ListFolderResponse {
    pub folders: Vec<u64>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ShareFolderRequest {
    /// The emails of the users to share the folder with. The id is extracted from the path.
    pub emails: Vec<String>
}

#[derive(FromForm, ToSchema, Debug)]
pub struct ShareFolderRequestWithProposal<'r> {
    /// The user to share the folder with.
    pub email: String,
    /// The proposal to upload.
    pub proposal: &'r [u8],
}

#[derive(FromForm, ToSchema, Debug)]
pub struct MetadataUpload<'r> {
    /// The metadata file to upload.
    pub metadata: &'r [u8],
    /// The previous metadata etag to which this file is related.
    pub parent_etag: Option<String>,
    /// The previous metadata version to which this file is related.
    pub parent_version: Option<String>,
}

/// Upload a file to the server.
#[derive(FromForm, ToSchema, Debug)]
pub struct Upload<'r> {
    /// The file to upload.
    pub file: &'r [u8],
    /// The metadata file to upload.
    pub metadata: &'r [u8],
    /// The previous metadata etag to which this file is related.
    pub parent_etag: Option<String>,
    /// The previous metadata version to which this file is related.
    pub parent_version: Option<String>,
}

/// When a file is uploaded successfully, an etag is returned with the latest version of the metadata file of the folder.
#[derive(ToSchema, Serialize, Debug, Deserialize)]
pub struct UploadFileResponse {
    /// The metadata etag.
    pub etag: Option<String>,
    /// The metadata version. 
    pub version: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct FolderFileResponse {
    pub file: Vec<u8>,
    pub etag: Option<String>,
    pub version: Option<String>
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ProposalResponse {
    message_ids: Vec<u64>,
}

/// Custom responder.
#[derive(Responder, Debug)]
pub enum SSFResponder<R> {
    #[response(status = 200, content_type = "json")]
    Ok(Json<R>),
    #[response(status = 200, content_type = "plain")]
    EmptyOk(String),
    #[response(status = 200)]
    File(Vec<u8>),
    #[response(status = 201)]
    Created(Json<R>),
    #[response(status = 201, content_type = "plain")]
    EmptyCreated(String),
    #[response(status = 400, content_type = "plain")]
    BadRequest(String),
    #[response(status = 401, content_type = "plain")]
    Unauthorized(String),
    #[response(status = 404, content_type = "plain")]
    NotFound(String),
    #[response(status = 429, content_type = "plain")]
    RetryAfter(String),
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
        (status = 200, description = "List of users using the SSF.", body = ListUsersResponse),
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

#[utoipa::path(
    post,
    request_body(content = CreateKeyPackageRequest, content_type = "multipart/form-data"),
    path = "/users/keys",
    responses(
        (status = 201, description = "New key package created."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[post("/users/keys", data = "<request>")]
pub async fn publish_key_package(
    client_certificate: CertificateWithEmails<'_>,
    request: Form<CreateKeyPackageRequest<'_>>,
    mut db: Connection<DbConn>,
) ->  SSFResponder<CreateKeyPackageResponse> {
    log::debug!(
        "Received client certificate to publish a key package, user emails `{:?}`",
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    match insert_key_package(&known_user.unwrap().user_email, request.key_package.to_vec(), db).await {
        Ok(key_package_id) => {
            SSFResponder::Created(Json(CreateKeyPackageResponse {
                key_package_id
            }))
        },
        Err(_) => {
            SSFResponder::InternalServerError("Error occurred while trying to save the key package.".to_string())
        }
    }
}

#[utoipa::path(
    post,
    params(
        ("folder_id", description = "Folder id."),
    ),
    request_body = FetchKeyPackageRequest,
    responses(
        (status = 200, description = "Retrieved a key package.", body = FetchKeyPackageResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[post("/folders/<folder_id>/keys", data = "<request>")]
pub async fn fetch_key_package(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    request: Json<FetchKeyPackageRequest>,
    sse_queue: &State<SenderSentEventQueue>, 
) -> SSFResponder<FetchKeyPackageResponse> {
    log::debug!(
        "Received client certificate to retrieve a key package for `{:?}`, user emails `{:?}`",
        &request.user_email,
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    match consume_key_package(&request.user_email,  &known_user.unwrap().user_email, folder_id, db).await {
        Ok(key_package_entity) => {
            // Send a notification to inform the client to produce a new key package.
            send_see(None, &request.user_email, sse_queue).await;
            SSFResponder::Ok(Json(FetchKeyPackageResponse{
                payload: key_package_entity.key_package
            }))
        }
        Err(sqlx::Error::RowNotFound) => {
            SSFResponder::NotFound("Key package not found, retry in some time.".to_string())
        } 
        Err(_) => {
            SSFResponder::InternalServerError("Error while processing the query".to_string())
        }
    }
}

#[utoipa::path(
    post,
    params(
        ("folder_id", description = "Folder id."),
    ),
    request_body(content = ProposalMessageRequest, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Create a proposal.", body = ProposalResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 409, description = "Conflict: the user state is outdated, please fetch the pending proposals first."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[post("/folders/<folder_id>/proposals", data="<request>")]
pub async fn try_publish_proposal(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    request: Form<ProposalMessageRequest<'_>>,
    sse_queue: &State<SenderSentEventQueue>,     
) -> SSFResponder<ProposalResponse> {
    log::debug!(
        "Received client certificate to propose a change in folder `{:?}`, user emails `{:?}`",
        &folder_id,
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    let email = &known_user.unwrap().user_email;
    match db::insert_message(email, folder_id, request.proposal, &mut db).await {
        Ok((receivers, message_ids)) => {
            for email in &receivers {
                // If the send fails, it just means that the client is not online, they will fetch the new state upon initialisation.
                send_see(Some(folder_id), email, sse_queue).await;
            }
            SSFResponder::Ok(Json(
                ProposalResponse {
                    message_ids
                }
            ))

        }
        Err(Ok(pending_msgs)) => {
            log::debug!("Sending notification to fetch {pending_msgs} pending proposals to the user.");
            // Used to indicate that the user has still pending proposals.
            // for i in 0..pending_msgs {
            send_see(Some(folder_id), email, sse_queue).await;
            //}
            SSFResponder::Conflict("Conflict: the user state is outdated, please fetch the pending proposals first.".to_string())

        }
        Err(Err(e)) => {
            SSFResponder::InternalServerError("Error while trying to propose a change to the folder.".to_string())
        }
    }
}


#[utoipa::path(
    patch,
    params(
        ("folder_id", description = "Folder id."),
    ),
    request_body(content = ApplicationMessageRequest, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Added application message."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[patch("/folders/<folder_id>/proposals", data="<request>")]
pub async fn try_publish_application_msg(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    request: Form<ApplicationMessageRequest<'_>>,
    sse_queue: &State<SenderSentEventQueue>,     
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to propose a change in folder `{:?}`, user emails `{:?}`, `{:?}`",
        &folder_id,
        &client_certificate.emails,
        &request,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    let email = &known_user.unwrap().user_email;
    match insert_application_message(&request.message_ids, email, folder_id, request.payload, db).await {
        Ok(receivers) => {
            for email in &receivers {
                // If the send fails, it just means that the client is not online, they will fetch the new state upon initialisation.
                send_see(Some(folder_id), email, sse_queue).await;
            }
            SSFResponder::EmptyCreated("Successful proposal.".to_string())
        }
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("The message to publish the application message for was not found.");
            SSFResponder::NotFound("The message to publish the application message for was not found.".to_string())
        }
        Err(e) => {
            log::debug!("Error in publishing application message {:?}.", e);
            SSFResponder::InternalServerError("Error while trying to propose a change to the folder.".to_string())
        }
    }
}

/* 
#[utoipa::path(
    get,
    params(
        ("folder_id", description = "Folder id."),
    ),
    responses(
        (status = 200, description = "Retrieved the eldest proposal.", body = GroupMessage),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[get("/folders/<folder_id>/welcomes")]
pub async fn get_welcome(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
) -> SSFResponder<GroupMessage> {
    log::debug!(
        "Received client certificate to propose a change in folder `{:?}`, user emails `{:?}`",
        &folder_id,
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    let email = &known_user.unwrap().user_email;
    match db::get_welcome_message_by_folder_and_user(folder_id, &email, db).await {
        Ok(welcome_message) => {
            SSFResponder::Ok(Json(GroupMessage {
                message_id: welcome_message.message_id,
                folder_id: welcome_message.folder_id,
                payload: welcome_message.payload
            }))
        }
        Err(sqlx::Error::RowNotFound) => {
            SSFResponder::NotFound("No welcome message found.".to_string())
        }
        Err(_) => {
            SSFResponder::InternalServerError("Internal server error".to_string())
        }
    }
}
    */


#[utoipa::path(
    get,
    params(
        ("folder_id", description = "Folder id."),
    ),
    responses(
        (status = 200, description = "Retrieved the eldest proposal.", body = GroupMessage),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 429, description = "Too many requests."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[get("/folders/<folder_id>/proposals")]
pub async fn get_pending_proposal(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
) -> SSFResponder<GroupMessage> {
    log::debug!(
        "Received client certificate to get pending proposals for folder `{:?}`, user emails `{:?}`",
        &folder_id,
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    let email = &known_user.unwrap().user_email;
    match get_first_message_by_folder_and_user(folder_id, &email, db).await {
        Ok(Some(pending_proposal)) => {
            SSFResponder::Ok(Json(GroupMessage {
                message_id: pending_proposal.message_id,
                folder_id: pending_proposal.folder_id,
                payload: pending_proposal.payload,
                application_payload: pending_proposal.application_payload
            }))
        }
        Ok(None) => {
            SSFResponder::RetryAfter("The first pending proposal is still not consumable, retry after.".to_string())
        }
        Err(sqlx::Error::RowNotFound) => {
            SSFResponder::NotFound("No more pending proposals found.".to_string())
        }
        Err(_) => {
            SSFResponder::InternalServerError("Internal server error".to_string())
        }
    }
}

/* 
/// Delete a welcome message.
#[utoipa::path(
    delete,
    params(
        ("folder_id", description="The folder id."),
        ("message_id", description="The welcome message to delete.")
    ),
    responses(
        (status = 200, description = "Welcome message removed from the db."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error, couldn't delete the message"),
    )
)]
#[delete("/folders/<folder_id>/welcomes/<message_id>")]
pub async fn ack_welcome(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    message_id: u64,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to ack a welcome message for folder `{:?}`, user emails `{:?}`",
        &folder_id,
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    let email = &known_user.unwrap().user_email;
    match db::delete_welcome(message_id, email, folder_id, db).await {
        Ok(_) => SSFResponder::EmptyOk("Message deleted".to_string()),
        Err(sqlx::Error::RowNotFound) => {
            log::error!("Error while trying to remove the message with id {message_id} from folder {folder_id}");
            SSFResponder::NotFound("Couldn't fine the message".to_string())
        }
        Err(_) => SSFResponder::InternalServerError("Internal error while trying to delete message".to_string())
    }
}
    */


/// Delete a proposal message.
#[utoipa::path(
    delete,
    params(
        ("folder_id", description="The folder id."),
        ("message_id", description="The message to delete.")
    ),
    responses(
        (status = 200, description = "Message removed from the queue."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error, couldn't delete the message"),
    )
)]
#[delete("/folders/<folder_id>/proposals/<message_id>")]
pub async fn ack_message(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    message_id: u64,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to propose a change in folder `{:?}`, user emails `{:?}`",
        &folder_id,
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized
    }
    let email = &known_user.unwrap().user_email;
    match db::delete_message(message_id, email, folder_id, db).await {
        Ok(true) => SSFResponder::EmptyOk("Message deleted".to_string()),
        Ok(false) => SSFResponder::BadRequest("There are older messages to be acked first.".to_string()),
        Err(sqlx::Error::RowNotFound) => {
            log::error!("Error while trying to remove the message with id {message_id} from folder {folder_id}");
            SSFResponder::NotFound("Couldn't fine the message".to_string())
        }
        Err(_) => SSFResponder::InternalServerError("Internal error while trying to delete message".to_string())
        
    }
}


/// Create a new folder and link it to the user.
#[utoipa::path(
    post,
    request_body(content = CreateFolderRequest, content_type = "multipart/form-data"),
    path = "/folders",
    responses(
        (status = 201, description = "New folder created.", body = FolderResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 500, description = "Internal Server Error")
    )
)]
#[post("/folders", data = "<request>")]
pub async fn create_folder(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    store: &State<SyncStore>,
    request: Form<CreateFolderRequest<'_>>,
) -> SSFResponder<FolderResponse> {
    log::debug!(
        "Received client certificate to create a folder, user emails `{:?}`",
        &client_certificate.emails,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    match insert_folder_and_relation(&known_user.unwrap().user_email, db).await {
        Ok(result) => {
            log::debug!("Created folder with id `{}`, proceed creating the empty metadata file.", result);
            let store = store.lock().await;
            let metadata = storage::init_metadata(&store, FolderEntity {
                folder_id: result,
            }, request.metadata.to_vec()).await;
            if let Ok((etag, version)) = metadata {
                return SSFResponder::Created(Json(FolderResponse { id: result, etag, version, metadata_content: None }));
            } else {
                log::error!("Couldn't create the metadata file for the folder `{}`", result);
                return SSFResponder::InternalServerError("Internal Server Error".to_string());
            }
        },
        Err(e) => {
            log::error!("Couldn't create a new folder: `{}", e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
    }
}

/// List all the folders in which the user participates.
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
                .map(|f| f.folder_id)
                .collect(),
        })),
    }
}

/// List all the users.
#[utoipa::path(
    get,
    params(
        ("folder_id", description = "Folder id."),
    ),
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
    store: &State<SyncStore>,
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
        Ok(folder) => {
            let store = store.lock().await;
            let metadata = storage::read_metadata(&store, &folder).await;
            if let Ok((content, obj_meta)) = metadata {
                return SSFResponder::Ok(Json(FolderResponse {
                    etag: obj_meta.e_tag,
                    version: obj_meta.version,
                    id: folder.folder_id,
                    metadata_content: Some(content),
                }));
            } else {
                log::error!("Couldn't retrieve the metadata from the object store");
                return SSFResponder::InternalServerError("Internal Server Error".to_string());
            }
        },
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
    params(
        ("folder_id", description = "Folder id."),
    ),
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
    sse_queue: &State<SenderSentEventQueue>, 
    folder_id: u64,
    mut request: Json<ShareFolderRequest>,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to share folder with id `{}`",
        folder_id
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let owner_email = known_user.unwrap().user_email;
    request.emails.push(owner_email.clone());
    let emails = request.emails.iter().map(AsRef::as_ref).collect();
    let result = db::insert_folder_users_relations(folder_id, &owner_email, emails, None, db).await;
    match result {
        Ok(_) => {
            log::debug!("Should send a notification to all receivers of the folder {:?}", &request.emails);
            // This is only for the baseline, for GRaPPA is redundant. use v2 instead.
            for email in &request.emails {
                // If the send fails, it just means that the client is not online, they will fetch the new state upon initialisation.
                send_see(Some(folder_id), email, sse_queue).await;
            }
            SSFResponder::Ok(Json(EmptyResponse {}))
        },
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


/// Share a folder with another user.
#[utoipa::path(
    patch, 
    params(
        ("folder_id", description = "Folder id."),
    ),
    request_body(content = ShareFolderRequestWithProposal, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Folder shared.", body = ProposalResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 409, description = "Conflict: client status out of sync."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[patch("/v2/folders/<folder_id>", data = "<request>")]
pub async fn v2_share_folder(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    sse_queue: &State<SenderSentEventQueue>, 
    folder_id: u64,
    request: Form<ShareFolderRequestWithProposal<'_>>,
) -> SSFResponder<ProposalResponse> {
    log::debug!(
        "Received client certificate to share folder with id `{}`",
        folder_id
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let owner = known_user.unwrap().user_email;
    let emails = vec![request.email.as_str(), owner.as_str()];
    let result = db::insert_folder_users_relations(folder_id, &owner, emails, Some(request.proposal), db).await;
    match result {
        Ok((users, Some(message_ids))) if users.len() > 0 => {
            log::debug!("Should send a notification to the all the receivers of the proposal.");
            for user in users {
                // If the send fails, it just means that the client is not online, they will fetch the new state upon initialisation.
                send_see(Some(folder_id), &user, sse_queue).await;
            }
            SSFResponder::Ok(Json(ProposalResponse {
                message_ids
            }))
        },
        Ok(_) => {
            log::debug!("The sender {owner} is not in sync with pending messages!");
            SSFResponder::Conflict("Not in sync, please first process the proposals that are pending!.".to_string())
        },
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found", folder_id);
            SSFResponder::NotFound("Folder not found".to_string())
        },
        Err(e) => {
            log::error!("Couldn't share the folder with id `{}`: `{}`", folder_id, e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
    }
}

/*
/// Share a folder with another user.
#[utoipa::path(
    patch, 
    params(
        ("folder_id", description = "Folder id."),
    ),
    request_body(content = ShareFolderRequestWithProposal, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Folder shared."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[patch("/v2/folders/<folder_id>/welcomes", data = "<request>")]
pub async fn v2_share_folder_welcome(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    sse_queue: &State<SenderSentEventQueue>, 
    folder_id: u64,
    request: Form<ShareFolderRequestWithProposal<'_>>,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to publish welcome for folder with id `{}`",
        folder_id
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let owner = known_user.unwrap().user_email;
    let receiver = request.email.as_str();
    let result = db::insert_welcome(&owner, receiver, folder_id, request.proposal, &mut db).await;
    match result {
        Ok(()) => {
            log::debug!("Should send a notification to the receiver of the folder {:?}", &request.email);
            // If the send fails, it just means that the client is not online, they will fetch the new state upon initialisation.
            send_see(Some(folder_id), &request.email, sse_queue).await;
            SSFResponder::Ok(Json(EmptyResponse {}))
        },
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found", folder_id);
            SSFResponder::NotFound("Folder not found".to_string())
        },
        Err(e) => {
            log::error!("Couldn't send a welcome message for folder id `{}`: `{}`", folder_id, e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
    }
}
    */



/// Unshare a folder with other users.
#[utoipa::path(
    delete,
    params(
        ("folder_id", description="The folder id."),
    ),
    responses(
        (status = 200, description = "User removed from folder."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the users"),
    )
)]
#[delete("/folders/<folder_id>")]
pub async fn remove_self_from_folder(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
) -> SSFResponder<EmptyResponse> {
    log::debug!(
        "Received client certificate to unshare folder with id `{}`",
        folder_id
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let result = db::remove_user_from_folder(folder_id, &known_user.unwrap().user_email, db).await;
    match result {
        Ok(_) => SSFResponder::Ok(Json(EmptyResponse {})),
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found", folder_id);
            SSFResponder::NotFound("Folder not found".to_string())
        }
        Err(e) => {
            log::error!("Couldn't unshare the folder with id `{}`: `{}`", folder_id, e);
            SSFResponder::InternalServerError("Internal Server Error".to_string())
        }
    }
}

/// Get a file from the cloud storage.
#[utoipa::path(
    get,
    params(
        ("folder_id", description = "Folder id."),
        ("file_id", description = "File identifier."),
    ),
    responses(
        (status = 200, description = "The requested file.", body = FolderFileResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "File not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the file"),
    )
)]
#[get("/folders/<folder_id>/files/<file_id>")]
pub async fn get_file(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    file_id: &str,
    store: &State<SyncStore>,
) -> SSFResponder<FolderFileResponse> {
    log::debug!(
        "Received client certificate to read a file in folder with id `{}`",
        folder_id
    );    
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let user_email = known_user.unwrap().user_email;
    let folder = match get_folder_by_id(&user_email, folder_id, db).await {
        Ok(folder) => folder,
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found for user `{}`", folder_id, user_email);
            return SSFResponder::Unauthorized("This user doesn't have access to the requested folder".to_string());
        }
        Err(e) => {
            log::error!("Couldn't retrieve the folder from the DB: `{}`", e);
            return SSFResponder::InternalServerError("Internal Server Error".to_string());
        }
    };
    let store = store.lock().await;
    let file = match storage::read_file(&store, &folder, file_id).await {
        Ok(file) => file,
        Err(e) => {
            match e {
                object_store::Error::NotFound { path: _, source: _} => {
                    log::debug!("File with id `{}` not found in folder `{}`", file_id, folder_id);
                    return SSFResponder::NotFound("File not found".to_string());
                },
                _ => {
                    log::error!("Couldn't retrieve the file from the object store: `{}`", e);
                    return SSFResponder::InternalServerError("Internal Server Error".to_string());
                }
            }
        }
    };
    SSFResponder::Ok(Json(FolderFileResponse {
        file: file.0,
        etag: file.1.e_tag,
        version: file.1.version,
    }))
}

/// Upload a file to the cloud storage.
#[utoipa::path(
    post,
    request_body(content = Upload, content_type = "multipart/form-data"),
    params(
        ("folder_id", description = "Folder id."),
        ("file_id", description = "File identifier."),
    ),
    responses(
        (status = 201, description = "File uploaded."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Folder not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the file"),
    )
)]
#[post("/folders/<folder_id>/files/<file_id>", data = "<upload>")]
pub async fn upload_file(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    file_id: &str,
    upload: Form<Upload<'_>>,
    state: &State<SyncStore>
) -> SSFResponder<UploadFileResponse>  {
    log::debug!(
        "Received client certificate to upload a file in folder with id `{}` with parameters `{:?}`.",
        folder_id,
        upload,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    // Protect against metadata override.
    if storage::is_metadata_file_name(file_id) {
        return SSFResponder::BadRequest("The file_id is invalid!".to_string());
    }
    let user_email = known_user.unwrap().user_email;
    let folder_entity = match get_folder_by_id(&user_email, folder_id, db).await {
        Ok(folder) => folder,
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found for user `{}`", folder_id, user_email);
            return SSFResponder::Unauthorized("This user doesn't have access to the requested folder".to_string());
        }
        Err(e) => {
            log::error!("Couldn't retrieve the folder from the DB: `{}`", e);
            return SSFResponder::InternalServerError("Internal Server Error".to_string());
        }
    };
    let object_store = state.lock().await;
    let result = storage::write(&object_store, WriteInput {
        folder_entity,
        file_id, 
        file_to_write: Some(upload.file.to_vec()),
        metadata_file: upload.metadata.to_vec(),
        parent_etag: upload.parent_etag.clone().map(|etag| etag.trim().to_string()),
        parent_version: upload.parent_version.clone().map(|version| version.trim().to_string()),
    }).await;
    match result {
        Err(object_store::Error::Precondition {..} | object_store::Error::AlreadyExists {..})  => {
            log::debug!("Precondition failed while writing a file to S3, the metadata version you want to update doesn't match");
            SSFResponder::Conflict("Precondition failed".to_string())
        },
        Err(e) => {
            log::error!("Internal server error while writing a file to S3: `{}`", e.to_string());
            SSFResponder::InternalServerError("".to_string())
        },
        Ok((etag, version)) => {
            SSFResponder::Created(Json(UploadFileResponse {
               etag, version 
            }))
        }
    }

}

/// Get the metadata of a folder. The metadata contain the list of files and their metadata.
#[utoipa::path(
    get,
    params(
        ("folder_id", description = "Folder id."),
    ),
    responses(
        (status = 200, description = "The requested folder's metadata.", body = FolderFileResponse),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "File not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the file"),
    )
)]
#[get("/folders/<folder_id>/metadatas")]
pub async fn get_metadata(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    store: &State<SyncStore>,
) -> SSFResponder<FolderFileResponse> {
    log::debug!(
        "Received client certificate to read a file in folder with id `{}`",
        folder_id
    );    
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let user_email = known_user.unwrap().user_email;
    let folder = match get_folder_by_id(&user_email, folder_id, db).await {
        Ok(folder) => folder,
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found for user `{}`", folder_id, user_email);
            return SSFResponder::Unauthorized("This user doesn't have access to the requested folder".to_string());
        }
        Err(e) => {
            log::error!("Couldn't retrieve the folder from the DB: `{}`", e);
            return SSFResponder::InternalServerError("Internal Server Error".to_string());
        }
    };
    let store = store.lock().await;
    let metadata = match storage::read_metadata(&store, &folder).await {
        Ok(metadata) => metadata,
        Err(e) => {
            match e {
                object_store::Error::NotFound { path: _, source: _} => {
                    log::debug!("Metadata not found in folder `{}`", folder_id);
                    return SSFResponder::NotFound("Metadata not found".to_string());
                },
                _ => {
                    log::error!("Couldn't retrieve the metadata from the object store: `{}`", e);
                    return SSFResponder::InternalServerError("Internal Server Error".to_string());
                }
            }
        }
    };
    SSFResponder::Ok(Json(FolderFileResponse {
        file: metadata.0,
        etag: metadata.1.e_tag,
        version: metadata.1.version,
    }))
}



/// Upload a new version of the metadata of a folder. The metadata contain the list of files and their metadata.
#[utoipa::path(
    post,
    params(
        ("folder_id", description = "Folder id."),
    ),
    request_body(content = MetadataUpload, content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "Metadata file uploaded."),
        (status = 401, description = "Unkwown or unauthorized user."),
        (status = 404, description = "Folder not found."),
        (status = 500, description = "Internal Server Error, couldn't retrieve the file"),
    )
)]
#[post("/folders/<folder_id>/metadatas", data = "<metadata_upload>")]
pub async fn post_metadata(
    client_certificate: CertificateWithEmails<'_>,
    mut db: Connection<DbConn>,
    folder_id: u64,
    metadata_upload: Form<MetadataUpload<'_>>,
    state: &State<SyncStore>,
) -> SSFResponder<UploadFileResponse> {
    log::debug!(
        "Received client certificate to upload metadata in folder with id `{}` with parameters `{:?}`.",
        folder_id,
        metadata_upload,
    );
    let known_user = get_known_user_or_unauthorized(client_certificate, &mut db).await;
    if let Err(unauthorized) = known_user {
        return unauthorized;
    }
    let user_email = known_user.unwrap().user_email;
    let folder_entity = match get_folder_by_id(&user_email, folder_id, db).await {
        Ok(folder) => folder,
        Err(sqlx::Error::RowNotFound) => {
            log::debug!("Folder with id `{}` not found for user `{}`", folder_id, user_email);
            return SSFResponder::Unauthorized("This user doesn't have access to the requested folder".to_string());
        }
        Err(e) => {
            log::error!("Couldn't retrieve the folder from the DB: `{}`", e);
            return SSFResponder::InternalServerError("Internal Server Error".to_string());
        }
    };
    let object_store = state.lock().await;
    let result = storage::write(&object_store, WriteInput {
        folder_entity,
        file_id: "", // Ignored since file to write is None.
        file_to_write: None,
        metadata_file: metadata_upload.metadata.to_vec(),
        parent_etag: metadata_upload.parent_etag.clone().map(|etag| etag.trim().to_string()),
        parent_version: metadata_upload.parent_version.clone().map(|version| version.trim().to_string()),
    }).await;
    match result {
        Err(object_store::Error::Precondition {..} | object_store::Error::AlreadyExists {..})  => {
            log::debug!("Precondition failed while writing metadata to S3, the metadata version you want to update doesn't match");
            SSFResponder::Conflict("Precondition failed".to_string())
        },
        Err(e) => {
            log::error!("Internal server error while writing a file to S3: `{}`", e.to_string());
            SSFResponder::InternalServerError("".to_string())
        },
        Ok((etag, version)) => {
            SSFResponder::Created(Json(UploadFileResponse {
               etag, version 
            }))
        }
    }
}


/// Push notifications using server sent events.
/// The notification sends the folder_id of the folder where an event occurred, so that the client can fetch the new state.
// This mechanism can be enhanced with more information. Let's keep it simple for now.
#[get("/notifications")]
pub async fn sse<'a>(mut shutdown: Shutdown, client_certificate: CertificateWithEmails<'_>,  mut db: Connection<DbConn>, sse_queue: &'a State<SenderSentEventQueue>) -> EventStream![Event + 'a] {
    log::debug!(
        "Received client certificate to register for notifications with emails: {}.",
        client_certificate.emails.join(","),
    );
    let user = get_known_user_or_unauthorized::<EmptyResponse>(client_certificate, &mut db).await;
    EventStream! {
        match user {
            Ok(known_user) => {
                log::debug!("The user is found: {}, registering for SSE.", known_user.user_email);
                let mut rx = sse_queue.subscribe();
                loop {
                    let msg = select! {
                        msg = rx.recv() => match msg {
                            Ok(msg) if msg.receiver == known_user.user_email => msg.folder_id,
                            Ok(_) => continue,
                            Err(RecvError::Closed) => {
                                log::debug!("SSE Closing stream");
                                break
                            },
                            Err(RecvError::Lagged(_)) => continue,
                        },
                        _ = &mut shutdown => break,
                    };
                    log::debug!("SSE Notification: {:?}", msg);
                    // -1 indicates that a key package has been consumed.
                    yield Event::data(msg.map_or("-1".to_string(), |folder_id| folder_id.to_string()));
                }
            },
            Err(_) => {
                log::debug!("Error: Unauthorized");
                yield Event::data("Unknown");
            }
        }
    }
}


async fn send_see(folder_id: Option<u64>, email: &str, sse_queue: &State<SenderSentEventQueue>) {
    let notification = Notification {
        folder_id,
        receiver: email.to_owned(),
    };
    let result = sse_queue.send(notification);
    if let Err(e) = result {
        log::debug!("Error while trying to send the notification: {:?}", e);
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

/// Returns the user entity associated with the client certificate from mTLS or an error if the client is not registered.
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
