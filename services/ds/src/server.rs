use std::{ sync::Arc};

use rocket::{
    delete, form::Form, get, http::Status, mtls::{self, x509::GeneralName, Certificate}, outcome::try_outcome, patch, post, request::{FromRequest, Outcome}, response::{stream::{Event, EventStream}, Responder}, serde::json::Json, FromForm, Request, Shutdown, State
};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::spawn_local};
use utoipa::{OpenApi, ToSchema};
use rocket::tokio::sync::broadcast::{channel, Sender, error::RecvError};
use rocket::tokio::select;

use crate::{db::{
    self, get_folder_by_id, get_users_by_emails, insert_folder_and_relation, insert_message, insert_user, DbConn, FolderEntity, UserEntity
}, storage::{self, DynamicStore, WriteInput}};

/// The syncronized store to be used as managed state in Rocket.
/// This will protect
pub type SyncStore = Arc<Mutex<DynamicStore>>;

//pub type WebSocketConnectedClients = Arc<Mutex<HashSet<String>>>;
//pub type WebSocketConnectedQueues = Arc<Mutex<HashMap<String, SplitSink<DuplexStream, Message>>>>;

#[derive(Debug, Clone)]
pub struct Notification {
    folder_id: u64,
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

/// Create the folder with the initial Metadata file.
#[derive(FromForm, ToSchema, Debug)]
pub struct CreateFolderRequest<'r> {
    /// The metadata file to upload.
    pub metadata: &'r [u8],
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
    pub emails: Vec<String>,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupMessage<'r> {
    /// The folder the group is sharing.
    pub folder_id: u64,
    /// The payload of the MLS message.
    pub payload: &'r [u8],
}

/// Custom responder.
#[derive(Responder, Debug)]
pub enum SSFResponder<R> {
    #[response(status = 200, content_type = "json")]
    Ok(Json<R>),
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
        Ok(_) => {
            log::debug!("Should send a notification to all receivers of the folder {:?}", &request.emails);
            for email in &request.emails {
                // If the send fails, it just means that the client is not online, they will fetch the new state upon initialisation.
                send_see(folder_id, email, sse_queue).await;
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
pub async fn sse(mut shutdown: Shutdown, client_certificate: CertificateWithEmails<'_>,  mut db: Connection<DbConn>, sse_queue: &State<SenderSentEventQueue>) -> EventStream![] {
    let known_user = get_known_user_or_unauthorized::<EmptyResponse>(client_certificate, &mut db).await.expect("The user is not known to the server, first register!");
    let mut rx = sse_queue.subscribe();
    EventStream! {
        loop {
            let msg = select! {
                msg = rx.recv() => match msg {
                    Ok(msg) if msg.receiver == known_user.user_email => msg.folder_id,
                    Ok(_) => continue,
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut shutdown => break,
            };
            log::debug!("SSE Notification: {:?}", msg);
            yield Event::data(msg.to_string());
        }
    }
}


async fn send_see(folder_id: u64, email: &str, sse_queue: &State<SenderSentEventQueue>) {
    let notification = Notification {
        folder_id,
        receiver: email.to_owned(),
    };
    let result = sse_queue.send(notification);
    if let Err(e) = result {
        log::debug!("Error while trying to send the notification: {:?}", e);
    }
}

/** 
#[get("/groups/ws")]
pub async fn echo_channel<'r>(ws: rocket_ws::WebSocket, mut db: Connection<DbConn>, client_certificate: CertificateWithEmails<'_>, state: &'r State<WebSocketConnectedClients>, queues: &'r State<WebSocketConnectedQueues>) -> rocket_ws::Channel<'r> {
    use rocket::futures::{SinkExt, StreamExt};
    let known_user = get_known_user_or_unauthorized::<EmptyResponse>(client_certificate, &mut db).await;
    let mut client_pending_messages = state.lock().await;
    log::debug!("Open WebSockets: {:?}", client_pending_messages.len());
    match known_user {
        Err(_) => {
            ws.channel(move |mut stream| Box::pin(async move {
                stream.close(None).await?;
                // Close immediately the connection if the client is not among the known users.
                Err(Error::AttackAttempt)
            }) )
        }
        Ok(user_entity) if client_pending_messages.contains(&user_entity.user_email) => {
            ws.channel(move |mut stream| Box::pin(async move {
                stream.close(None).await?;
                // Close immediately the connection if the client already has a WebSocket.
                Err(Error::ConnectionClosed)
            }) )
        }
        Ok(user_entity) => {
            let channel = ws.channel(move |mut stream| Box::pin(async move {
                client_pending_messages.insert(user_entity.user_email.clone());
                let (sink, mut stream) = stream.split();
                {
                    queues.lock().await.insert(user_entity.user_email.clone(), sink);
                    // Drop the lock immediately after.
                }
                drop(client_pending_messages);
                // Do not hold the lock to the shared state while the connection is open.
                while let Some(message) = stream.next().await {
                    if let Ok(wire_message) = message {
                        if let Message::Binary(cbor_payload) = wire_message { 
                            let group_message = serde_cbor::from_slice::<GroupMessage>(&cbor_payload);
                            match group_message {
                                Err(e) => {
                                    log::debug!("There was an error while parsing from CBOR the message sent by {:?}, {:?}.", &user_entity.user_email, e);
                                    break;
                                }
                                Ok(deserialized) => {
                                    match insert_message(&user_entity.user_email, deserialized.folder_id, deserialized.payload, &mut db).await {
                                        Err(_) => {
                                            log::debug!("There was an error while trying to queue the message sent by {:?}.", &user_entity.user_email);
                                            break;
                                        },
                                        Ok(users) => {
                                            log::debug!("{:?}", users);
                                            for user in users {
                                                if (user != user_entity.user_email) {
                                                    // Do not lock all the sinks all the time. Allow for other threads to send in between a broadcast from one thread.
                                                    let mut others = queues.lock().await;
                                                    let sink = others.get_mut(&user).expect("All users should be connected through a ws.");
                                                    sink.send(Message::Binary(deserialized.payload.to_vec())).await?;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if let Message::Close(_) = wire_message {
                                break;
                            } else {
                                log::debug!("Wrong format!");
                            }
                        }
                    } else {
                        log::debug!("There was an error while parsing the message sent by {:?}, wrong format, it must be binary.", &user_entity.user_email);
                        break;
                    }
                }
                let mut st = state.lock().await;
                st.remove(&user_entity.user_email);
                let mut others = queues.lock().await;
                others.remove(&user_entity.user_email);
                Ok(())
            }));

            channel 
        }
    }
   
}
*/

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
