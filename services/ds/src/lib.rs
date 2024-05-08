mod db;
pub mod server;
mod storage;

use rocket::{
    config::{MutualTls, TlsConfig},
    figment::providers::{Format, Toml},
};
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_db_pools::Database;
use std::sync::Arc;
use storage::StoreConfig;
use tokio::sync::Mutex;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Initialise the Rocket server.
pub fn init_server_from_config() -> rocket::Rocket<rocket::Build> {
    let _ = env_logger::try_init().inspect_err(|e| log::warn!("error `{}`", e));

    let (ds_cert_path, ds_keys_path) = pki::get_ds_server_credential_paths();
    let tls_config = TlsConfig::from_paths(ds_cert_path, ds_keys_path)
        .with_mutual(MutualTls::from_path(pki::get_ca_credential_paths().0));
    let figment = rocket::Config::figment()
        // Load the configuration file for the PKI server.
        .merge(Toml::file("DS_Rocket.toml").nested())
        .merge((rocket::Config::TLS, tls_config));

    let storage_config = figment
        .extract::<StoreConfig>()
        .expect("valid storage configuration");
    let storage: server::SyncStore = Arc::new(Mutex::new(
        storage::initialise_object_store(storage_config).expect("A valid Store instance!"),
    ));

    // TODO: configure through env variables.
    let other_servers = vec![
        "https://localhost:8000",
        "https://localhost:8001",
        "http://localhost:3000",
    ];
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::some_exact(&other_servers))
        .to_cors()
        .expect("The CORS configuration is invalid.");

    // Initialise the rocket server also mounting the swagger-ui.
    rocket::custom(figment)
        .attach(db::DbConn::init())
        .attach(cors)
        .manage(storage)
        .mount(
            "/",
            SwaggerUi::new("/swagger-ui/<_..>")
                .url("/api-docs/openapi.json", server::OpenApiDoc::openapi()),
        )
        .mount(
            "/",
            rocket::routes![
                server::openapi,
                server::create_user,
                server::create_folder,
                server::list_users,
                server::list_folders_for_user,
                server::get_folder,
                server::share_folder,
                server::remove_self_from_folder,
                server::get_file,
                server::upload_file,
                server::get_metadata,
            ],
        )
}
