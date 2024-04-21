use ds::db;
use ds::server;
use rocket::{
    config::{MutualTls, TlsConfig},
    figment::providers::{Format, Toml},
};
use rocket_db_pools::Database;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[rocket::launch]
fn rocket() -> _ {
    env_logger::init();

    let (ds_cert_path, ds_keys_path) = pki::get_ds_server_credential_paths();
    let tls_config = TlsConfig::from_paths(ds_cert_path, ds_keys_path)
        .with_mutual(MutualTls::from_path(pki::get_ca_credential_paths().0));
    let figment = rocket::Config::figment()
        // Load the configuration file for the PKI server.
        .merge(Toml::file("DS_Rocket.toml").nested())
        .merge((rocket::Config::TLS, tls_config));

    // Initialise the rocket server also mounting the swagger-ui.
    rocket::custom(figment)
        .attach(db::DbConn::init())
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
                server::get_users,
            ],
        )
}
