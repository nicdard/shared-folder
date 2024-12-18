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
mod db;
pub mod server;
mod storage;

use rocket::figment::providers::{Format, Toml};
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_db_pools::Database;
use server::{Notification, SenderSentEventQueue};
//use server::{WebSocketConnectedClients, WebSocketConnectedQueues};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use storage::StoreConfig;
use tokio::sync::{broadcast::channel, Mutex};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Initialise the Rocket server.
pub fn init_server_from_config() -> rocket::Rocket<rocket::Build> {
    let _ = env_logger::try_init().inspect_err(|e| log::warn!("error `{}`", e));

    let figment = rocket::Config::figment()
        // Load the configuration file for the DS server.
        .merge(Toml::file("DS_Rocket.toml").nested());

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
        "https://127.0.0.1:8001",
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
        //.manage(web_socket_clients)
        //.manage(web_socket_queues)
        .manage(channel::<Notification>(1024).0)
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
                server::post_metadata,
                server::publish_key_package,
                server::fetch_key_package,
                server::try_publish_proposal,
                server::get_pending_proposal,
                server::ack_message,
                server::v2_share_folder,
                server::try_publish_application_msg,
                //server::echo_channel,
                server::sse
            ],
        )
}
