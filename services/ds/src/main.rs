use ds::init_server_from_config;

#[rocket::launch]
fn rocket() -> _ {
    init_server_from_config()
}
