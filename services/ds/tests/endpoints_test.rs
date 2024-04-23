/// Attention! This module contains tests that interact with the database.
/// You will need to run the `MySQL` database using the docker-compose.yaml configuration provided.
#[cfg(test)]
mod test {
    use ds::init_server_from_config;
    use ds::server::{
        CreateFolderRequest, CreateFolderResponse, CreateUserRequest, FolderResponse,
        ListFolderResponse, ListUsersResponse,
    };
    use rand::distributions::{Alphanumeric, DistString};
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    /// Create a random string of 50 characters.
    fn create_random_string(len: usize) -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), len)
    }

    /// Create a client certificate on the fly to test the server.
    /// uses the same CA certificate that the server reads.
    fn create_client_credentials() -> (String, String) {
        // Initialise the logger for testing.
        let _ = env_logger::builder().is_test(true).try_init();
        // Create a client random email.
        // Randomize input to avoid conflicts on running the tests mutliple times.
        // TODO: sqlx has a feature to perform automatic migrations, but doesn't seem to work with InnoDB engine.
        // https://docs.rs/sqlx/latest/sqlx/attr.test.html
        // Some articles on the topic: https://wtjungle.com/blog/integration-testing-rocket-sqlx/
        let mut email = create_random_string(50).to_owned();
        email.push_str("@test.com");
        // This will try to load the state from the file system or create a new one if it fails.
        let ca_ck = pki::init_ca();
        // Create a client certificate on the fly to test the server.
        let (_, request) = pki::crypto::mk_client_certificate_request_params(&email).unwrap();
        let test_client_cert = pki::crypto::sign_request(request, &ca_ck).unwrap();
        (test_client_cert.pem(), email.to_string())
    }

    /// Send a valid create user request and return the response.
    fn create_test_user<'r>(
        client: &'r Client,
        client_credential_pem: &str,
        email: &str,
    ) -> rocket::local::blocking::LocalResponse<'r> {
        client
            .post("/users")
            .header(ContentType::JSON)
            .identity(client_credential_pem.as_bytes())
            .body(
                serde_json::to_string_pretty(&CreateUserRequest {
                    email: email.to_string(),
                })
                .unwrap(),
            )
            .dispatch()
    }

    // Send a valid get users request and return the response body parsed.
    fn list_users<'r>(client: &Client, client_credential_pem: &str) -> ListUsersResponse {
        let response = client
            .get("/users")
            .identity(client_credential_pem.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.body().is_some());
        response
            .into_json::<ListUsersResponse>()
            .expect("Valid users list")
    }

    #[test]
    fn post_users_unhautorized() {
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = client.post("/users").header(ContentType::JSON).dispatch();
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    fn post_users_bad_request() {
        let (client_credential_pem, _) = create_client_credentials();
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = client
            .post("/users")
            .header(ContentType::JSON)
            .identity(client_credential_pem.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn users_create_list_conflict() {
        let (client_credential_pem, email) = create_client_credentials();
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = create_test_user(&client, &client_credential_pem, &email);
        assert_eq!(response.status(), Status::Created);
        let get_user_response_1 = list_users(&client, &client_credential_pem);
        assert!(get_user_response_1.emails.contains(&email));
        let response = create_test_user(&client, &client_credential_pem, &email);
        assert_eq!(response.status(), Status::Conflict);
        let get_user_response_2 = list_users(&client, &client_credential_pem);
        assert!(
            get_user_response_2
                .emails
                .iter()
                .filter(|e| e == &&email)
                .collect::<Vec<_>>()
                .len()
                == 1
        );
    }

    /// Create a random folder name of 36 characters (see the database limits).
    fn random_folder_name() -> String {
        create_random_string(36)
    }

    #[test]
    fn folders_unauthorized() {
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = client.post("/folders").dispatch();
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    fn post_folders_bad_request() {
        let (client_credential_pem, _) = create_client_credentials();
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = client
            .post("/folders")
            .identity(client_credential_pem.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::BadRequest);
    }

    fn post_folder_create<'r>(
        client: &'r Client,
        client_credential_pem: &str,
        folder_name: &str,
    ) -> rocket::local::blocking::LocalResponse<'r> {
        client
            .post("/folders")
            .identity(client_credential_pem.as_bytes())
            .body(
                serde_json::to_string_pretty(&CreateFolderRequest {
                    name: folder_name.to_string(),
                })
                .unwrap(),
            )
            .dispatch()
    }

    fn list_folders(client: &Client, client_credential_pem: &str) -> ListFolderResponse {
        let response = client
            .get("/folders")
            .identity(client_credential_pem.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.body().is_some());
        response
            .into_json::<ListFolderResponse>()
            .expect("Valid folders list")
    }

    #[test]
    fn folders_create_list_conflict() {
        let (client_credential_pem, email) = create_client_credentials();
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = create_test_user(&client, &client_credential_pem, &email);
        assert_eq!(response.status(), Status::Created);
        let folder_name = random_folder_name();
        let create_folder_response_1 =
            post_folder_create(&client, &client_credential_pem, &folder_name);
        assert_eq!(create_folder_response_1.status(), Status::Created);
        log::debug!("Response: {:?}", create_folder_response_1.into_string());
        let response = list_folders(&client, &client_credential_pem);
        assert!(response
            .folders
            .iter()
            .any(|folder| folder.name == folder_name));
        assert!(response.folders.len() == 1);
        let create_folder_response_2 =
            post_folder_create(&client, &client_credential_pem, &folder_name);
        assert_eq!(create_folder_response_2.status(), Status::Conflict);
        let response = list_folders(&client, &client_credential_pem);
        assert!(response
            .folders
            .iter()
            .any(|folder| folder.name == folder_name));
        assert!(response.folders.len() == 1);
    }

    fn get_folder_by_id<'r>(
        client: &'r Client,
        client_credential_pem: &str,
        id: u64,
    ) -> rocket::local::blocking::LocalResponse<'r> {
        let path = format!("/folders/{}", id);
        client
            .get(path)
            .identity(client_credential_pem.as_bytes())
            .dispatch()
    }

    #[test]
    fn user_cannot_see_other_users_folde_but_shared_ones() {
        let (client_credential_pem, email) = create_client_credentials();
        let client = Client::tracked(init_server_from_config()).expect("valid rocket instance");
        let response = create_test_user(&client, &client_credential_pem, &email);
        assert_eq!(response.status(), Status::Created);
        let (client_credential_pem_2, email_2) = create_client_credentials();
        let response = create_test_user(&client, &client_credential_pem_2, &email_2);
        assert_eq!(response.status(), Status::Created);
        let folder_name = random_folder_name();
        let create_folder_response_1 =
            post_folder_create(&client, &client_credential_pem, &folder_name);
        assert_eq!(create_folder_response_1.status(), Status::Created);
        let create_response_content = create_folder_response_1
            .into_json::<CreateFolderResponse>()
            .unwrap();
        let folder_name_2 = random_folder_name();
        let create_folder_response_2 =
            post_folder_create(&client, &client_credential_pem_2, &folder_name_2);
        assert_eq!(create_folder_response_2.status(), Status::Created);
        let create_response_content_2 = create_folder_response_2
            .into_json::<CreateFolderResponse>()
            .unwrap();
        let response = list_folders(&client, &client_credential_pem);
        assert!(response
            .folders
            .iter()
            .all(|folder| folder.name == folder_name && folder.id == create_response_content.id));
        assert_eq!(response.folders.len(), 1);
        let response = list_folders(&client, &client_credential_pem_2);
        assert!(response.folders.iter().any(
            |folder| folder.name == folder_name_2 && folder.id == create_response_content_2.id
        ));
        assert_eq!(response.folders.len(), 1);
        let response = get_folder_by_id(
            &client,
            &client_credential_pem,
            create_response_content_2.id,
        );
        assert_eq!(response.status(), Status::NotFound);
        let response =
            get_folder_by_id(&client, &client_credential_pem, create_response_content.id);
        assert_eq!(response.status(), Status::Ok);
        let folder_response = response.into_json::<FolderResponse>().unwrap();
        assert_eq!(folder_response.name, folder_name);
        // Share the folder 1 with the second user.
        let share_path = format!("/folders/{}", create_response_content.id);
        let shared_response = client
            .patch(share_path)
            .identity(client_credential_pem.as_bytes())
            .body(
                serde_json::to_string_pretty(&ds::server::ShareFolderRequest {
                    emails: vec![email_2],
                })
                .unwrap(),
            )
            .dispatch();
        assert_eq!(shared_response.status(), Status::Ok);
        let response = get_folder_by_id(
            &client,
            &client_credential_pem_2,
            create_response_content.id,
        );
        assert_eq!(response.status(), Status::Ok);
        let folder_response = response.into_json::<FolderResponse>().unwrap();
        assert_eq!(folder_response.name, folder_name);
        let folders = list_folders(&client, &client_credential_pem_2);
        assert_eq!(folders.folders.len(), 2);
    }
}
