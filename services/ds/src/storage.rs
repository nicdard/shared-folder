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
use std::{env, time::Duration};

use object_store::{
    aws::{AmazonS3, AmazonS3Builder, DynamoCommit, S3ConditionalPut},
    local::LocalFileSystem,
    path::Path,
    ClientOptions, ObjectMeta, ObjectStore, PutMode, PutPayload, UpdateVersion,
};
use tokio::sync::MutexGuard;

use crate::db::FolderEntity;

/// The dynamic store type. This is used to abstract the object store implementation.
pub type DynamicStore = Box<dyn ObjectStore + Send + Sync + 'static>;

/// The configuration provider of the object store for [`Rocket`](https://rocket.rs/guide/v0.5/configuration/#extracting-values).
/// The configuration is loaded from the `DS_Rocket.toml` file.
/// This structure should be used with the [`AdHoc`](https://rocket.rs/v0.5-rc/guide/fairings/#ad-hoc-fairings) fairing.
#[derive(Debug, serde::Deserialize)]
#[non_exhaustive]
pub struct StoreConfig {
    /// fallback on file system active?
    #[serde(default = "Default::default")]
    fs_fallback: bool,
    /// The S3 storage configuration.
    s3_storage: Option<S3Config>,
}

/// The S3 configuration.
#[derive(Debug, serde::Deserialize)]
#[non_exhaustive]
pub struct S3Config {
    /// The S3 bucket name.
    pub bucket: String,
    /// The S3 endpoint.
    pub endpoint: String,
    /// The S3 access key ID.
    pub access_key_id: String,
    /// The S3 secret access key.
    pub secret_access_key: String,
}

/// The parameters for writing a file in the storage.
/// The file content is optional to allow for metadata only updates.
#[derive(Debug)]
pub struct WriteInput<'r> {
    /// The folder entity.
    pub folder_entity: FolderEntity,
    /// The file id.
    pub file_id: &'r str,
    /// The optional file content.
    pub file_to_write: Option<Vec<u8>>,
    /// The metadata file metadata.
    pub metadata_file: Vec<u8>,
    /// The previous etag of the metadata file to which change applies.
    pub parent_etag: Option<String>,
    /// The previous version of the metadata file to which change applies.
    pub parent_version: Option<String>,
}

/// Initialise the S3 object store.
fn initialise_s3(config: S3Config) -> Result<AmazonS3, String> {
    AmazonS3Builder::new()
        .with_endpoint(config.endpoint)
        .with_access_key_id(config.access_key_id)
        .with_secret_access_key(config.secret_access_key)
        .with_bucket_name(config.bucket)
        .with_retry(object_store::RetryConfig {
            backoff: object_store::BackoffConfig::default(),
            max_retries: 1,
            retry_timeout: Duration::from_secs(60),
        })
        // We are testing with a local instance using Localstack!
        .with_client_options(ClientOptions::new().with_allow_invalid_certificates(true))
        // Use the etag to perform optimistic concurrency. Other option would be to use a Dynamo table.
        .with_conditional_put(S3ConditionalPut::Dynamo(
            DynamoCommit::new("test-table".to_string())
                .with_timeout(10_000)
                .with_max_clock_skew_rate(2),
        ))
        .build()
        .map_err(|e| e.to_string())
}

fn initialise_fs() -> Result<LocalFileSystem, String> {
    let mut current_dir = // env::current_dir().map_err(|e| e.to_string())?;
        env::temp_dir();
    current_dir.push("storage-data");
    std::fs::create_dir_all(&current_dir)
        .expect("Could not create storage-data folder for the LocalFileSystem storage type.");
    LocalFileSystem::new_with_prefix(current_dir).map_err(|e| e.to_string())
}

/// Initialise the object store from the configuration.
/// If the configuration is invalid an error is returned.
pub fn initialise_object_store(config: StoreConfig) -> Result<DynamicStore, String> {
    if let Some(s3_config) = config.s3_storage {
        let object_store = initialise_s3(s3_config)?;
        return Ok(Box::new(object_store));
    } else {
        if config.fs_fallback {
            return Ok(Box::new(initialise_fs()?));
        }
        Err("No object store configuration provided".to_string())
    }
}

/// The metadata file name.
/// The metadata file is stored directly in the root of the bucket/<folder_id>/
const METADATA_FILE_NAME: &'static str = "metadata";
pub fn is_metadata_file_name(name: &str) -> bool {
    name == METADATA_FILE_NAME
}

/// Initialise an empty metadata file for a folder.
pub async fn init_metadata<'a>(
    object_store: &MutexGuard<'a, DynamicStore>,
    folder_entity: FolderEntity,
    metadata_file: Vec<u8>,
) -> Result<(Option<String>, Option<String>), object_store::Error> {
    write(
        &object_store,
        WriteInput {
            folder_entity,
            file_id: "", // Ignored as the content is None.
            file_to_write: None,
            metadata_file,
            // At the beginning, create an empty metadata file to return the etag and version to the client.
            // This prevents the client from re-creating a new metadata file from scratch during a file upload operation.
            parent_etag: None,
            parent_version: None,
        },
    )
    .await
}

/// Writes a file in the folder together with the updated metadata.
/// The object_store reference is syncrhonized with a mutex.
pub async fn write<'a>(
    object_store: &MutexGuard<'a, DynamicStore>,
    write_input: WriteInput<'_>,
) -> Result<(Option<String>, Option<String>), object_store::Error> {
    log::debug!("Attempting to write to object store `{:?}`.", &write_input);
    // We use a form of optimistic concurrency control. We could allow a more fine-grained
    // control over the single file, if the server would have a certain degree of access into the metadata file.
    let metadata_location = get_location_for_metadata_file(&write_input.folder_entity);
    let metadata_payload = PutPayload::from_bytes(write_input.metadata_file.into());
    let put_result = if write_input.parent_etag.is_some() || write_input.parent_version.is_some() {
        log::info!(
            "Try to write a new version of the metadata file for folder `{}`",
            &write_input.folder_entity.folder_id,
        );
        let version = UpdateVersion {
            e_tag: write_input.parent_etag,
            version: write_input.parent_version,
        };
        log::debug!("Metadata version `{:?}`", &version);
        object_store
            .put_opts(
                &metadata_location,
                metadata_payload,
                PutMode::Update(version).into(),
            )
            .await?
    } else {
        log::info!(
            "Try creating the metadata object for the first time for folder `{}`",
            &write_input.folder_entity.folder_id
        );
        object_store
            .put_opts(&metadata_location, metadata_payload, PutMode::Create.into())
            .await?
    };
    log::debug!("Metadata file written successfully! `{:?}", &put_result);
    put_result
        .e_tag
        .clone()
        .or(put_result.version.clone())
        .expect(
            "At least one of etag or version should be present after writing the metadata file!",
        );
    let file_location = get_location_for_file(&write_input.folder_entity, write_input.file_id);
    if let Some(file) = write_input.file_to_write {
        log::debug!("Attempting to write file `{}`", &file_location);
        let file_payload = PutPayload::from_bytes(file.into());
        object_store.put(&file_location, file_payload).await?;
    }
    Ok((put_result.e_tag, put_result.version))
}

/// Reads a file from the object store.
pub async fn read_file<'a>(
    object_store: &MutexGuard<'a, DynamicStore>,
    folder_entity: &FolderEntity,
    file_id: &str,
) -> Result<(Vec<u8>, ObjectMeta), object_store::Error> {
    let location = get_location_for_file(folder_entity, file_id);
    log::debug!("Attempting to read from `{}`", &location);
    let result = object_store.get(&location).await?;
    let meta = result.meta.clone();
    let bytes = result.bytes().await?;
    Ok((bytes.into(), meta))
}

/// Reads the metadata of a folder.
/// Do not deserialize the metadata file here, just return the bytes to the client.
pub async fn read_metadata<'a>(
    object_store: &MutexGuard<'a, DynamicStore>,
    folder_entity: &FolderEntity,
) -> Result<(Vec<u8>, ObjectMeta), object_store::Error> {
    read_file(object_store, &folder_entity, METADATA_FILE_NAME).await
}

/// Reads the metadata version of a folder.
async fn read_metadata_version<'a>(
    object_store: &MutexGuard<'a, DynamicStore>,
    folder_entity: &FolderEntity,
) -> Result<ObjectMeta, object_store::Error> {
    let location = get_location_for_metadata_file(&folder_entity);
    log::debug!(
        "Attempting to read versions for metadata file from `{}`",
        &location
    );
    object_store.head(&location).await
}

/// Get the location of a file in the object store, given the [`FolderEntity`] and the file id.
fn get_location_for_file(folder_entity: &FolderEntity, file_id: &str) -> Path {
    Path::from(format!(
        "{}/{}",
        get_folder_name_prefix(folder_entity),
        file_id
    ))
}

/// Get the folder name inside the object store from the folder entity.
/// Prefix the folder name with the folder ID to break disambiguation.
/// Maintain a Url like structure.
fn get_folder_name_prefix(folder_entity: &FolderEntity) -> String {
    format!("/{}", folder_entity.folder_id)
}

/// The metadata file name.
/// The metadata file is stored directly in the root of the bucket/<folder_id>/
/// The metadata file is sent encrypted from the client.
/// Each file is identified by an identifier in the server and the real name is stored only inside the metadata encrypted file.
fn get_location_for_metadata_file(folder_entity: &FolderEntity) -> Path {
    get_location_for_file(folder_entity, METADATA_FILE_NAME)
}

#[cfg(test)]
mod tests {

    use object_store::Error;
    use rand::distributions::{Alphanumeric, DistString};
    use tokio::sync::Mutex;

    /// Create a random string.
    fn create_random_string(len: usize) -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), len)
    }

    /// Create a random file name of 10 characters.
    fn create_random_file_name() -> String {
        create_random_string(10)
    }

    /// Create a random file id.
    fn create_random_file_id() -> u64 {
        rand::random::<u64>()
    }

    use super::*;

    pub fn setup() -> DynamicStore {
        let _ = env_logger::builder().is_test(true).try_init();
        let config = StoreConfig {
            fs_fallback: true,
            s3_storage: Some(S3Config {
                bucket: "test-bucket".to_string(),
                endpoint: "https://localhost:4566".to_string(),
                access_key_id: "test".to_string(),
                secret_access_key: "test".to_string(),
            }),
        };
        initialise_object_store(config).unwrap()
    }

    #[test]
    fn test_initialise_object_store() {
        let store = setup();
        assert!(store.to_string().contains("AmazonS3"));
        assert!(store.to_string().contains("test"));
        assert!(store.to_string().contains("test-bucket"));
    }

    fn setup_local_fs() -> DynamicStore {
        let _ = env_logger::builder().is_test(true).try_init();
        let config = StoreConfig {
            fs_fallback: true,
            s3_storage: None,
        };
        initialise_object_store(config).unwrap()
    }

    #[test]
    fn test_fallback_fs() {
        let store = setup_local_fs();
        assert!(store.to_string().contains("LocalFileSystem"));
    }

    /// You will need to start `Localstack` provided in services/docker-compose.yaml file to run this test.
    #[tokio::test]
    async fn test_write_file_with_metadata() {
        let store = setup();
        let store = Mutex::new(store);
        let folder_id = create_random_file_id();
        let folder_entity = FolderEntity { folder_id };
        let file_name = create_random_file_name();
        let write_input = WriteInput {
            folder_entity: folder_entity.clone(),
            file_id: &file_name,
            file_to_write: Some(b"test-file".to_vec()),
            metadata_file: b"test-metadata".to_vec(),
            parent_etag: None,
            parent_version: None,
        };
        let store = store.lock().await;
        let result = write(&store, write_input).await.unwrap();
        assert!(result.0.is_some() || result.1.is_some());
        let metadata_version = read_metadata_version(&store, &folder_entity).await.unwrap();
        log::debug!("Metadata `{:?}`", metadata_version);
        assert_eq!(metadata_version.e_tag, result.0);
        assert_eq!(metadata_version.version, result.1);
        let conflict_write = WriteInput {
            folder_entity,
            file_id: &file_name,
            file_to_write: Some(b"test-file-updated".to_vec()),
            metadata_file: b"test-metadata-updated".to_vec(),
            parent_etag: Some("some-etag".to_string()),
            parent_version: Some("some-version".to_string()),
        };
        let result_2 = write(&store, conflict_write).await;
        assert!(result_2.is_err());
        match result_2 {
            Err(Error::Precondition { .. }) => (),
            otherwise => {
                log::error!("Got an unexpected result `{:?}`", otherwise);
                panic!("Unexpected error, this should lead to a conflict!");
            }
        }
    }
}
