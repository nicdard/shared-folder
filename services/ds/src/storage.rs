use std::env;

use object_store::{
    aws::{AmazonS3, AmazonS3Builder},
    local::LocalFileSystem,
    path::Path,
    ObjectStore,
};
use rocket::fs::TempFile;

use crate::db::FolderEntity;

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

/**
 * The object store.
 * Wrapping the [`ObjectStore`][`ObjectStore`] trait.
 */
pub struct Store {
    /// The store configuration.
    // config: StoreConfig,
    /// The wrapped object store.
    object_store: Box<dyn ObjectStore>,
}

/// The parameters for writing a file in the storage.
pub struct WriteInput<'r> {
    /// The folder entity.
    folder_entity: FolderEntity,
    /// The file name.
    file_to_write: TempFile<'r>,
    /// The metadata file metadata.
    metadata_file: TempFile<'r>,
}

impl Store {
    /// Initialise the S3 object store.
    fn initialise_s3(config: S3Config) -> Result<AmazonS3, String> {
        AmazonS3Builder::new()
            .with_endpoint(config.endpoint)
            .with_access_key_id(config.access_key_id)
            .with_secret_access_key(config.secret_access_key)
            .with_bucket_name(config.bucket)
            .build()
            .map_err(|e| e.to_string())
    }

    fn initialise_fs() -> Result<LocalFileSystem, String> {
        let current_dir = env::current_dir().map_err(|e| e.to_string())?;
        LocalFileSystem::new_with_prefix(current_dir).map_err(|e| e.to_string())
    }

    /// Initialise the object store from the configuration.
    /// If the configuration is invalid an error is returned.
    pub fn initialise_object_store(config: StoreConfig) -> Result<Self, String> {
        if let Some(s3_config) = config.s3_storage {
            let object_store = Store::initialise_s3(s3_config)?;
            return Ok(Self {
                object_store: Box::new(object_store),
            });
        } else {
            if config.fs_fallback {
                return Ok(Self {
                    object_store: Box::new(Store::initialise_fs()?),
                });
            }
            Err("No object store configuration provided".to_string())
        }
    }

    pub async fn write_file_with_metadata(self, write_input: WriteInput<'_>) -> Result<(), String> {
        let folder_name = Store::get_folder_name_prefix(write_input.folder_entity);
        log::debug!("Attempting to write in folder `{}`", &folder_name);
        // [`ObjectMeta`]
        /*let location = Store::metadata_file_name(&folder_name);
        let version = UpdateVersion {
            e_tag: write_input.etag,
            version: write_input.etag,
        };
        self.object_store.put_opts(&location, payload, opts);
        */
        unimplemented!();
    }

    /// Reads a file from the object store.
    pub async fn read_file(
        self,
        folder_entity: FolderEntity,
        file_name: &str,
    ) -> Result<Vec<u8>, String> {
        let folder_name = Store::get_folder_name_prefix(folder_entity);
        log::debug!("Attempting to read from folder `{}`", &folder_name);
        let location = Path::from(format!("{}/{}", folder_name, file_name));
        let result = self
            .object_store
            .get(&location)
            .await
            .map_err(|e| e.to_string())?;
        let bytes = result.bytes().await.map_err(|e| e.to_string())?;
        Ok(bytes.into())
    }

    /// Get the folder name inside the object store from the folder entity.
    /// Prefix the folder name with the folder ID to break disambiguation.
    /// Maintain a Url like structure.
    fn get_folder_name_prefix(folder_entity: FolderEntity) -> String {
        format!("/{}/{}", folder_entity.folder_id, folder_entity.folder_name)
    }

    /// The metadata file name.
    /// The metadata file is stored directly in the root of the bucket/<folder_id>/<folder_name>
    /// The metadata file is sent encrypted from the client.
    /// Each file is identified by an identifier in the server and the real name is stored only inside the metadata encrypted file.
    fn metadata_file_name(prefix: &str) -> Path {
        Path::from(format!("{}/metadata", prefix))
    }
}

/// Implement the [`ToString`]
/// Delegate the implementation to the [`ObjectStore`][`ObjectStore`] trait.
impl ToString for Store {
    fn to_string(&self) -> String {
        format!("ObjectStore: {}", self.object_store.to_string())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn setup() -> Store {
        let _ = env_logger::builder().is_test(true).try_init();
        let config = StoreConfig {
            fs_fallback: true,
            s3_storage: Some(S3Config {
                bucket: "test-bucket".to_string(),
                endpoint: "test-endpoint".to_string(),
                access_key_id: "test-access_key_id".to_string(),
                secret_access_key: "test-secret_access_key".to_string(),
            }),
        };
        Store::initialise_object_store(config).unwrap()
    }

    #[test]
    fn test_initialise_object_store() {
        let store = setup();
        assert!(store.to_string().contains("AmazonS3"));
        assert!(store.to_string().contains("test-"));
    }

    #[test]
    fn test_fallback_fs() {
        let config = StoreConfig {
            fs_fallback: true,
            s3_storage: None,
        };
        let store = Store::initialise_object_store(config).unwrap();
        assert!(store.to_string().contains("LocalFileSystem"));
    }
}
