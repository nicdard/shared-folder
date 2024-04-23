use object_store::aws::AmazonS3Builder;

/// The configuration provider of the object store for [`Rocket`](https://rocket.rs/guide/v0.5/configuration/#extracting-values).
/// The configuration is loaded from the `DS_Rocket.toml` file.
/// This structure should be used with the [`AdHoc`](https://rocket.rs/v0.5-rc/guide/fairings/#ad-hoc-fairings) fairing.
#[derive(Debug, serde::Deserialize)]
#[non_exhaustive]
pub struct StoreConfig {
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

/// Initialise the object store from the configuration.
pub fn initialise_object_store(
    config: StoreConfig,
) -> Result<Box<dyn object_store::ObjectStore>, String> {
    if let Some(s3_config) = config.s3_storage {
        initialise_s3(s3_config)
    } else {
        Err("No object store configuration provided".to_string())
    }
}

/// Initialise the S3 object store.
fn initialise_s3(config: S3Config) -> Result<Box<dyn object_store::ObjectStore>, String> {
    let s3 = AmazonS3Builder::new()
        .with_endpoint(config.endpoint)
        .with_access_key_id(config.access_key_id)
        .with_secret_access_key(config.secret_access_key)
        .with_bucket_name(config.bucket)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(Box::new(s3))
}

#[cfg(test)]
mod tests {

    use super::*;

    fn setup() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_initialise_object_store() {
        setup();
        let config = StoreConfig {
            s3_storage: Some(S3Config {
                bucket: "test-bucket".to_string(),
                endpoint: "test-endpoint".to_string(),
                access_key_id: "test-access_key_id".to_string(),
                secret_access_key: "test-secret_access_key".to_string(),
            }),
        };
        let store = initialise_object_store(config).unwrap();
        assert!(store.to_string().contains("test-"));
    }
}
