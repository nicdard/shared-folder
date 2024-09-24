#![cfg(all(mls_build_async))]

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, OnceLock};

use mls_rs::client_builder::ClientBuilder;
use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs::storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage};
use mls_rs::{CipherSuiteProvider, CryptoProvider, ExtensionList, GroupStateStorage};

use mls_rs::identity::SigningIdentity;
use mls_rs::{
    client_builder::MlsConfig,
    error::MlsError,
    identity::basic::{BasicCredential, BasicIdentityProvider},
    mls_rules::{CommitOptions, DefaultMlsRules},
    CipherSuite, Client,
};
use mls_rs_core::key_package;

use crate::log;

const CIPHERSUITE: CipherSuite = CipherSuite::P256_AES128;

fn webcrypto() -> impl CryptoProvider + Clone {
    mls_rs_crypto_webcrypto::WebCryptoProvider::default()
}

fn cipher_suite() -> impl CipherSuiteProvider {
    webcrypto()
        .cipher_suite_provider(CIPHERSUITE)
        .expect("Ciphersuite is not supported!")
}

/// Keep the state of a Client in memory.
struct ClientInMemoryState {
    group_storage: InMemoryGroupStateStorage,
    key_package_repo: InMemoryKeyPackageStorage,
    signer: SigningIdentity,
    signer_secret_key: SignatureSecretKey,
}

/**
 * For now keep the state in a global map, so that we can re-use between invocations to the WASM module.
 * Obviously the appropriate solution would be to write a localStorage or better IndexedDB-based
 * storage module for aws mls-rs using web_sys crate.
 */
fn clients_state() -> &'static Mutex<HashMap<Vec<u8>, ClientInMemoryState>> {
    static CLIENTS_STATE: OnceLock<Mutex<HashMap<Vec<u8>, ClientInMemoryState>>> = OnceLock::new();
    CLIENTS_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/**
 * For now keep the state in a global map, so that we can re-use between invocations to the WASM module.
 * Obviously the appropriate solution would be to write a localStorage or better IndexedDB-based
 * storage module for aws mls-rs using web_sys crate.
 */
fn in_memory_group_state_storage_map() -> &'static Mutex<HashMap<Vec<u8>, InMemoryGroupStateStorage>>
{
    static GROUP_STORAGES: OnceLock<Mutex<HashMap<Vec<u8>, InMemoryGroupStateStorage>>> =
        OnceLock::new();
    GROUP_STORAGES.get_or_init(|| Mutex::new(HashMap::new()))
}

/**
 * For now keep the state in a global map, so that we can re-use between invocations to the WASM module.
 * Obviously the appropriate solution would be to write a localStorage or better IndexedDB-based
 * storage module for aws mls-rs using web_sys crate.
 */
fn in_memory_key_package_map() -> &'static Mutex<HashMap<Vec<u8>, InMemoryKeyPackageStorage>> {
    static KEY_PACKAGES: OnceLock<Mutex<HashMap<Vec<u8>, InMemoryKeyPackageStorage>>> =
        OnceLock::new();
    KEY_PACKAGES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn get_client_default_state(name: &[u8]) -> ClientInMemoryState {
    let cipher_suite = cipher_suite();

    // Generate a signature key pair.
    let (signer_secret_key, public) = cipher_suite
        .signature_key_generate()
        .await
        .expect("should generate the keys");

    // Create a basic credential for the session.
    // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
    // X.509 credentials are recommended.
    let basic_identity = BasicCredential::new(name.to_owned());
    let signer = SigningIdentity::new(basic_identity.into_credential(), public);

    ClientInMemoryState {
        group_storage: InMemoryGroupStateStorage::new(),
        key_package_repo: InMemoryKeyPackageStorage::new(),
        signer,
        signer_secret_key,
    }
}

/// Generate (or retrieve) a client and store it in a global map to avoid loosing its state between
/// invocations as the client is using the in memory storage providers. This allows the compiled WASM
/// to work with the in memory storage providers for now.
/// The client will be associated with the name of the user creating it,
/// however for now we are using only [`BasicCredential`] which do not provide
/// any authentication. We should instead write an [`IdentityProvider`] from our X509 credentials.
pub async fn get_client(name: &[u8]) -> Result<Client<impl MlsConfig>, MlsError> {
    let crypto_provider = webcrypto();

    let mut clients_state = clients_state().lock().expect("Clients state corrupted!");
    let client_state = clients_state
        .entry(name.to_owned())
        .or_insert(get_client_default_state(name).await);

    Ok(ClientBuilder::default()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider)
        // All clones of the [`InMemoryGroupStateStorage`] will share the same underlying map.
        .group_state_storage(client_state.group_storage.clone())
        .key_package_repo(client_state.key_package_repo.clone())
        //.mls_rules(
        //    DefaultMlsRules::new()
        //        .with_commit_options(CommitOptions::new().with_path_required(true)),
        // )
        .signing_identity(
            client_state.signer.clone(),
            client_state.signer_secret_key.clone(),
            CIPHERSUITE,
        )
        .build())
}

/// Initialise a new mls group with the given uid.
/// The client identity initiating the creation is provided so that we can retrieve it from the Global state (storage).
/// Returns the starting epoch.
/// Achtung! Calling this function multiple times for the same user and with the same group id will overwrite the group state!.
pub async fn cgka_init(identity: &[u8], group_uid: &[u8]) -> Result<u64, MlsError> {
    let client = get_client(identity).await?;
    let mut group = client
        .create_group_with_id(group_uid.to_owned(), ExtensionList::default())
        .await?;
    group.write_to_storage().await?;
    Ok(group.current_epoch())
}

#[cfg(test)]
mod test {

    // When targeting Browser
    // wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use std::{fmt::format, future::IntoFuture};

    use mls_rs::{error::MlsError, ExtensionList, GroupStateStorage};

    use crate::{log, mls::get_client, utils::set_panic_hook};

    use super::cgka_init;

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_cgka_init() -> Result<(), MlsError> {
        set_panic_hook();
        let identity = b"alice";
        let group_uid_0 = b"0";
        let epoch_0 = cgka_init(identity, group_uid_0).await?;
        let client_0 = get_client(identity).await?;
        let mut group_0 = client_0.load_group(group_uid_0).await?;
        let bob = get_client(b"bob").await?;
        let bob_key_package = bob.generate_key_package_message().await?;
        let _ = group_0
            .commit_builder()
            .add_member(bob_key_package)?
            .build()
            .await?;
        group_0.apply_pending_commit().await?;
        // Confirm that the group state advanced.
        assert_ne!(group_0.current_epoch(), epoch_0);
        // Attention: you can overwrite the state of a group!.
        let epoch_1 = cgka_init(identity, group_uid_0).await?;
        assert_eq!(epoch_0, epoch_1);
        Ok(())
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn mls_test() {
        set_panic_hook();
        let _ = get_client(b"Alice")
            .await
            .expect("Couldn't create a client!");
    }

    /*#[wasm_bindgen_test::wasm_bindgen_test]
    async fn mls_example_test() {
        pub async fn example() -> Result<Vec<u8>, MlsError> {
            let alice = get_client(b"alice").await?;
            let bob = get_client(b"bob").await?;
            let mut alice_group = alice.create_group(ExtensionList::default()).await?;
            alice_group.write_to_storage().await?;
            let bob_key_package = bob.generate_key_package_message().await?;
            let alice_commit = alice_group
                .commit_builder()
                .add_member(bob_key_package)?
                .build()
                .await?;
            alice_group.apply_pending_commit().await?;
            let (mut bob_group, _) = bob
                .join_group(None, &alice_commit.welcome_messages[0])
                .await?;
            alice_group.write_to_storage().await?;
            bob_group.write_to_storage().await?;

            Ok(alice_group
                .export_secret(b"exported_secret", b"hash_context", 256)
                .await?
                .as_bytes()
                .to_owned())
        }
    }
    */
}
/*

*/

/*
// InMemeoryGroupStateStorage::state returns the serailized version of the group state to save in db.

const CREDENTIAL_V1: CredentialType = CredentialType::new(65002);

#[derive(Debug)]
/// Error returned in the event that a non-custom invalid credential is passed to a [`WebCustomX509IdentityProvider`].
pub struct WebCustomX509IdentityProviderError(CredentialType);

impl IntoAnyError for WebCustomX509IdentityProviderError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl fmt::Display for WebCustomX509IdentityProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid identity!")
    }
}

impl Error for WebCustomX509IdentityProviderError {}

impl WebCustomX509IdentityProviderError {
    pub fn credential_type(&self) -> CredentialType {
        self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WebCustomX509IdentityProvider;

impl IdentityProvider for WebCustomX509IdentityProvider {
    type Error = WebCustomX509IdentityProviderError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        let Credential::Custom(custom) = &signing_identity.credential else {
            return Err(WebCustomX509IdentityProviderError(
                signing_identity.credential.credential_type(),
            ));
        };

        if custom.credential_type != CREDENTIAL_V1 {
            return Err(WebCustomX509IdentityProviderError(
                signing_identity.credential.credential_type(),
            ));
        }

        check_signature(&String::from_utf8(custom.data));

        Ok(())
    }

    #[doc = " Determine if `signing_identity` is valid for an external sender in"]
    #[doc = " the ExternalSendersExtension stored in the group context."]
    #[doc = ""]
    #[doc = " A `timestamp` value can optionally be supplied to aid with validation"]
    #[doc = " of a [`Credential`](mls-rs-core::identity::Credential) that requires"]
    #[doc = " time based context. For example, X.509 certificates can become expired."]
    #[must_use]
    #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
    fn validate_external_sender<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        signing_identity: &'life1 SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&'life2 ExtensionList>,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<(), Self::Error>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        todo!()
    }

    #[doc = " A unique identifier for `signing_identity`."]
    #[doc = ""]
    #[doc = " The MLS protocol requires that each member of a group has a unique"]
    #[doc = " set of identifiers according to the application."]
    #[must_use]
    #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
    fn identity<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        signing_identity: &'life1 SigningIdentity,
        extensions: &'life2 ExtensionList,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Vec<u8>, Self::Error>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        todo!()
    }

    #[doc = " Determines if `successor` can remove `predecessor` as part of an external commit."]
    #[doc = ""]
    #[doc = " The MLS protocol allows for removal of an existing member when adding a"]
    #[doc = " new member via external commit. This function determines if a removal"]
    #[doc = " should be allowed by providing the target member to be removed as"]
    #[doc = " `predecessor` and the new member as `successor`."]
    #[must_use]
    #[allow(clippy::type_complexity, clippy::type_repetition_in_bounds)]
    fn valid_successor<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        predecessor: &'life1 SigningIdentity,
        successor: &'life2 SigningIdentity,
        extensions: &'life3 ExtensionList,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<bool, Self::Error>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        todo!()
    }

    #[doc = " Credential types that are supported by this provider."]
    fn supported_types(&self) -> Vec<CredentialType> {
        todo!()
    }
}
*/
