#![cfg(all(mls_build_async))]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use mls_rs::client_builder::ClientBuilder;
use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs::group::{self, ApplicationMessageDescription, ReceivedMessage};
use mls_rs::storage_provider::in_memory::{
    InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage,
};
use mls_rs::{
    CipherSuiteProvider, CryptoProvider, ExtensionList, Group, GroupStateStorage, KeyPackage,
};

use mls_rs::identity::SigningIdentity;
use mls_rs::MlsMessage;
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
use wasm_bindgen::prelude::*;

fn webcrypto() -> impl CryptoProvider + Clone {
    mls_rs_crypto_webcrypto::WebCryptoProvider::default()
}

fn cipher_suite() -> impl CipherSuiteProvider {
    webcrypto()
        .cipher_suite_provider(CIPHERSUITE)
        .expect("Ciphersuite is not supported!")
}

/// Keep the state of a Client in memory.
pub(crate) struct ClientInMemoryState {
    group_storage: InMemoryGroupStateStorage,
    key_package_repo: InMemoryKeyPackageStorage,
    psk_storage: InMemoryPreSharedKeyStorage,
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

pub async fn get_client_default_state(uid: &[u8]) -> ClientInMemoryState {
    let cipher_suite = cipher_suite();

    // Generate a signature key pair.
    let (signer_secret_key, public) = cipher_suite
        .signature_key_generate()
        .await
        .expect("should generate the keys");

    // Create a basic credential for the session.
    // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
    // X.509 credentials are recommended.
    let basic_identity = BasicCredential::new(uid.to_owned());
    let signer = SigningIdentity::new(basic_identity.into_credential(), public);

    ClientInMemoryState {
        group_storage: InMemoryGroupStateStorage::new(),
        key_package_repo: InMemoryKeyPackageStorage::new(),
        psk_storage: InMemoryPreSharedKeyStorage::default(),
        signer,
        signer_secret_key,
    }
}

/// Generate (or retrieve) a client and store it in a global map to avoid loosing its state between
/// invocations as the client is using the in memory storage providers. This allows the compiled WASM
/// to work with the in memory storage providers for now.
/// The client will be associated with the uid of the user creating it,
/// however for now we are using only [`BasicCredential`] which do not provide
/// any authentication. We should instead write an [`IdentityProvider`] from our X509 credentials.
pub async fn get_client(uid: &[u8]) -> Result<Client<impl MlsConfig>, MlsError> {
    let crypto_provider = webcrypto();

    let mut clients_state = clients_state().lock().expect("Clients state corrupted!");
    let client_state = clients_state
        .entry(uid.to_owned())
        .or_insert(get_client_default_state(uid).await);

    Ok(ClientBuilder::default()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider)
        // All clones of the [`InMemoryGroupStateStorage`] will share the same underlying map.
        .group_state_storage(client_state.group_storage.clone())
        .key_package_repo(client_state.key_package_repo.clone())
        .psk_store(client_state.psk_storage.clone())
        // Simplify adding new member, we generate one and only one welcome message to send to all.
        .mls_rules(
            DefaultMlsRules::new().with_commit_options(
                CommitOptions::new()
                    .with_single_welcome_message(true)
                    .with_ratchet_tree_extension(true),
            ),
        )
        .signing_identity(
            client_state.signer.clone(),
            client_state.signer_secret_key.clone(),
            CIPHERSUITE,
        )
        .build())
}

/// Initialise a new mls group with the given uid.
/// The client uid initiating the creation is provided so that we can retrieve it from the Global state (storage).
/// Returns the starting epoch.
/// Achtung! Calling this function multiple times for the same user and with the same group id will overwrite the group state!.
pub async fn cgka_init(uid: &[u8], group_id: &[u8]) -> Result<u64, MlsError> {
    let client = get_client(uid).await?;
    let mut group = client
        .create_group_with_id(group_id.to_owned(), ExtensionList::default())
        .await?;
    group.write_to_storage().await?;
    Ok(group.current_epoch())
}

/// Join a group from a Welcome message.
/// The welcome message can be generate with [`cgka_add_proposal`].
/// When the client joins the group, it saves to the storage the new group.
/// Returns the group_id.
pub async fn cgka_join_group(uid: &[u8], welcome_msg: &[u8]) -> Result<Vec<u8>, MlsError> {
    let client = get_client(uid).await?;
    let mls_msg = MlsMessage::from_bytes(welcome_msg)?;
    let (mut group, _) = client.join_group(None, &mls_msg).await?;
    group.write_to_storage().await?;
    Ok(group.group_id().to_vec())
}

/// Generate a new serialized key package [`MlsMessage`] for client `uid`.
pub async fn cgka_generate_key_package(uid: &[u8]) -> Result<Vec<u8>, MlsError> {
    let client = get_client(uid).await?;
    let key_package_msg = client.generate_key_package_message().await?;
    key_package_msg.to_bytes()
}

/// Represent the result of proposing to ADD a new user.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct AddProposalMessages {
    /// In the protocol description: W
    #[wasm_bindgen(js_name = welcomeMsg)]
    pub welcome_msg: Vec<u8>,
    /// In the protocol description: T
    #[wasm_bindgen(js_name = controlMsg)]
    pub control_msg: Vec<u8>,
}

/// Add a pending proposal to the group state and return the serialized welcome (W) and control (T) messages.
/// The `key_package_raw_msg` parameter is a serailized [`MlsMessage`] containing a [`KeyPackage`]
/// and can be obtained from [`cgka_generate_key_package`].
pub async fn cgka_add_proposal(
    uid: &[u8],
    group_id: &[u8],
    key_package_raw_msg: &[u8],
) -> Result<AddProposalMessages, MlsError> {
    let key_package_mls_msg = MlsMessage::from_bytes(key_package_raw_msg)?;
    let mut group = cgka_load_group(uid, group_id).await?;
    // It also verify for the message to be a valid key package.
    //let (commit, secrets) = group
    let commit = group
        .commit_builder()
        .add_member(key_package_mls_msg)?
        .build()
        //.build_detached()
        .await?;
    assert_eq!(1, commit.welcome_messages.len());
    // Instead of writing to storage, we could also use commit detached.
    // However, I feel it's better to keep the secret state of CGKA inside the Wasm module only
    // and avoid passing it around to JS.
    // This could be a viable option in case we want to fully detached to operate on a copy of CGKA
    // sort of, as described in the paper.
    group.write_to_storage().await?;
    let w_msg = commit.welcome_messages[0].to_bytes()?;
    let t_msg = commit.commit_message.to_bytes()?;
    // let secrets = secrets.to_bytes();
    Ok(AddProposalMessages {
        welcome_msg: w_msg,
        control_msg: t_msg,
    })
}

/// Propose and commit the removal of a member.
pub async fn cgka_remove_proposal(
    uid: &[u8],
    group_id: &[u8],
    identity: &[u8],
) -> Result<Vec<u8>, MlsError> {
    let mut group = cgka_load_group(uid, group_id).await?;
    let member = group.member_with_identity(identity).await?;
    let commit = group
        .commit_builder()
        .remove_member(member.index)?
        .build()
        .await?;
    group.write_to_storage().await?;
    let t_msg = commit.commit_message.to_bytes();
    t_msg
}

/// Propose and commit an update.
/// Update proposals are not necessary in this implementation, as we always immediately commit afterwards.
pub async fn cgka_update_proposal(uid: &[u8], group_id: &[u8]) -> Result<Vec<u8>, MlsError> {
    let mut group = cgka_load_group(uid, group_id).await?;
    let _ = group.propose_update(Vec::new()).await?;
    let commit = group.commit(Vec::new()).await?;
    group.write_to_storage().await?;
    let t_msg = commit.commit_message.to_bytes();
    t_msg
}

/// Apply a previously created pending commit.
///
/// Export the resulting secret and return it (256 bits).
pub async fn cgka_apply_pending_commit(uid: &[u8], group_id: &[u8]) -> Result<(), MlsError> {
    let mut group = cgka_load_group(uid, group_id).await?;
    let _ = group.apply_pending_commit().await?;
    group.write_to_storage().await
    /*group
    .export_secret(b"CGKA", b"GKP", 256)
    .await
    // Need to extract the underlying vector from the zeroing wrapper to return it...
    .map(|s| s.as_bytes().to_owned())*/
}

/// Delete the pending commit, if any is present in the state.
pub async fn cgka_delete_pending_commit(uid: &[u8], group_id: &[u8]) -> Result<(), MlsError> {
    let mut group = cgka_load_group(uid, group_id).await?;
    let _ = group.clear_pending_commit();
    group.write_to_storage().await
}

#[derive(Debug, Clone)]
#[wasm_bindgen]
pub enum ApplicationMsgAuthenticatedData {
    KpInt = 0,
    KpExt = 1,
    KpState = 2,
}

impl Into<Vec<u8>> for ApplicationMsgAuthenticatedData {
    fn into(self) -> Vec<u8> {
        match self {
            ApplicationMsgAuthenticatedData::KpInt => b"KP_INT".to_vec(),
            ApplicationMsgAuthenticatedData::KpExt => b"KP_EXT".to_vec(),
            ApplicationMsgAuthenticatedData::KpState => b"KP_STATE".to_vec(),
        }
    }
}

impl From<Vec<u8>> for ApplicationMsgAuthenticatedData {
    fn from(bytes: Vec<u8>) -> Self {
        let s = String::from_utf8(bytes).expect("The value is not utf-8 encoded.");
        match s.as_str() {
            "KP_INT" => ApplicationMsgAuthenticatedData::KpInt,
            "KP_EXT" => ApplicationMsgAuthenticatedData::KpExt,
            "KP_STATE" => ApplicationMsgAuthenticatedData::KpState,
            _ => panic!("Unexpected authenticated data for an application message."),
        }
    }
}

/// Prepares the message to be sent for the wire, needs "private_message" feature enabled,
/// otherwise the message will be sent in plain text.
pub async fn cgka_prepare_application_msg(
    uid: &[u8],
    group_id: &[u8],
    app_msg: &[u8],
    additional_authenticated_data: ApplicationMsgAuthenticatedData,
) -> Result<Vec<u8>, MlsError> {
    log(&format!(
        "Preparing application message with authenticated data: {:?}",
        additional_authenticated_data
    ));
    let mut group = cgka_load_group(uid, group_id).await?;
    let encrypted_signed_msg = group
        .encrypt_application_message(app_msg, additional_authenticated_data.into())
        .await?;
    encrypted_signed_msg.to_bytes()
}

/// Represent the result of proposing to ADD a new user.
#[wasm_bindgen(getter_with_clone)]
pub struct ApplicationMsg {
    #[wasm_bindgen(js_name = data)]
    pub data: Vec<u8>,
    #[wasm_bindgen(js_name = authenticatedData)]
    pub authenticated_data: ApplicationMsgAuthenticatedData,
}

impl From<ApplicationMessageDescription> for ApplicationMsg {
    fn from(value: ApplicationMessageDescription) -> Self {
        ApplicationMsg {
            data: value.data().to_owned(),
            authenticated_data: value.authenticated_data.into(),
        }
    }
}

/// Process an incoming message.
/// If the message is an application message, send the data back to
pub async fn cgka_process_incoming_msg(
    uid: &[u8],
    group_id: &[u8],
    message: &[u8],
) -> Result<Option<ApplicationMsg>, MlsError> {
    let mut group = cgka_load_group(uid, group_id).await?;
    let mls_msg = MlsMessage::from_bytes(message)?;
    let incoming = group.process_incoming_message(mls_msg).await?;
    log(&format!(
        "Processing incoming message for group: {:?}, incoming message: {:?}",
        group_id, incoming
    ));
    match incoming {
        ReceivedMessage::ApplicationMessage(app_msg) => Ok(Some(app_msg.into())),
        ReceivedMessage::Commit(cmt) => {
            log(&format!("Received a message from: {}", cmt.committer));
            group.write_to_storage().await?;
            Ok(None)
        }
        _ => Ok(None),
    }
    // TODO: should you apply the pending commits?
}

async fn cgka_load_group(uid: &[u8], group_id: &[u8]) -> Result<Group<impl MlsConfig>, MlsError> {
    let client = get_client(uid).await?;
    let group = client.load_group(group_id).await?;
    Ok(group)
}

#[cfg(test)]
mod test {

    // When targeting Browser
    // wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use std::{fmt::format, future::IntoFuture};

    use mls_rs::{
        client_builder::MlsConfig,
        crypto::{self, SignatureSecretKey},
        error::MlsError,
        identity::{basic::BasicIdentityProvider, SigningIdentity},
        CipherSuiteProvider, Client, ExtensionList,
    };
    use mls_rs_core::{identity::BasicCredential, key_package};

    use crate::{
        log,
        mls::{cgka_delete_pending_commit, cgka_load_group},
        mls_cgka_add_proposal, mls_cgka_apply_pending_commit, mls_cgka_delete_pending_commit,
        mls_cgka_init, mls_cgka_join_group, mls_cgka_update_proposal, mls_generate_key_package,
        mls_init_client,
        utils::set_panic_hook,
    };

    use super::{
        cgka_add_proposal, cgka_apply_pending_commit, cgka_generate_key_package, cgka_init,
        cgka_update_proposal, cipher_suite, get_client, webcrypto, CIPHERSUITE,
    };

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_random_values() {
        set_panic_hook();
        let mut buffer = vec![0; 32];
        cipher_suite().random_bytes(&mut buffer).unwrap();
        log(&format!("Random bytes: {:?}", buffer));
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_update_keys() -> Result<(), String> {
        let uid = vec![1u8, 2, 3, 4, 5];
        let group_id = vec![1u8, 2, 3, 4, 5];
        mls_init_client(&uid).await?;
        mls_cgka_init(&uid, &group_id).await?;
        let otherUid = vec![5u8, 4, 3, 2, 1];
        mls_init_client(&otherUid).await?;
        let keyPackage = mls_generate_key_package(&otherUid).await?;
        let proposal = mls_cgka_add_proposal(&uid, &group_id, &keyPackage).await?;
        log(&format!("Proposal: {:?}", proposal));
        mls_cgka_apply_pending_commit(&uid, &group_id).await?;
        mls_cgka_join_group(&otherUid, &proposal.welcome_msg).await?;
        log("Group with two members");
        mls_cgka_update_proposal(&uid, &group_id).await?;
        mls_cgka_apply_pending_commit(&uid, &group_id).await?;
        mls_cgka_update_proposal(&otherUid, &group_id).await?;
        mls_cgka_apply_pending_commit(&otherUid, &group_id).await?;
        Ok(())
    }

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

    // Check that we can commit pending commits between group loading from the storage.
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_pending_proposals_are_loaded() -> Result<(), MlsError> {
        set_panic_hook();
        let uid = b"alice";
        let other_uid = b"bob";
        let third_uid = b"bob2";
        let group_id = b"test_pending_proposals_are_loaded";
        cgka_init(uid, group_id).await?;
        let key_package = cgka_generate_key_package(other_uid).await?;
        cgka_add_proposal(uid, group_id, &key_package).await?;
        cgka_apply_pending_commit(uid, group_id).await?;
        let duplicate_key_package = cgka_add_proposal(uid, group_id, &key_package).await;
        assert!(duplicate_key_package.is_err());
        let key_package_2 = cgka_generate_key_package(third_uid).await?;
        cgka_add_proposal(uid, group_id, &key_package_2).await?;
        let mut group = cgka_load_group(uid, group_id).await?;
        assert!(
            group.has_pending_commit(),
            "group was expected to have some pending commits."
        );
        cgka_delete_pending_commit(uid, group_id).await?;
        group = cgka_load_group(uid, group_id).await?;
        assert!(!group.has_pending_commit());
        cgka_add_proposal(uid, group_id, &key_package_2).await?;
        cgka_apply_pending_commit(uid, group_id).await?;
        Ok(())
    }

    /* This fails!
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_kem() {
        let cipher_suite = cipher_suite();
        let (hpke_secret, hpke_public) = cipher_suite.kem_generate().await.unwrap();
    }
    */

    /*
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_update_keys() {
        set_panic_hook();
        let uid = b"1";
        let group_id = b"updateKeyGroup";
        let admin_group_id = b"adminupdateKeyGroup";
        cgka_init(uid, group_id).await.unwrap();
        cgka_init(uid, admin_group_id).await.unwrap();
        let other = b"2";
        let other_key_package = cgka_generate_key_package(other).await.unwrap();
        let other_key_package_2 = cgka_generate_key_package(other).await.unwrap();
        cgka_add_proposal(uid, group_id, &other_key_package)
            .await
            .unwrap();
        cgka_add_proposal(uid, admin_group_id, &other_key_package_2)
            .await
            .unwrap();
        cgka_apply_pending_commit(uid, group_id).await.unwrap();
        cgka_apply_pending_commit(uid, admin_group_id)
            .await
            .unwrap();
        cgka_update_proposal(uid, group_id).await.unwrap();
        cgka_update_proposal(uid, admin_group_id).await.unwrap();
        cgka_apply_pending_commit(uid, group_id).await.unwrap();
        cgka_apply_pending_commit(uid, admin_group_id)
            .await
            .unwrap();
    }
    */

    async fn make_identity(name: &str) -> (SignatureSecretKey, SigningIdentity) {
        let cipher_suite = cipher_suite();
        let (secret, public) = cipher_suite.signature_key_generate().await.unwrap();

        // Create a basic credential for the session.
        // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
        // X.509 credentials are recommended.
        let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
        let identity = SigningIdentity::new(basic_identity.into_credential(), public);

        (secret, identity)
    }

    async fn make_client(name: &str) -> Result<Client<impl MlsConfig>, MlsError> {
        let (secret, signing_identity) = make_identity(name).await;

        Ok(Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(webcrypto())
            .signing_identity(signing_identity, secret, CIPHERSUITE)
            .build())
    }

    /*
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn test_update_mls() {
        set_panic_hook();
        let group_id = b"updateKeyGroup";
        let client = make_client("updateKeyClient").await.unwrap();
        let mut group = client
            .create_group_with_id(group_id.to_vec(), ExtensionList::default())
            .await
            .unwrap();
        let client2 = make_client("updateKeyClient2").await.unwrap();
        let key_package = client2.generate_key_package_message().await.unwrap();
        let join = group
            .commit_builder()
            .add_member(key_package)
            .unwrap()
            .build()
            .await
            .unwrap();
        let commit = group.apply_pending_commit().await.unwrap();
        let (mut group2, info) = client2
            .join_group(None, &join.welcome_messages[0])
            .await
            .unwrap();
        group2.commit(Vec::new()).await.unwrap();
        let _ = group.apply_pending_commit();
    }
    */

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn mls_example_test() {
        async fn example() -> Result<Vec<u8>, MlsError> {
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
        example().await;
    }
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
