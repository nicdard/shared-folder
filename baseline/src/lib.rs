use metadata::{deserialize, serialize};
use utils::set_panic_hook;
use wasm_bindgen::prelude::wasm_bindgen;

mod metadata;
mod utils;

#[wasm_bindgen]
/// Share a folder with a user.
/// The metadata is the metadata of the folder to share, as retrieved encrypted from the server.
pub fn share_folder(
    metadata_encoded: &[u8],
    user_identity: &str,
    user_sk: &[u8],
    other_identity: &str,
    ohter_pk: &[u8],
) -> Result<Vec<u8>, String> {
    unimplemented!();
    /*
    set_panic_hook();
    let crypto_provider = mls_rs_crypto_awslc::AwsLcCryptoProvider::new();
    // Deserialize the metadata of the folder.
    let metadata = deserialize(&metadata_encoded)?;
    // Decrypt the folder key with the user's private key.
    let user_encrypted_folder_key = metadata
        .folder_keys_by_user
        .get(user_identity)
        .ok_or("User not found.")?;
    // Obtain the folder symmetric key.
    let folder_key = (&user_encrypted_folder_key, user_sk)?;
    // Encrypt the folder key with the other user's public key.
    let other_encrypted_folder_key = asymmetric_encrypt(&folder_key, ohter_pk)?;
    // Update the metadata with the new encrypted folder key.
    let mut metadata = metadata;
    metadata
        .folder_keys_by_user
        .insert(other_identity.to_string(), other_encrypted_folder_key);
    // Serialize the metadata and return it, see the Display implementation.
    Ok(serialize(metadata)?)
    */
}

//type ignored = String;
