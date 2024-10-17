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
use std::collections::HashMap;

#[derive(Debug)]
pub struct FileMetadata {
    /// The key of the file that is encrypted for the user.
    /// The value is the asymmetrically encrypted key of the file that can be decrypted by the user's private key.
    pub file_key: String,
    /// The name of the file to be displayed to the end user.
    pub file_name: String,
}

/// The type of the encrtypted [`FileMetadata`] object.
type EncryptedFileMetadata = Vec<u8>;

#[derive(Debug)]
pub struct Metadata {
    /// All the folder keys that are encrypted for the user.
    /// The map is indexed by the user's identity.
    /// The value is the asymmetrically encrypted key of the folder that can be decrypted by the user's private key.
    pub folder_keys_by_user: HashMap<String, Vec<u8>>,
    /// For each file id, maps to the metadata of the file.
    /// The index is the id of the file (a GUID).
    pub file_metadatas: HashMap<String, EncryptedFileMetadata>,
}

/// Serialize the [`Metadata`] object to byte array.
pub fn serialize(metadata: Metadata) -> Result<Vec<u8>, String> {
    unimplemented!();
}

/// Deserialize the [`Metadata`] object from byte array.
pub fn deserialize(metadata: &[u8]) -> Result<Metadata, String> {
    unimplemented!();
}
