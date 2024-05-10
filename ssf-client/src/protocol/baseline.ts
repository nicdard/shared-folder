import { FolderResponse } from "../gen/clients/ds";

/**
 * The metadata of a file.
 * Holds the cryptographic state associated with a file and sensitive metadata information.
 */
interface FileMetadata {
    // The file symmetric encryption key.
    fileKey: CryptoKey,
    // The file name.
    fileName: string,
}

/**
 * The type of an encrypted {@link FileMetadata} object.
 */
type EncryptedFileMetadata = Uint8Array;

/**
 * The type of an asymmetric encrypted folder key.
 */
type EncryptedFolderKey = Uint8Array;

/**
 * The Metadata file is associated with a sharable folder and stored at the root of the folder.
 * This contains the cryptographic state:
 * - a folder key encrypted for each user
 * - a map from each file id (known to the DS server) to the corresponding encrypted {@link FileMetadata} object. Those are represented using {@link EncryptedFileMetadata}.
 */
interface Metadata {
    /**
     * All the folder keys that are encrypted for the user.
     * The map is indexed by the user's identity.
     * The value is the asymmetrically encrypted key of the folder that can be decrypted by the user's private key.
     */
    folderKeysByUser: { [key: string]: EncryptedFolderKey },
    /**
     * For each file id, maps to the metadata of the file.
     * The index is the id of the file (a GUID).
     */
    fileMetadatas: { [key: string]: EncryptedFileMetadata },
}
/** 
function serializeMetadata(metadata: Metadata) {
   const ser = createSer();
   const folderKeysByUserEntries = Object.entries(metadata.folderKeysByUser);
   ser.serializeNumber(folderKeysByUserEntries.length);
   folderKeysByUserEntries.forEach(([userIdetity, encryptedFolderKey]) => {
     ser.serializeString(userIdetity);
    
   })
}
*/

async function shareFolder(folder: FolderResponse, ...otherEmails: string[]) {
    const { metadata_content, etag, version, id } = folder;
    const metadata = new Uint8Array(await metadata_content.arrayBuffer());
    
}
 
async function encryptFileKey(fileKey: CryptoKey, ...otherEmails: string[]) {
    if (otherEmails.length == 0) {
        throw new Error("There should be at least one email to share the key with.");
    }
    //const 
    const {window} = globalThis;

    const { subtle } = globalThis.crypto;
    // Retrieve public key
    // subtle.decrypt();

    const key = await subtle.generateKey({
        name: 'AES-CBC',
        length,
    }, true, ['encrypt', 'decrypt']);
}
