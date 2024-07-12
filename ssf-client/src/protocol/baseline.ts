import { Decoder, Encoder } from 'cbor';
import {
  base64encode,
  exportPublicCryptoKey,
  importECDHPublicKey,
  importECDHSecretKey,
  subtle,
} from './commonCrypto';
import { PkeEncryptResult, pkeDec, pkeEnc } from './publicCrypto';
import { aesGcmEncrypt, generateSymmetricKey } from './symmetricCrypto';

// https://davidmyers.dev/blog/a-practical-guide-to-the-web-cryptography-api

/**
 * The metadata of a file.
 * Holds the cryptographic state associated with a file and sensitive metadata information.
 */
export interface FileMetadata {
  // The file symmetric encryption key.
  fileKey: CryptoKey;
  // The file name.
  fileName: string;
}

/**
 * The type of an encrypted {@link FileMetadata} object.
 */
type EncryptedFileMetadata = Uint8Array;

/**
 * The type of an asymmetric encrypted folder key.
 */
type EncryptedFolderKey = {
  ctxt: ArrayBuffer;
  pe: string;
  iv: Uint8Array;
  salt: Uint8Array;
};

/**
 * The Metadata file is associated with a sharable folder and stored at the root of the folder.
 * This contains the cryptographic state:
 * - a folder key encrypted for each user
 * - a map from each file id (known to the DS server) to the corresponding encrypted {@link FileMetadata} object. Those are represented using {@link EncryptedFileMetadata}.
 */
export interface Metadata {
  /**
   * All the folder keys that are encrypted for the user.
   * The map is indexed by the user's identity.
   * The value is the asymmetrically encrypted key of the folder that can be decrypted by the user's private key.
   */
  folderKeysByUser: Record<string, EncryptedFolderKey>;
  /**
   * For each file id, maps to the metadata of the file.
   * The index is the id of the file (a GUID).
   */
  fileMetadatas: Record<string, EncryptedFileMetadata>;
}

/**
 * Encrypt the file under an ephemeral key and the file metadata under the folder key.
 * @param folderKey the folder key used to encrypt the file metadata.
 * @param file the file content.
 * @param filename the file name.
 */
/** 
export async function encryptFile(folderKey: CryptoKey, file: Buffer, filename: string) {
  if (folderKey.type != 'secret') {
    throw new Error("Invalid key!");
  }
  // f_k <- $ AES-GCM.KG()
  const fileKey = await generateSymmetricKey();
  // c_file <- SE.Enc(f_k, file)
  const fileCtxt = await aesGcmEncrypt(fileKey, file);
  // c_filekey = <- AES_GCM.Enc(Fk, fk, filename = AD)
  const filekeyCtxt = await aesGcmEncrypt(folderKey, fileKey, filename);
  return {

  }

}

export async function decryptFile() {

}
*/

/**
 * Create the initial metadata file for an empty folder.
 * The initial file contains only the AES-GCM key encrypted under the public key of the creator of the folder.
 * @see EncryptedFolderKey
 */
export async function createInitialMetadataFile({
  senderIdentity,
  senderPkPEM,
}: {
  senderIdentity: string;
  senderPkPEM: string;
}): Promise<Metadata> {
  checkIdentityAsMapKey(senderIdentity);
  const senderPk = await importECDHPublicKey(senderPkPEM);
  const folderKey = await generateSymmetricKey();
  const exportedFolderKey = new Uint8Array(
    await subtle.exportKey('raw', folderKey)
  );
  return {
    folderKeysByUser: {
      [senderIdentity]: await encryptFolderKeyForUser(
        senderPk,
        exportedFolderKey
      ),
    },
    fileMetadatas: {},
  };
}

/**
 * Create the initial metadata file for an empty folder.
 * The initial file contains only the AES-GCM key encrypted under the public key of the creator of the folder.
 * The metadata file is encoded to be sent over the wire to the server using CBOR.
 * @see EncryptedFolderKey
 */
export async function createEncodedInitialMetadataFile({
  senderIdentity,
  senderPkPEM,
}: {
  senderIdentity: string;
  senderPkPEM: string;
}): Promise<Buffer> {
  return encodeMetadata(
    await createInitialMetadataFile({ senderIdentity, senderPkPEM })
  );
}

/**
 * @param encryptedFolderKey the {@link EncryptedFolderKey} to be represented as the {@link PkeEncryptResult} of a Public Key Encryption operation.
 * @returns the encrypted folder key in the format {@link PkeEncryptResult}, where the ephemeral public key is represented as a {@link CryptoKey}.
 */
export async function encryptedFolderKeyToPkeEncryptResult(
  encryptedFolderKey: EncryptedFolderKey
): Promise<PkeEncryptResult> {
  return {
    ctxt: encryptedFolderKey.ctxt,
    iv: encryptedFolderKey.iv,
    cKem: {
      salt: encryptedFolderKey.salt,
      pe: await importECDHPublicKey(encryptedFolderKey.pe),
    },
  };
}

/**
 * @param identity the current user identity (a string not containing dots)
 * @param senderSkPEM the current user secret key in PEM format
 * @param senderPkPEM the current user public key in PEM format
 * @param receiverIdentity the user with whom to share the folder (key) (a string without dots)
 * @param receiverPkPEM the user with whom to share the folder key Public Key in PEM format
 * @param metadata_content the metadata file content as a {@link Uint8Array}
 */
export async function shareFolder({
  senderIdentity,
  senderPkPEM,
  senderSkPEM,
  receiverIdentity,
  receiverPkPEM,
  metadataContent,
}: {
  senderIdentity: string;
  senderSkPEM: string;
  senderPkPEM: string;
  receiverIdentity: string;
  receiverPkPEM: string;
  metadataContent: Uint8Array;
}): Promise<Buffer> {
  // TODO optimise: use certificates as parameters and reduce import export
  checkIdentityAsMapKey(senderIdentity);
  checkIdentityAsMapKey(receiverIdentity);
  // Decrypt the folder key for the current user.
  const metadata = await decodeMetadata(metadataContent);
  const encryptedFolderKey = metadata.folderKeysByUser[senderIdentity];
  const senderSk = await importECDHSecretKey(senderSkPEM);
  const senderPk = await importECDHPublicKey(senderPkPEM);
  const pkeEncResult = await encryptedFolderKeyToPkeEncryptResult(
    encryptedFolderKey
  );
  const folderKey = await pkeDec(
    { privateKey: senderSk, publicKey: senderPk },
    pkeEncResult
  );
  // Encrypt the folder key for the other user.
  const receiverPk = await importECDHPublicKey(receiverPkPEM);
  const encryptedFolderKeyForOther = await encryptFolderKeyForUser(
    receiverPk,
    folderKey
  );
  metadata.folderKeysByUser[receiverIdentity] = encryptedFolderKeyForOther;
  return encodeMetadata(metadata);
}

/**
 *
 * @param receiverPk {@link CryptoKey} the public key of the user with whon to share the Folder Key
 * @param folderKeyBytes the folder key bytes
 * @returns the {@link EncryptedFolderKey} for the user corresponding to otherPk identity.
 */
export async function encryptFolderKeyForUser(
  receiverPk: CryptoKey,
  folderKeyBytes: ArrayBufferLike
): Promise<EncryptedFolderKey> {
  if (receiverPk.algorithm.name != 'ECDH') {
    throw new Error(`Unsupported algorithm ${receiverPk.algorithm.name}`);
  }
  const {
    ctxt,
    cKem: { pe, salt },
    iv,
  } = await pkeEnc(receiverPk, folderKeyBytes);
  const exportedPe = await exportPublicCryptoKey(pe);
  return {
    iv,
    ctxt,
    pe: exportedPe,
    salt: new Uint8Array(salt),
  };
}

/**
 *
 * @param receiverKeyPair the key pair for the current user that wants to decrypt the folder key.
 * @param encryptedFolderKey the encrypted folder key as saved in the metadata file.
 * @returns the Folder key bytes
 */
export async function decryptFolderKey(
  receiverKeyPair: CryptoKeyPair,
  encryptedFolderKey: EncryptedFolderKey
): Promise<ArrayBufferLike> {
  const pkeEncResult = await encryptedFolderKeyToPkeEncryptResult(
    encryptedFolderKey
  );
  return await pkeDec(receiverKeyPair, pkeEncResult);
}

/**
 * @param metadata the {@link Metadata} object to encode
 * @returns CBOR encoding of the metadata object
 */
export async function encodeMetadata(metadata: Metadata): Promise<Buffer> {
  /* TODO: when server supports stream api, use stream: https://nodejs.org/api/stream.html
    const encoder = new Encoder({ canonical: true, detectLoops: false });
    encoder.pushAny(metadata);
    */
  const encoded = await Encoder.encodeAsync(metadata, {
    canonical: true,
    detectLoops: false,
  });
  return encoded;
}

/**
 * @param metadata the {@link Metadata} object searialized by {@link encodeMetadata}
 * @returns the {@link Metadata} object
 */
export async function decodeMetadata(metadata: Uint8Array): Promise<Metadata> {
  const decoded: Metadata = (await Decoder.decodeFirst(metadata, {
    preventDuplicateKeys: false,
    extendedResults: false,
  })) as Metadata;
  return decoded;
}

/**
 *
 * @param identity the identity to represent in the Metadata
 * @returns the base64 encoding of the identity
 */
export function encodeIdentityAsMetadataMapKey(identity: string) {
  return base64encode(identity);
}

function checkIdentityAsMapKey(identity: string) {
  if (identity.includes('.')) {
    throw new Error('Invalid user identity, should not contain `.`');
  }
}
