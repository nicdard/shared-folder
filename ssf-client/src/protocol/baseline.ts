import { Decoder, Encoder } from 'cbor';
import { FolderResponse } from '../gen/clients/ds';
import {
  deriveAesGcmKeyFromEphemeralAndPublicKey,
  deriveHKDFKeyWithDH,
  exportPublicCryptoKey,
  generateEphemeralKeyPair,
  generateIV,
  generateSalt,
  importECDHPublicKey,
  importECDHSecretKey,
  subtle,
} from './crypto';

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
  cipher: ArrayBuffer;
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
  folderKeysByUser: { [userIdentity: string]: EncryptedFolderKey };
  /**
   * For each file id, maps to the metadata of the file.
   * The index is the id of the file (a GUID).
   */
  fileMetadatas: { [fileId: string]: EncryptedFileMetadata };
}


/**
 * @param identity the current user identity
 * @param userSkPem the current user secret key in PEM format
 * @param userPkPem the current user public key in PEM format
 * @param otherIdentity the user with whom to share the folder (key)
 * @param otherPkPem the user with whom to share the folder key Public Key in PEM format
 * @param metadata_content the metadata file content as a {@link Uint8Array}
 */
export async function shareFolder(identity: string, userSkPem: string, userPkPem: string, otherIdentity: string, otherPkPem: string, metadata_content: Uint8Array): Promise<Buffer> {
  // Decrypt the folder key for the current user.
  const metadata = await decodeMetadata(metadata_content);
  const encryptedFolderKey = metadata.folderKeysByUser[identity];
  console.log(encryptedFolderKey);
  const userSk = await importECDHSecretKey(userSkPem);
  const userPk = await importECDHPublicKey(userPkPem);
  const folderKey = await decryptFolderKey(userSk, userPk, encryptedFolderKey);
  console.log("folder key", folderKey);
  // Encrypt the folder key for the other user.
  console.log(otherPkPem);
  const otherPk = await importECDHPublicKey(otherPkPem);
  const encryptedFolderKeyForOther = await agreeAndEncryptFolderKey(otherPk, folderKey);
  metadata.folderKeysByUser[otherIdentity] = encryptedFolderKeyForOther;
  return encodeMetadata(metadata);
}

export async function agreeAndEncryptFolderKey(
  otherPk: CryptoKey,
  encoded: Buffer | ArrayBuffer
): Promise<EncryptedFolderKey> {
  if (otherPk.algorithm.name != 'ECDH') {
    throw new Error(`Unsupported algorithm ${otherPk.algorithm.name}`);
  }
  const { privateKey: se, publicKey: pe } = await generateEphemeralKeyPair();
  const _k = await deriveHKDFKeyWithDH(otherPk, se);

  /*const rawPk = await subtle.exportKey('raw', otherPk);
  const rawPe = await subtle.exportKey('raw', pe);
  const label = appendBuffers(rawPe, rawPk);
  console.log(label);
  const k = await deriveHKDFKeyWithHKDF(_k, label)
  */
  const salt = generateSalt(256);
  const aesK = await deriveAesGcmKeyFromEphemeralAndPublicKey(
    _k,
    otherPk,
    pe,
    salt
  );
  console.log('AES KEY:', await subtle.exportKey('raw', aesK));
  const iv = generateIV();
  const encryptedEncoded = await subtle.encrypt(
    { name: aesK.algorithm.name, iv },
    aesK,
    encoded
  );
  const exportedPe = await exportPublicCryptoKey(pe);
  return {
    iv,
    cipher: encryptedEncoded,
    pe: exportedPe,
    salt,
  };
}

// eslint-disable-next-line @typescript-eslint/require-await
export async function decryptFolderKey(
  sk: CryptoKey,
  pk: CryptoKey,
  encryptedFolderKey: EncryptedFolderKey
) {
  if (sk.algorithm.name != 'ECDH') {
    throw new Error(`Unsupported algorithm ${sk.algorithm.name}`);
  }
  const { pe, iv, cipher, salt } = encryptedFolderKey;
  const importedPe = await importECDHPublicKey(pe);
  console.log(importedPe);
  const _k = await deriveHKDFKeyWithDH(importedPe, sk);
  const aesK = await deriveAesGcmKeyFromEphemeralAndPublicKey(
    _k,
    pk,
    importedPe,
    salt
  );
  console.log('AES KEY:', await subtle.exportKey('raw', aesK));
  const decryptedFolderKey = await subtle.decrypt(
    { name: aesK.algorithm.name, iv },
    aesK,
    cipher
  );
  return decryptedFolderKey;
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
