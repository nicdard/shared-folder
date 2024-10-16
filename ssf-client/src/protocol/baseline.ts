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
import {
  base64encode,
  exportPublicCryptoKey,
  importECDHPublicKey,
  importECDHPublicKeyFromCertificate,
  importECDHPublicKeyPEMFromCertificate,
  importECDHSecretKey,
  string2ArrayBuffer,
} from './commonCrypto';
import { decodeObject, encodeObject } from './marshaller';
import { AddFileResult, ProtocolClient } from './protocolCommon';
import { PkeEncryptResult, pkeDec, pkeEnc } from './publicCrypto';
import {
  AesGcmEncryptResult,
  aesGcmDecrypt,
  aesGcmEncrypt,
  exportAesGcmKey,
  generateSymmetricKey,
  importAesGcmKey,
} from './symmetricCrypto';
import { CrateService as dsclient } from '../gen/clients/ds';

/**
 * The metadata of a file.
 * Holds the cryptographic state associated with a file and sensitive metadata information.
 */
export interface FileMetadata {
  // The file symmetric encryption key.
  rawFileKey: ArrayBufferLike;
  // The file name.
  fileName: string;
}

/**
 * The type of an encrypted {@link FileMetadata} object.
 * An opaque object to the server.
 */
type EncryptedFileMetadata = AesGcmEncryptResult;

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
 * The result of the encryption of a file and its metadata.
 * Contains a file ciphertext where we need the file id as additional authenticated data (to bind it to the file content so that the server cannot swap files).
 */
type FileEncryptionResult = {
  fileCtxt: AesGcmEncryptResult;
  fileMetadataCtxt: EncryptedFileMetadata;
};

export class BaselineProtocolClient implements ProtocolClient {
  addAdmin(
    identity: string,
    folderId: string,
    adminIdentity: string
  ): Promise<void> {
    throw new Error('Operation not supported.');
  }
  removeAdmin(
    identity: string,
    folderId: string,
    adminIdentity: string
  ): Promise<void> {
    throw new Error('Operation not supported.');
  }
  removeMember(
    identity: string,
    folderId: string,
    memberIdentity: string
  ): Promise<void> {
    throw new Error('Operation not supported.');
  }
  rotateKeys(identity: string, folderId: string): Promise<void> {
    throw new Error('Operation not supported.');
  }
  syncFolder(identity: string, folderId: string): Promise<string> {
    console.log('Synced.');
    return Promise.resolve('member');
  }
  getFoldersToSync() {
    return { folders: [] as number[], keyPackages: 0 };
  }
  listFiles({
    folderId,
    identity,
    skPEM,
    certPEM,
    metadataContent,
  }: {
    folderId: number;
    identity: string;
    skPEM: string;
    certPEM: string;
    metadataContent: Uint8Array;
  }): Promise<Record<string, string>> {
    return listFiles(
      folderId,
      encodeIdentityAsMetadataMapKey(identity),
      skPEM,
      certPEM,
      metadataContent
    );
  }
  readFile({
    identity,
    certPEM,
    metadataContent,
    skPEM,
    fileId,
    encryptedFileContent,
  }: {
    identity: string;
    certPEM: string;
    skPEM: string;
    fileId: string;
    encryptedFileContent: Uint8Array;
    metadataContent: Uint8Array;
  }): Promise<ArrayBuffer> {
    return readFile({
      identity: encodeIdentityAsMetadataMapKey(identity),
      certPEM,
      skPEM,
      fileId,
      encryptedFileContent,
      metadataContent,
    });
  }
  async addFile({
    senderCertPEM,
    senderIdentity,
    senderSkPEM,
    fileId,
    fileName,
    file,
    metadataContent,
  }: {
    senderIdentity: string;
    senderCertPEM: string;
    senderSkPEM: string;
    fileName: string;
    file: Buffer;
    fileId: string;
    metadataContent: Uint8Array;
  }) {
    return await addFile({
      senderIdentity: encodeIdentityAsMetadataMapKey(senderIdentity),
      senderCertPEM,
      senderSkPEM,
      fileName,
      file,
      fileId,
      metadataContent,
    });
  }
  async shareFolder({
    folderId,
    receiverCert,
    receiverIdentity,
    senderCert,
    senderIdentity,
    senderSkPEM,
    metadata_content,
    etag,
    version,
  }: {
    folderId: number;
    receiverIdentity: string;
    receiverCert: string;
    senderIdentity: string;
    senderCert: string;
    senderSkPEM: string;
    metadata_content: ArrayBuffer;
    etag?: string;
    version?: string;
  }): Promise<void> {
    await dsclient.shareFolder({
      folderId,
      requestBody: {
        emails: [receiverIdentity],
      },
    });
    const receiverPkPEM = await importECDHPublicKeyPEMFromCertificate(
      receiverCert
    );
    const senderPkPEM = await importECDHPublicKeyPEMFromCertificate(senderCert);
    // Also advanced the cryptographic state.
    const metadataContent = new Uint8Array(
      metadata_content as unknown as ArrayBuffer
    );
    const updatedMetadata = await shareFolder({
      senderIdentity: encodeIdentityAsMetadataMapKey(senderIdentity),
      senderPkPEM,
      senderSkPEM,
      receiverIdentity: encodeIdentityAsMetadataMapKey(receiverIdentity),
      receiverPkPEM,
      metadataContent,
    });
    await dsclient.postMetadata({
      folderId,
      formData: {
        metadata: new Blob([updatedMetadata]),
        parent_etag: etag,
        parent_version: version,
      },
    });
  }
  createFolder(senderIdentity: string, folderId: number): Promise<number> {
    // Not used in the Baseline protocol.
    throw new Error('Operation not supported.');
  }
  async createNewFolderMetadata(
    senderIdentity: string,
    senderPkPEM: string
  ): Promise<Buffer> {
    const encodedMetadata = await createEncodedInitialMetadataFile({
      senderIdentity: encodeIdentityAsMetadataMapKey(senderIdentity),
      senderPkPEM,
    });
    return encodedMetadata;
  }
  register(email: string): Promise<void> {
    return Promise.resolve();
  }
  load(email: string): Promise<void> {
    return Promise.resolve();
  }
}

/**
 * @returns the metadata updated with the new file metadata object and the file content encrypted as a {@link AddFileResult}.
 */
export async function addFile({
  senderIdentity,
  senderCertPEM,
  senderSkPEM,
  fileName,
  fileId,
  file,
  metadataContent,
}: {
  senderIdentity: string;
  senderCertPEM: string;
  senderSkPEM: string;
  fileName: string;
  file: Buffer;
  fileId: string;
  metadataContent: Uint8Array;
}): Promise<AddFileResult> {
  checkIdentityAsMapKey(senderIdentity);
  // Decrypt the folder key for the current user.
  const metadata = await decodeObject<Metadata>(metadataContent);
  const folderKey = await decryptFolderKeyFromMetadata(
    metadata,
    senderIdentity,
    senderSkPEM,
    senderCertPEM
  );
  // Encrypt the file and modify the metadata.
  const fileEncryptionResult = await encryptFileAndFileMetadata(
    folderKey,
    file,
    fileName,
    fileId
  );
  metadata.fileMetadatas[fileId] = fileEncryptionResult.fileMetadataCtxt;
  return {
    metadataContent: await encodeObject(metadata),
    fileCtxt: await encodeObject(fileEncryptionResult.fileCtxt),
  };
}

/**
 * @returns the content of the file decrypted.
 */
export async function readFile({
  identity,
  certPEM,
  skPEM,
  fileId,
  encryptedFileContent,
  metadataContent,
}: {
  identity: string;
  certPEM: string;
  skPEM: string;
  fileId: string;
  encryptedFileContent: Uint8Array;
  metadataContent: Uint8Array;
}): Promise<ArrayBuffer> {
  checkIdentityAsMapKey(identity);
  // Decrypt the folder key for the current user.
  const metadata = await decodeObject<Metadata>(metadataContent);
  const folderKey = await decryptFolderKeyFromMetadata(
    metadata,
    identity,
    skPEM,
    certPEM
  );
  // Get the file metadata
  const fileMetadata = await decryptFileMetadata(
    folderKey,
    metadata.fileMetadatas[fileId],
    fileId
  );
  const fileCtxt = await decodeObject<FileEncryptionResult['fileCtxt']>(
    encryptedFileContent
  );
  return decryptFile(fileMetadata, fileCtxt);
}

async function decryptFolderKeyFromMetadata(
  metadata: Metadata,
  senderIdentity: string,
  senderSkPEM: string,
  senderCertPEM: string
) {
  const encryptedFolderKey = metadata.folderKeysByUser[senderIdentity];
  const senderSk = await importECDHSecretKey(senderSkPEM);
  const senderPk = await importECDHPublicKeyFromCertificate(senderCertPEM);
  const exportedFolderKey = await decryptFolderKey(
    { privateKey: senderSk, publicKey: senderPk },
    encryptedFolderKey
  );
  const folderKey = await importAesGcmKey(exportedFolderKey);
  return folderKey;
}

/**
 * Encrypt the file under an ephemeral key and the file metadata under the folder key.
 * @param folderKey the folder key used to encrypt the file metadata.
 * @param file the file content.
 * @param fileName the file name.
 */
export async function encryptFileAndFileMetadata(
  folderKey: CryptoKey,
  file: Buffer,
  fileName: string,
  fileId: string
): Promise<FileEncryptionResult> {
  if (folderKey.type != 'secret') {
    throw new Error('Invalid key!');
  }
  // f_k <- $ AES-GCM.KG()
  const fileKey = await generateSymmetricKey();
  // c_file <- SE.Enc(f_k, file)
  const fileCtxt = await aesGcmEncrypt(fileKey, file);
  const rawFileKey = await exportAesGcmKey(fileKey);
  const encodedFileMetadata = await encodeObject({ fileName, rawFileKey });
  // c_filekey = <- AES_GCM.Enc(Fk, fk, filename = AD)
  const fileMetadataCtxt = await aesGcmEncrypt(
    folderKey,
    encodedFileMetadata,
    string2ArrayBuffer(fileId)
  );
  return { fileCtxt, fileMetadataCtxt };
}

/**
 * @param folderKey the {@link CryptoKey} of the folder.
 * @param fileMetadataCtxt the {@link EncryptedFileMetadata} to decrypt.
 * @returns the {@link FileMetadata} containing info such as the name of the file and the encryption key.
 */
export async function decryptFileMetadata(
  folderKey: CryptoKey,
  fileMetadataCtxt: FileEncryptionResult['fileMetadataCtxt'],
  fileId: string
): Promise<FileMetadata> {
  if (folderKey.type != 'secret') {
    throw new Error('Invalid key!');
  }
  const fileMetadata = await aesGcmDecrypt(
    folderKey,
    fileMetadataCtxt,
    string2ArrayBuffer(fileId)
  );
  return decodeObject(new Uint8Array(fileMetadata));
}

/**
 *
 * @param fileMetadata the {@link FileMetadata}
 * @param fileCtxt the result of the file encryption {@link AesGcmEncryptResult}
 * @returns the decrypted content of the file.
 * @see decryptFileMetadata
 */
export async function decryptFile(
  fileMetadata: FileMetadata,
  fileCtxt: FileEncryptionResult['fileCtxt']
): Promise<ArrayBuffer> {
  const { rawFileKey } = fileMetadata;
  const fileKey = await importAesGcmKey(rawFileKey);
  const file = await aesGcmDecrypt(fileKey, fileCtxt);
  return file;
}

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
  const exportedFolderKey = new Uint8Array(await exportAesGcmKey(folderKey));
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
  return encodeObject(
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
  const metadata = await decodeObject<Metadata>(metadataContent);
  const encryptedFolderKey = metadata.folderKeysByUser[senderIdentity];
  const senderSk = await importECDHSecretKey(senderSkPEM);
  const senderPk = await importECDHPublicKey(senderPkPEM);
  const folderKey = await decryptFolderKey(
    { privateKey: senderSk, publicKey: senderPk },
    encryptedFolderKey
  );
  // Encrypt the folder key for the other user.
  const receiverPk = await importECDHPublicKey(receiverPkPEM);
  const encryptedFolderKeyForOther = await encryptFolderKeyForUser(
    receiverPk,
    folderKey
  );
  metadata.folderKeysByUser[receiverIdentity] = encryptedFolderKeyForOther;
  return encodeObject(metadata);
}

/**
 * @param folderId the folder id for which we want to list the files.
 * @param identity the identity requesting the operation
 * @param skPEM the sk associated with the identity
 * @param certPEM the certificate associated with the identity
 * @param metadataContent the metadata file content
 * @returns the mappings from fileNames to fileIds.
 */
export async function listFiles(
  folderId: number,
  identity: string,
  skPEM: string,
  certPEM: string,
  metadataContent: Uint8Array
): Promise<Record<string, string>> {
  checkIdentityAsMapKey(identity);
  const metadata = await decodeObject<Metadata>(metadataContent);
  const folderKey = await decryptFolderKeyFromMetadata(
    metadata,
    identity,
    skPEM,
    certPEM
  );
  const mappings = await Promise.all(
    Object.keys(metadata.fileMetadatas).map(async (fileId) => {
      const fileMetadata = await decryptFileMetadata(
        folderKey,
        metadata.fileMetadatas[fileId],
        fileId
      );
      return [fileId, fileMetadata.fileName];
    })
  );
  return mappings.reduce((acc, [fileId, fileName]) => {
    acc[fileName] = fileId;
    return acc;
  }, {} as Record<string, string>);
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
