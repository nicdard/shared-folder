import { string2ArrayBuffer, string2Uint8Array } from './commonCrypto';
import { DsMiddleware } from './group-key-progression/dsMiddleware';
import {
  GKP,
  GKPMiddleware,
} from './group-key-progression/gkp';
import { GRaPPA } from './group-key-progression/grappa';
import { Epoch } from './key-progression/kp';
import { decodeObject, encodeObject } from './marshaller';
import { AddFileResult, ProtocolClient } from './protocolCommon';
import {
  AesGcmEncryptResult,
  aesGcmDecrypt,
  aesGcmEncrypt,
  exportAesGcmKey,
  generateSymmetricKey,
  importAesGcmKey,
} from './symmetricCrypto';
import { loadCaTLSCredentials, loadTLSCredentials } from './authentication';
import { createSSENotificationReceiver } from './notifications';
import EventSource = require('eventsource');

/**
 * The metadata of a file.
 * Holds the cryptographic state associated with a file and sensitive metadata information.
 */
export interface FileMetadata {
  // The file symmetric encryption key.
  rawFileKey: ArrayBufferLike;
  // The file name.
  fileName: string;
  // The file id in the cloud storage.
  fileId: string;
}

/**
 * The type of an encrypted {@link FileMetadata} object.
 * An opaque object to the server.
 */
type EncryptedFileMetadata = AesGcmEncryptResult;

/**
 * The Metadata file is associated with a sharable folder and stored at the root of the folder.
 * This contains the cryptographic state:
 * - a map from each epoch {@link Epoch} (known to the DS server) to the corresponding encrypted {@link FileMetadata} object. Those are represented using {@link EncryptedFileMetadata}.
 */
export interface Metadata {
  /**
   * For each file find the epoch.
   */
  epochByFileId: Record<string, Epoch>;
  /**
   * For each epoch, maps the file id to the metadata of the file.
   */
  fileMetadatasByEpoch: Record<Epoch, Record<string, EncryptedFileMetadata>>;
}

/**
 * The result of the encryption of a file and its metadata.
 * Contains a file ciphertext where we need the file id as additional authenticated data (to bind it to the file content so that the server cannot swap files).
 */
type FileEncryptionResult = {
  fileCtxt: AesGcmEncryptResult;
  fileMetadataCtxt: EncryptedFileMetadata;
};

export class GKPProtocolClient implements ProtocolClient {
  private middleware: GKPMiddleware = new DsMiddleware();
  private receiver: EventSource;
  private currentEmail: string | undefined;
  /**
   * Keep track of which folder ids have pending messages,
   * so we can execute the state update before apply the commands.
   * We need however to tell the user that there are state updates before applying a command.
   * Otherwise we can use it to process all the state updates in between the user commands are applied.
   */
  private inbox: Map<bigint, boolean>;

  public getFoldersToSync() {
    const folders: number[] = [];
    let keyPackages = 0;
    this.inbox.forEach((value, folderId) => { 
      if (value) {
        const f = Number(folderId);
        if (f != -1) {
          folders.push(f);
        } else {
          keyPackages++;
        }
      }
    });
    return { folders, keyPackages };
  }

  async register(email: string): Promise<void> {
    for (let i = 0; i < 200; ++i) {
      await GRaPPA.publishKeyPackage(email, this.middleware);
    }
    await this.load(email);
  }

  async load(email: string): Promise<void> {
    // Cleanup previous state.
    if (this.receiver != null) {
      this.receiver.close();
    }
    this.inbox = new Map();
    // Create state for current client.
    console.log(`Creating the SSE receiver for ${email}`);
    const ca = loadCaTLSCredentials();
    const [key, cert] = loadTLSCredentials();
    // Create the new receiver for the loaded client.
    this.receiver = await createSSENotificationReceiver(
      (folderId) => {
        console.log(folderId);
        this.inbox.set(folderId, true);
      },
      {
        ca,
        cert,
        key,
      }
    );
    this.currentEmail = email;
  }
  async createNewFolderMetadata(
    senderIdentity: string,
    _senderPkPEM: string
  ): Promise<Buffer> {
    if (senderIdentity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const encodedMetadata = await createEncodedInitialMetadataFile();
    return encodedMetadata;
  }
  async createFolder(senderIdentity: string, folderId: number): Promise<void> {
    if (senderIdentity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    // Create a GKP.
    const grappa = await GRaPPA.initUser(senderIdentity, this.middleware);
    await grappa.createGroup(folderId.toString());
  }

  async shareFolder({
    senderIdentity,
    receiverIdentity,
    folderId,
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
    if (senderIdentity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(
            senderIdentity,
            folderId.toString(),
            this.middleware
          );
    await grappa.execCtrl({
      type: 'ADD',
      uid: GRaPPA.getUidFromUserId(receiverIdentity),
    });
  }

  async addFile({
    senderIdentity,
    folderId,
    metadataContent,
    file,
    fileId,
    fileName,
  }: {
    senderIdentity: string;
    senderCertPEM: string;
    senderSkPEM: string;
    fileName: string;
    file: Buffer;
    fileId: string;
    metadataContent: Uint8Array;
    folderId: number;
  }): Promise<AddFileResult> {
    if (senderIdentity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(
            senderIdentity,
            folderId.toString(),
            this.middleware
          );
    const epoch = grappa.getCurrentEpoch();
    const epochKey = await grappa.getEpochKey(epoch);
    return addFile({
      epoch,
      epochKey,
      metadataContent,
      file,
      fileId,
      fileName,
    });
  }

  async readFile({
    identity,
    folderId,
    metadataContent,
    fileId,
    encryptedFileContent,
  }: {
    identity: string;
    certPEM: string;
    skPEM: string;
    fileId: string;
    encryptedFileContent: Uint8Array;
    metadataContent: Uint8Array;
    folderId: number;
  }): Promise<ArrayBuffer> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
    // Decrypt the folder key for the current user.
    const metadata = await decodeObject<Metadata>(metadataContent);
    const epoch = metadata.epochByFileId[fileId];
    const epochKey = await grappa.getEpochKey(epoch);
    return await readFile({
      epoch,
      epochKey,
      fileId,
      encryptedFileContent,
      metadata,
    });
  }

  async listFiles({
    folderId,
    identity,
    metadataContent,
  }: {
    folderId: number;
    identity: string;
    metadataContent: Uint8Array;
  }): Promise<Record<string, string>> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
    // Decrypt the folder key for the current user.
    const metadata = await decodeObject<Metadata>(metadataContent);
    const mappings = await Promise.all(
      Object.entries(metadata.epochByFileId).map(async ([fileId, epoch]) => {
        const fileMetadata = await decryptFileMetadata(
          await grappa.getEpochKey(epoch),
          metadata.fileMetadatasByEpoch[epoch][fileId],
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

  async syncFolder(identity: string, folderId: string): Promise<void> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const groupId = string2Uint8Array(folderId);
    // Try to see if we need to join the group.
    let grappa;
    try {
      console.log("Loading the group's state...");
      grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
      console.log(`Client loaded the group attached to folder ${folderId}, role: ${grappa.getRole()}`);
    } catch (error) {
      console.log('Couldn\'t load the group, trying to join it...');
      const proposal = await this.middleware.fetchPendingProposal(groupId);
      // If we cannot load a group for a folder, we need to join it.
      grappa = await GRaPPA.joinCtrl(identity, this.middleware, proposal);
      console.log(`Client joined the group attached to folder ${folderId}`);
    }
    // Then try to sync all the pending remaning proposals if any.
    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const pending = await this.middleware.fetchPendingProposal(groupId);
        await grappa.procCtrl(pending);
      }
    } catch (error) {
      console.error(error);
      console.log('Synced.');
    }
  }

  async addAdmin(identity: string, folderId: string, adminIdentity: string): Promise<void> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
    await grappa.execCtrl({
      type: 'ADD_ADM',
      uid: GRaPPA.getUidFromUserId(adminIdentity),
    });
  }

  async removeAdmin(identity: string, folderId: string, adminIdentity: string): Promise<void> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
    await grappa.execCtrl({
      type: 'REM_ADM',
      uid: GRaPPA.getUidFromUserId(adminIdentity),
    });
  }

  async removeMember(identity: string, folderId: string, memberIdentity: string): Promise<void> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
    await grappa.execCtrl({
      type: 'REM',
      uid: GRaPPA.getUidFromUserId(memberIdentity),
    });
  }

  async rotateKeys(identity: string, folderId: string): Promise<void> {
    if (identity != this.currentEmail) {
      throw new Error('Inconsistent state.');
    }
    const grappa = await GRaPPA.load(identity, folderId.toString(), this.middleware);
    switch (grappa.getRole()) {
      case 'admin':
        await grappa.execCtrl({
          type: 'ROT_KEYS',
        });
        break;
      case 'member':
        await grappa.execCtrl({
          type: 'UPD_USER',
        });
        break;
      default:
        throw new Error('Invalid role, you should be either an admin or a member.');
    }
  }
}

/**
 * @returns the content of the file decrypted.
 */
export async function readFile({
  epochKey,
  epoch,
  fileId,
  encryptedFileContent,
  metadata,
}: {
  epochKey: CryptoKey;
  epoch: Epoch;
  fileId: string;
  encryptedFileContent: Uint8Array;
  metadata: Metadata;
}): Promise<ArrayBuffer> {
  // Get the file metadata
  const fileMetadata = await decryptFileMetadata(
    epochKey,
    metadata.fileMetadatasByEpoch[epoch][fileId],
    fileId
  );
  const fileCtxt = await decodeObject<FileEncryptionResult['fileCtxt']>(
    encryptedFileContent
  );
  return decryptFile(fileMetadata, fileCtxt);
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
 * @returns the metadata updated with the new file metadata object and the file content encrypted as a {@link AddFileResult}.
 */
export async function addFile({
  epochKey,
  epoch,
  fileName,
  fileId,
  file,
  metadataContent,
}: {
  epochKey: CryptoKey;
  epoch: Epoch;
  fileName: string;
  file: Buffer;
  fileId: string;
  metadataContent: Uint8Array;
}): Promise<AddFileResult> {
  // Decrypt the folder key for the current user.
  const metadata = await decodeObject<Metadata>(metadataContent);
  // Encrypt the file and modify the metadata.
  const fileEncryptionResult = await encryptFileAndFileMetadata(
    epochKey,
    file,
    fileName,
    fileId
  );
  const epochMetadatas = metadata.fileMetadatasByEpoch[epoch] || {};
  epochMetadatas[fileId] = fileEncryptionResult.fileMetadataCtxt;
  metadata.fileMetadatasByEpoch[epoch] = epochMetadatas;
  metadata.epochByFileId[fileId] = epoch;
  return {
    metadataContent: await encodeObject(metadata),
    fileCtxt: await encodeObject(fileEncryptionResult.fileCtxt),
  };
}

/**
 * Encrypt the file under an ephemeral key and the file metadata under the epoch key.
 * @param epochKey the epoch key used to encrypt the file metadata.
 * @param file the file content.
 * @param fileName the file name.
 */
export async function encryptFileAndFileMetadata(
  epochKey: CryptoKey,
  file: Buffer,
  fileName: string,
  fileId: string
): Promise<FileEncryptionResult> {
  if (epochKey.type != 'secret') {
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
    epochKey,
    encodedFileMetadata,
    string2ArrayBuffer(fileId)
  );
  return { fileCtxt, fileMetadataCtxt };
}

/**
 * Create the initial metadata file for an empty folder.
 */
export async function createEncodedInitialMetadataFile(): Promise<Buffer> {
  return encodeObject<Metadata>(createInitialMetadataFile());
}

/**
 * Create the initial metadata file for an empty folder.
 * This is just the initial map.
 */
export function createInitialMetadataFile(): Metadata {
  return { fileMetadatasByEpoch: {}, epochByFileId: {} };
}
