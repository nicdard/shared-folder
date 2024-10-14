import { BaselineProtocolClient } from './baseline';
import { GKPProtocolClient } from './ssf';

export const protocol =
  process?.env?.PROTOCOL != undefined ? process.env.PROTOCOL : 'baseline';

export type AddFileResult = {
  metadataContent: Buffer;
  fileCtxt: Buffer;
};

export interface ProtocolClient {
  register(email: string): Promise<void>;
  load(email: string): Promise<void>;
  createNewFolderMetadata(
    senderIdentity: string,
    senderPkPEM: string
  ): Promise<Buffer>;
  createFolder(senderIdentity: string, folderId: number): Promise<void>;
  shareFolder(params: {
    folderId: number;
    receiverIdentity: string;
    receiverCert: string;
    senderIdentity: string;
    senderCert: string;
    senderSkPEM: string;
    metadata_content: ArrayBuffer;
    etag?: string;
    version?: string;
  }): Promise<void>;
  addFile(params: {
    senderIdentity: string;
    senderCertPEM: string;
    senderSkPEM: string;
    fileName: string;
    file: Buffer;
    fileId: string;
    metadataContent: Uint8Array;
    folderId: number;
  }): Promise<AddFileResult>;
  readFile(params: {
    identity: string;
    certPEM: string;
    skPEM: string;
    fileId: string;
    encryptedFileContent: Uint8Array;
    metadataContent: Uint8Array;
    folderId: number;
  }): Promise<ArrayBuffer>;

  listFiles(params: {
    folderId: number;
    identity: string;
    skPEM: string;
    certPEM: string;
    metadataContent: Uint8Array;
  }): Promise<Record<string, string>>;

  syncFolder(identity: string, folderId: string): Promise<void>;

  addAdmin(identity: string, folderId: string, adminIdentity: string): Promise<void>;
  
  removeAdmin(identity: string, folderId: string, adminIdentity: string): Promise<void>;
  
  removeMember(identity: string, folderId: string, memberIdentity: string): Promise<void>;

  rotateKeys(identity: string, folderId: string): Promise<void>;

  getFoldersToSync(): { folders: number[], keyPackages: number };
}

export const protocolClient: ProtocolClient =
  protocol === 'GRaPPA'
    ? new GKPProtocolClient()
    : new BaselineProtocolClient();
