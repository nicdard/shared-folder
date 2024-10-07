import { CrateService as dsclient } from './gen/clients/ds';
import { PathLike, readFileSync } from 'fs';
import { getClientCertificate, localIsValid } from './pki';
import { randomString } from './protocol/commonCrypto';
import { protocolClient } from './protocol/protocolCommon';


/**
 * @param email the email to register. This needs to match the one in the client certificate.
 * @see loadDsTLSInterceptor
 */
export async function register(email: string) {
  await dsclient.createUser({
    requestBody: {
      email,
    },
  });
  // Create a client.
  // await protocolClient.register(email);
}

/**
 * @returns the users currently present on the system.
 */
export async function listUsers(): Promise<string[]> {
  return (await dsclient.listUsers()).emails;
}

/**
 * @returns a new folder for the current user.
 */
export async function createFolder({
  senderIdentity,
  senderPkPEM,
}: {
  senderIdentity: string;
  senderPkPEM: string;
}): Promise<{ id: number; etag: string }> {
  const encodedMetadata = await protocolClient.createNewFolderMetadata(
    senderIdentity,
    senderPkPEM
  );
  const metadata = new Blob([encodedMetadata]);
  const { id, etag, version } = await dsclient.createFolder({
    formData: { metadata },
  });
  await protocolClient.createFolder(senderIdentity, id);
  return { id, etag: etag ?? version };
}

/**
 * @returns all folders where the current user is a participant.
 */
export async function listFolders(): Promise<number[]> {
  return (await dsclient.listFoldersForUser()).folders;
}

/**
 * @param folderId The folder to share.
 * @param senderIdentity The user identity.
 */
export async function shareFolder(
  folderId: number,
  senderIdentity: string,
  senderSkPEM: string,
  senderCert: string,
  receiverIdentity: string
) {
  const receiverCert = await getClientCertificate(receiverIdentity);
  if (!localIsValid(receiverCert)) {
    throw new Error(
      `The certificate of the user to share the folder with is not valid! ${receiverCert}`
    );
  }
  const folderResponse = await dsclient.getFolder({ folderId });
  const { metadata_content, etag, version } = folderResponse;
  if (etag == null && version == null) {
    throw new Error('etag and version are both null');
  }
  if (metadata_content == null) {
    throw new Error('metadata_content is null');
  }
  await protocolClient.shareFolder({
    folderId,
    senderCert,
    senderIdentity,
    senderSkPEM,
    receiverCert,
    receiverIdentity,
    // FIXME: this is a terrible ack
    metadata_content: metadata_content as unknown as ArrayBuffer,
    etag,
    version,
  });
}

/**
 * Uploads a file in the given folder.
 * @param folderId The folder where to upload the file.
 */
export async function uploadFile(
  folderId: number,
  senderIdentity: string,
  senderSkPEM: string,
  senderCert: string,
  fileName: string,
  file: PathLike
): Promise<string> {
  const folderResponse = await dsclient.getFolder({ folderId });
  const { metadata_content, etag, version } = folderResponse;
  if (etag == null && version == null) {
    throw new Error('etag and version are both null');
  }
  if (metadata_content == null) {
    throw new Error('metadata_content is null');
  }
  const fileContent = readFileSync(file);
  const metadataContent = new Uint8Array(
    metadata_content as unknown as ArrayBuffer
  );
  const fileId = randomString(40);
  const { metadataContent: updatedMetadata, fileCtxt } =
    await protocolClient.addFile({
      senderCertPEM: senderCert,
      senderIdentity,
      senderSkPEM,
      file: fileContent,
      fileId,
      fileName,
      metadataContent,
      folderId,
    });
  await dsclient.uploadFile({
    fileId,
    folderId,
    formData: {
      metadata: new Blob([updatedMetadata]),
      file: new Blob([fileCtxt]),
      parent_etag: etag,
      parent_version: version,
    },
  });
  return fileId;
}

/**
 * @param folderId the folder id
 * @param identity the identity requesting the operation, must match the crypto keys
 * @param skPEM the secret key
 * @param certPEM the certificate containing the identity and public key
 * @param fileId the tile id to retrieve
 * @returns the file if exists
 */
export async function downloadFile(
  folderId: number,
  identity: string,
  skPEM: string,
  certPEM: string,
  fileId: string
): Promise<ArrayBuffer> {
  // TODO(future): optimise the server to return both metadata and file together?
  // However we could cache the calls to metadata file
  const { file: metadata_content } = await dsclient.getMetadata({
    folderId,
  });
  const metadataContent = new Uint8Array(
    metadata_content as unknown as ArrayBuffer
  );
  const encryptedFileContent = new Uint8Array(
    (
      await dsclient.getFile({
        fileId,
        folderId,
      })
    ).file as unknown as ArrayBuffer
  );
  // Decrypt the file.
  return protocolClient.readFile({
    identity,
    certPEM,
    skPEM,
    fileId,
    encryptedFileContent,
    metadataContent,
    folderId,
  });
}

export async function listAllFiles(
  folderId: number,
  identity: string,
  skPEM: string,
  certPEM: string
): Promise<Record<string, string>> {
  const { file: metadata_content } = await dsclient.getMetadata({
    folderId,
  });
  const metadataContent = new Uint8Array(
    metadata_content as unknown as ArrayBuffer
  );
  return protocolClient.listFiles({
    folderId,
    identity,
    skPEM,
    certPEM,
    metadataContent,
  });
}
