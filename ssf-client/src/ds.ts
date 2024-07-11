import { CrateService as dsclient, FolderResponse } from './gen/clients/ds';
import { PathLike } from 'fs';
import { getClientCertificate, localIsValid } from './pki';
import * as baseline from './protocol/baseline';

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
export async function createFolder(): Promise<{ id: number; etag: string }> {
  const { id, etag, version } = await dsclient.createFolder();
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
  senderPkPEM: string,
  receiverIdentity: string
) {
  const folderResponse = await dsclient.getFolder({ folderId });
  const { metadata_content, etag, version } = folderResponse;
  if (etag == null && version == null) {
    throw new Error('etag and version are both null');
  }
  if (metadata_content == null) {
    throw new Error('metadata_content is null');
  }
  const receiverPkPEM = await getClientCertificate(receiverIdentity);
  if (!localIsValid(receiverPkPEM)) {
    throw new Error(
      `The certificate of the user to share the folder with is not valid! ${receiverPkPEM}`
    );
  }
  await dsclient.shareFolder({
    folderId,
    requestBody: {
      emails: [receiverIdentity],
    },
  });
  // Also advanced the cryptographic state.
  const metadataContent = new Uint8Array(await metadata_content.arrayBuffer());
  const updatedMetadata = await baseline.shareFolder({
    senderIdentity,
    senderPkPEM,
    senderSkPEM,
    receiverIdentity,
    receiverPkPEM,
    metadataContent,
  });
  // TODO: add an api to upload the metadata or enhance the share folder api.
  await dsclient.uploadFile({
    fileId: 'dummy',
    folderId,
    formData: {
      file: new Blob([]),
      metadata: new Blob([updatedMetadata]),
      parent_etag: etag,
      parent_version: version,
    },
  });
}

/**
 * Uploads a file in the given folder.
 * @param folderId The folder where to upload the file.
 */
export async function uploadFile(folderId: number, file: PathLike) {
  const folderResponse = (await dsclient.getFolder({ folderId })).id;

  // dsclient.uploadFile({});
  // const metadata = (await dsclient.getMetadata({ folderId }));
  // console.log(metadata);
  // await dsclient.uploadFile();
}
