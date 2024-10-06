import { GroupMessage, CrateService as dsclient } from './gen/clients/ds';
import { PathLike, readFileSync } from 'fs';
import { getClientCertificate, localIsValid } from './pki';
import * as baseline from './protocol/baseline';
import {
  importECDHPublicKeyPEMFromCertificate,
  randomString,
} from './protocol/commonCrypto';

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
export async function createFolder({
  senderIdentity,
  senderPkPEM,
}: {
  senderIdentity: string;
  senderPkPEM: string;
}): Promise<{ id: number; etag: string }> {
  const encodedMetadata = await baseline.createEncodedInitialMetadataFile({
    senderIdentity: baseline.encodeIdentityAsMetadataMapKey(senderIdentity),
    senderPkPEM,
  });
  const metadata = new Blob([encodedMetadata]);
  const { id, etag, version } = await dsclient.createFolder({
    formData: { metadata },
  });
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
  const folderResponse = await dsclient.getFolder({ folderId });
  const { metadata_content, etag, version } = folderResponse;
  if (etag == null && version == null) {
    throw new Error('etag and version are both null');
  }
  if (metadata_content == null) {
    throw new Error('metadata_content is null');
  }
  const receiverCert = await getClientCertificate(receiverIdentity);
  if (!localIsValid(receiverCert)) {
    throw new Error(
      `The certificate of the user to share the folder with is not valid! ${receiverCert}`
    );
  }
  const receiverPkPEM = await importECDHPublicKeyPEMFromCertificate(
    receiverCert
  );
  await dsclient.shareFolder({
    folderId,
    requestBody: {
      emails: [receiverIdentity],
    },
  });
  const senderPkPEM = await importECDHPublicKeyPEMFromCertificate(senderCert);
  // Also advanced the cryptographic state.
  const metadataContent = new Uint8Array(
    metadata_content as unknown as ArrayBuffer
  );
  const updatedMetadata = await baseline.shareFolder({
    senderIdentity: baseline.encodeIdentityAsMetadataMapKey(senderIdentity),
    senderPkPEM,
    senderSkPEM,
    receiverIdentity: baseline.encodeIdentityAsMetadataMapKey(receiverIdentity),
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
  const { metadataContent: updatedMetadata, fileCtxt } = await baseline.addFile(
    {
      senderIdentity: baseline.encodeIdentityAsMetadataMapKey(senderIdentity),
      senderCertPEM: senderCert,
      senderSkPEM,
      fileName,
      file: fileContent,
      fileId,
      metadataContent,
    }
  );
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
  return baseline.readFile({
    identity: baseline.encodeIdentityAsMetadataMapKey(identity),
    certPEM,
    skPEM,
    fileId,
    encryptedFileContent,
    metadataContent,
  });
}

export async function listFiles(
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
  return baseline.listFiles(
    folderId,
    baseline.encodeIdentityAsMetadataMapKey(identity),
    skPEM,
    certPEM,
    metadataContent
  );
}

/* ---------------------- */
// Follow CGKA / GRaPPA related calls

export async function publishKeyPackage(
  keyPackage: Uint8Array,
) {
    await dsclient.publishKeyPackage({
        requestBody: {
            key_package: new Blob([keyPackage])
        }
    });
    return Promise.resolve();
}

export async function fetchKeyPackage(identity: string, folderId: number): Promise<Uint8Array> {
  const keyPackageRaw = await dsclient.fetchKeyPackage({
    folderId,
    requestBody: {
      user_email: identity
    }
  });
  return new Uint8Array(keyPackageRaw as unknown as ArrayBuffer);
}

export async function sendProposal(folderId: number, proposal: ArrayBufferLike) {
  await dsclient.tryPublishProposal({
    folderId,
    requestBody: {
      proposal: new Blob([proposal])
    }
  })
}

export async function fetchPendingProposal(folderId: number): Promise<GroupMessage> {
  return await dsclient.getPendingProposal({
    folderId
  });
}

export async function ackPendingProposal(folderId: number, messageId: number) {
  return await dsclient.ackMessage({
    folderId, 
    messageId
  });
}