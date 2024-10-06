import { CrateService as dsclient } from '../../gen/clients/ds';
import { arrayBuffer2string } from '../commonCrypto';
import { AcceptedProposal, GKPMiddleware, Proposal } from './gkp';
import { decodeObject, encodeObject } from '../marshaller';

/**
 * A middleware based on the DS (see /services/ds).
 */
export class DsMiddleware implements GKPMiddleware {
  async fetchKeyPackageForUidWithFolder(
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array> {
    const identity = arrayBuffer2string(uid);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const keyPackageRaw = await dsclient.fetchKeyPackage({
      folderId: serverFolderId,
      requestBody: {
        user_email: identity,
      },
    });
    return new Uint8Array(keyPackageRaw as unknown as ArrayBuffer);
  }

  async sendProposal(folderId: Uint8Array, proposal: Proposal): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const payload = await encodeObject<Proposal>(proposal);
    await dsclient.tryPublishProposal({
      folderId: serverFolderId,
      requestBody: {
        proposal: new Blob([payload]),
      },
    });
  }

  async sendKeyPackage(keyPackage: Uint8Array): Promise<void> {
    await dsclient.publishKeyPackage({
      requestBody: {
        key_package: new Blob([keyPackage]),
      },
    });
  }

  async fetchPendingProposal(folderId: Uint8Array): Promise<AcceptedProposal> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const raw = await dsclient.getPendingProposal({
      folderId: serverFolderId,
    });
    const msg = await decodeObject<AcceptedProposal>(
      raw.payload as unknown as ArrayBuffer
    );
    // Add the message id.
    msg.messageId = raw.message_id;
    return msg;
  }

  async ackProposal(
    folderId: Uint8Array,
    proposal: AcceptedProposal
  ): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    await dsclient.ackMessage({
      folderId: serverFolderId,
      messageId: proposal.messageId,
    });
  }
}
