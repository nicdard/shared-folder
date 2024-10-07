import { CrateService as dsclient } from '../../gen/clients/ds';
import { arrayBuffer2string } from '../commonCrypto';
import { AcceptedProposal, GKPMiddleware, AddMemberGroupMessage, Proposal, WelcomeMemberGroupMessage, AcceptedWelcomeMemberGroupMessage } from './gkp';
import { decodeObject, encodeObject } from '../marshaller';

/**
 * A middleware based on the DS (see /services/ds).
 */
export class DsMiddleware implements GKPMiddleware {
  async shareProposal(folderId: Uint8Array, proposal: AddMemberGroupMessage): Promise<void> {
    const payload = await encodeObject<Proposal>(proposal);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    await dsclient.v2ShareFolder({
      folderId: serverFolderId,
      formData: {
        email: arrayBuffer2string(proposal.cmd.uid),
        proposal: new Blob([payload]),
      },
    });
  }

  async sendWelcome(folderId: Uint8Array, welcome: WelcomeMemberGroupMessage): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const payload = await encodeObject<WelcomeMemberGroupMessage>(welcome);
    console.log(`Sending welcome to folder: ${serverFolderId}`);
    await dsclient.v2ShareFolderWelcome({
      folderId: serverFolderId,
      formData: {
        email: arrayBuffer2string(welcome.cmd.uid),
        proposal: new Blob([payload]),
      },
    });
  }

  async fetchPendingWelcome(folderId: Uint8Array): Promise<AcceptedWelcomeMemberGroupMessage> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Fetching pending proposal from folder: ${serverFolderId}`);
    const raw = await dsclient.getWelcome({
      folderId: serverFolderId,
    });
    const msg = await decodeObject<AcceptedWelcomeMemberGroupMessage>(
      new Uint8Array(raw.payload as unknown as ArrayBuffer)
    );
    // Add the message id.
    msg.messageId = raw.message_id;
    return msg;
  }

  async ackWelcome(
    folderId: Uint8Array,
    welcome: AcceptedWelcomeMemberGroupMessage
  ): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Acking welcome in folder: ${serverFolderId}`);
    await dsclient.ackWelcome({
      folderId: serverFolderId,
      messageId: welcome.messageId,
    });
  }

  async fetchKeyPackageForUidWithFolder(
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array> {
    const identity = arrayBuffer2string(uid);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Fetching the key package of ${identity} in folder ${serverFolderId}`);
    const keyPackageRaw = await dsclient.fetchKeyPackage({
      folderId: serverFolderId,
      requestBody: {
        user_email: identity,
      },
    });
    return new Uint8Array(keyPackageRaw.payload as unknown as ArrayBuffer);
  }

  async sendProposal(folderId: Uint8Array, proposal: Proposal): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const payload = await encodeObject<Proposal>(proposal);
    console.log(`Sending proposal to folder: ${serverFolderId}`);
    await dsclient.tryPublishProposal({
      folderId: serverFolderId,
      formData: {
        proposal: new Blob([payload]),
      },
    });
  }

  async sendKeyPackage(keyPackage: Uint8Array): Promise<void> {
    await dsclient.publishKeyPackage({
      formData: {
        key_package: new Blob([keyPackage]),
      },
    });
  }

  async fetchPendingProposal(folderId: Uint8Array): Promise<AcceptedProposal> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Fetching pending proposal from folder: ${serverFolderId}`);
    const raw = await dsclient.getPendingProposal({
      folderId: serverFolderId,
    });
    const msg = await decodeObject<AcceptedProposal>(
      new Uint8Array(raw.payload as unknown as ArrayBuffer)
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
    console.log(`Acking proposal in folder: ${serverFolderId}`);
    await dsclient.ackMessage({
      folderId: serverFolderId,
      messageId: proposal.messageId,
    });
  }
}
