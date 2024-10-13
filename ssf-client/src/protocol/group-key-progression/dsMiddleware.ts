import { CrateService as dsclient } from '../../gen/clients/ds';
import { arrayBuffer2string } from '../commonCrypto';
import {
  AcceptedProposal,
  GKPMiddleware,
  MemberAddGroupMessage,
  Proposal,
 ApplicationMessageForPendingProposals,
 AcceptedProposalWithApplicationMessage,
} from './gkp';
import { decodeObject, encodeObject } from '../marshaller';

/**
 * A middleware based on the DS (see /services/ds).
 */
export class DsMiddleware implements GKPMiddleware {
  
  async sendApplicationMessage(folderId: Uint8Array, applicationMsg: ApplicationMessageForPendingProposals): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Sending application message to folder: ${serverFolderId}`);
    const payload = await encodeObject<ApplicationMessageForPendingProposals>(applicationMsg);
    await dsclient.tryPublishApplicationMsg({
      folderId: serverFolderId,
      formData: {
        message_ids: applicationMsg.messageIds,
        payload: new Blob([payload]),
      }
    })
  }

  async shareProposal(
    folderId: Uint8Array,
    proposal: MemberAddGroupMessage
  ): Promise<number[]> {
    const payload = await encodeObject<Proposal>(proposal);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Sharing proposal for folder ${serverFolderId}.`);
    const proposalResponse = await dsclient.v2ShareFolder({
      folderId: serverFolderId,
      formData: {
        email: arrayBuffer2string(proposal.cmd.uid),
        proposal: new Blob([payload]),
      },
    });
    if (!proposalResponse.message_ids) {
      throw new Error('No message ids returned');
    }
    return proposalResponse.message_ids;
  }

  async fetchKeyPackageForUidWithFolder(
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array> {
    const identity = arrayBuffer2string(uid);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Fetching key package for folder ${serverFolderId} by user ${identity}`);
    console.log(
      `Fetching the key package of ${identity} in folder ${serverFolderId}`
    );
    const keyPackageRaw = await dsclient.fetchKeyPackage({
      folderId: serverFolderId,
      requestBody: {
        user_email: identity,
      },
    });
    return new Uint8Array(keyPackageRaw.payload as unknown as ArrayBuffer);
  }

  async sendProposal(folderId: Uint8Array, proposal: Proposal): Promise<number[]> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const payload = await encodeObject<Proposal>(proposal);
    console.log(`Sending proposal to folder: ${serverFolderId}`);
    const proposalResponse = await dsclient.tryPublishProposal({
      folderId: serverFolderId,
      formData: {
        proposal: new Blob([payload]),
      },
    });
    console.log(`Proposal sent, messages: ${proposalResponse.message_ids.join(', ')}`);
    return proposalResponse.message_ids;
  }

  async sendKeyPackage(keyPackage: Uint8Array): Promise<void> {
    console.log('Sending key package');
    await dsclient.publishKeyPackage({
      formData: {
        key_package: new Blob([keyPackage]),
      },
    });
  }

  async fetchPendingProposal(folderId: Uint8Array): Promise<AcceptedProposalWithApplicationMessage> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Fetching pending proposal from folder: ${serverFolderId}`);
    const raw = await dsclient.getPendingProposal({
      folderId: serverFolderId,
    });
    const proposal = await decodeObject<AcceptedProposal>(
      new Uint8Array(raw.payload as unknown as ArrayBuffer)
    );
    // Add the message id.
    proposal.messageId = raw.message_id;
    const applicationMsg = await decodeObject<ApplicationMessageForPendingProposals>(
      new Uint8Array(raw.application_payload as unknown as ArrayBuffer)
    );
    return {
      proposal, 
      applicationMsg
    };
  }

  async ackProposal(
    folderId: Uint8Array,
    proposal: AcceptedProposalWithApplicationMessage
  ): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`Acking proposal in folder: ${serverFolderId}, command: ${proposal.proposal.cmd.type}`);
    await dsclient.ackMessage({
      folderId: serverFolderId,
      messageId: proposal.proposal.messageId,
    });
  }
}
