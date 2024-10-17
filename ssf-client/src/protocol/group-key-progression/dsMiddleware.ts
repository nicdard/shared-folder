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
  async sendRemoveSelf(sender: string, folderId: Uint8Array): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(
      `${sender}: Removing the user from the folder ${serverFolderId}`
    );
    await dsclient.removeSelfFromFolder({
      folderId: serverFolderId,
    });
  }

  async sendApplicationMessage(
    sender: string,
    folderId: Uint8Array,
    applicationMsg: ApplicationMessageForPendingProposals
  ): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(
      `${sender}: Sending application message to folder: ${serverFolderId}, messageIds: ${applicationMsg.messageIds.join(
        ', '
      )}`
    );
    const payload = await encodeObject<ApplicationMessageForPendingProposals>(
      applicationMsg
    );
    await dsclient.tryPublishApplicationMsg({
      folderId: serverFolderId,
      formData: {
        message_ids: applicationMsg.messageIds,
        payload: new Blob([payload]),
      },
    });
    console.log(
      `${sender}: Application message sent to folder: ${serverFolderId}`
    );
  }

  async shareProposal(
    sender: string,
    folderId: Uint8Array,
    proposal: MemberAddGroupMessage
  ): Promise<number[]> {
    const payload = await encodeObject<Proposal>(proposal);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(`${sender}: Sharing proposal for folder ${serverFolderId}.`);
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
    console.log(
      `${sender}: Sent share proposal, messages: ${proposalResponse.message_ids.join(
        ', '
      )}.`
    );
    return proposalResponse.message_ids;
  }

  async fetchKeyPackageForUidWithFolder(
    sender: string,
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array> {
    const identity = arrayBuffer2string(uid);
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(
      `${sender}: Fetching the key package of ${identity} in folder ${serverFolderId}`
    );
    const keyPackageRaw = await dsclient.fetchKeyPackage({
      folderId: serverFolderId,
      requestBody: {
        user_email: identity,
      },
    });
    console.log(`${sender}: Key package fetched.`);
    return new Uint8Array(keyPackageRaw.payload as unknown as ArrayBuffer);
  }

  async sendProposal(
    sender: string,
    folderId: Uint8Array,
    proposal: Proposal
  ): Promise<number[]> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    const payload = await encodeObject<Proposal>(proposal);
    console.log(`${sender}: Sending proposal to folder: ${serverFolderId}.`);
    const proposalResponse = await dsclient.tryPublishProposal({
      folderId: serverFolderId,
      formData: {
        proposal: new Blob([payload]),
      },
    });
    console.log(
      `${sender}: Proposal sent, messages: ${proposalResponse.message_ids.join(
        ', '
      )}.`
    );
    return proposalResponse.message_ids;
  }

  async sendKeyPackage(sender: string, keyPackage: Uint8Array): Promise<void> {
    console.log(`${sender}: Sending key package.`);
    await dsclient.publishKeyPackage({
      formData: {
        key_package: new Blob([keyPackage]),
      },
    });
    console.log(`${sender}: Key package sent.`);
  }

  async fetchPendingProposal(
    sender: string,
    folderId: Uint8Array
  ): Promise<AcceptedProposalWithApplicationMessage> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(
      `${sender}: Fetching pending proposal from folder: ${serverFolderId}.`
    );
    const raw = await dsclient.getPendingProposal({
      folderId: serverFolderId,
    });
    const proposal = await decodeObject<AcceptedProposal>(
      new Uint8Array(raw.payload as unknown as ArrayBuffer)
    );
    // Add the message id.
    proposal.messageId = raw.message_id;
    const applicationMsg =
      await decodeObject<ApplicationMessageForPendingProposals>(
        new Uint8Array(raw.application_payload as unknown as ArrayBuffer)
      );
    console.log(
      `${sender}: Fetched proposal from folder: ${serverFolderId}, message id: ${proposal.messageId}, command in proposal: ${proposal.cmd.type}, command in application msg: ${applicationMsg.cmd.type}.`
    );
    return {
      proposal,
      applicationMsg,
    };
  }

  async ackProposal(
    sender: string,
    folderId: Uint8Array,
    proposal: AcceptedProposalWithApplicationMessage
  ): Promise<void> {
    const serverFolderId = Number(arrayBuffer2string(folderId));
    console.log(
      `${sender}: Acking proposal in folder: ${serverFolderId}, command: ${proposal.proposal.cmd.type}`
    );
    await dsclient.ackMessage({
      folderId: serverFolderId,
      messageId: proposal.proposal.messageId,
    });
  }
}
