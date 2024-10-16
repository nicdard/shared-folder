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
import { arrayBuffer2string } from '../commonCrypto';
import {
  AcceptedProposal,
  AcceptedProposalWithApplicationMessage,
  ApplicationMessageForPendingProposals,
  GKPMiddleware,
  MemberAddGroupMessage,
  Proposal,
} from './gkp';

export class InMemoryMiddleware implements GKPMiddleware {
  private membersByFolder: Map<string, string[]> = new Map();
  private keyPackagesByIdentity: Map<string, Uint8Array[]> = new Map();
  private proposalsByIdentityAndFolder: Map<string, AcceptedProposal[]> =
    new Map();
  private applicationMessageByIdentityAndFolder: Map<
    string,
    Map<number, ApplicationMessageForPendingProposals>
  > = new Map();

  private id = 0;

  private getId(): number {
    return this.id++;
  }

  createFolder(identity: string, folderId: Uint8Array): Promise<void> {
    this.membersByFolder.set(arrayBuffer2string(folderId), [identity]);
    return Promise.resolve();
  }

  sendKeyPackage(identity: string, keyPackage: Uint8Array): Promise<void> {
    const packages = this.keyPackagesByIdentity.get(identity) || [];
    packages.push(keyPackage);
    this.keyPackagesByIdentity.set(identity, packages);
    return Promise.resolve();
  }
  fetchKeyPackageForUidWithFolder(
    identity: string,
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array> {
    const keyPackages = this.keyPackagesByIdentity.get(arrayBuffer2string(uid));
    const keyPackage = keyPackages.shift();
    return Promise.resolve(keyPackage);
  }
  sendProposal(
    identity: string,
    folderId: Uint8Array,
    proposal: Proposal
  ): Promise<number[]> {
    const folder = arrayBuffer2string(folderId);
    const members = this.membersByFolder.get(folder) || [];
    this.membersByFolder.set(folder, members);
    const ids = members
      .filter((m) => m != identity)
      .map((member) => {
        const key = InMemoryMiddleware.getKey(member, folderId);
        const proposals = this.proposalsByIdentityAndFolder.get(key) || [];
        this.proposalsByIdentityAndFolder.set(key, proposals);
        const id = this.getId();
        proposals.push({ ...proposal, messageId: id });
        return id;
      });
    return Promise.resolve(ids);
  }
  shareProposal(
    identity: string,
    folderId: Uint8Array,
    proposal: MemberAddGroupMessage
  ): Promise<number[]> {
    const folder = arrayBuffer2string(folderId);
    const members = this.membersByFolder.get(folder) || [];
    members.push(arrayBuffer2string(proposal.cmd.uid));
    this.membersByFolder.set(folder, members);
    return this.sendProposal(identity, folderId, proposal);
  }
  fetchPendingProposal(
    identity: string,
    folderId: Uint8Array
  ): Promise<AcceptedProposalWithApplicationMessage> {
    try {
      const proposals = this.proposalsByIdentityAndFolder.get(
        InMemoryMiddleware.getKey(identity, folderId)
      );
      const first = proposals[0];
      const applicationMessages =
        this.applicationMessageByIdentityAndFolder.get(
          InMemoryMiddleware.getKey(identity, folderId)
        ) || new Map<number, ApplicationMessageForPendingProposals>();
      const msg = applicationMessages.get(first.messageId);
      return Promise.resolve({
        proposal: first,
        applicationMsg: msg,
      });
    } catch (error) {
      return Promise.reject();
    }
  }
  ackProposal(
    identity: string,
    folderId: Uint8Array,
    proposal: AcceptedProposalWithApplicationMessage
  ): Promise<void> {
    const proposals = this.proposalsByIdentityAndFolder.get(
      InMemoryMiddleware.getKey(identity, folderId)
    );
    const pi = proposals.shift();
    if (pi.messageId != proposal.proposal.messageId) {
      return Promise.reject('Not the same proposal');
    }
    const applicationMessages = this.applicationMessageByIdentityAndFolder.get(
      InMemoryMiddleware.getKey(identity, folderId)
    );
    for (const messageId of proposal.applicationMsg.messageIds) {
      applicationMessages.delete(messageId);
    }
    return Promise.resolve();
  }
  sendApplicationMessage(
    identity: string,
    folderId: Uint8Array,
    applicationMsg: ApplicationMessageForPendingProposals
  ): Promise<void> {
    applicationMsg.messageIds.forEach((messageId) => {
      const members =
        this.membersByFolder.get(arrayBuffer2string(folderId)) || [];
      members
        .filter((m) => identity != m)
        .forEach((member) => {
          const applicationsMessages =
            this.applicationMessageByIdentityAndFolder.get(
              InMemoryMiddleware.getKey(member, folderId)
            ) || new Map<number, ApplicationMessageForPendingProposals>();
          this.applicationMessageByIdentityAndFolder.set(
            InMemoryMiddleware.getKey(member, folderId),
            applicationsMessages
          );
          applicationsMessages.set(messageId, applicationMsg);
        });
    });
    return Promise.resolve();
  }
  sendRemoveSelf(identity: string, folderId: Uint8Array): Promise<void> {
    this.applicationMessageByIdentityAndFolder.delete(
      InMemoryMiddleware.getKey(identity, folderId)
    );
    this.proposalsByIdentityAndFolder.delete(
      InMemoryMiddleware.getKey(identity, folderId)
    );
    const members = this.membersByFolder.get(arrayBuffer2string(folderId));
    const index = members.indexOf(identity);
    this.membersByFolder.set(arrayBuffer2string(folderId), [
      ...members.slice(0, index),
      ...members.slice(index + 1),
    ]);
    return Promise.resolve();
  }

  private static getKey(identity: string, folderId: Uint8Array) {
    return identity + '_' + arrayBuffer2string(folderId);
  }

  public getProposalQueueLength(
    identity: string,
    folderId: Uint8Array
  ): number | undefined {
    return this.proposalsByIdentityAndFolder.get(
      InMemoryMiddleware.getKey(identity, folderId)
    )?.length;
  }
}
