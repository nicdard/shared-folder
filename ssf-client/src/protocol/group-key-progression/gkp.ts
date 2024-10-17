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
import {
  DoubleChainsInterval,
  Epoch,
  EpochInterval,
  KP,
} from '../key-progression/kp';

/**
 * Abstract the communication with the other clients through a Server used for synchronization.
 */
export interface GKPMiddleware {
  /**
   * Sends a keyPackage to the server to be stored and consumed for future joins from other users.
   * @param keyPackage the serialized key package to store in the server.
   */
  sendKeyPackage(identity: string, keyPackage: Uint8Array): Promise<void>;

  /**
   * @param uid the email of the user to retrieve the key package of.
   * @param folderId the folderId we want to invite `uid` to. This is requested by the server to perform ACL check and guarantee data consistency.
   */
  fetchKeyPackageForUidWithFolder(
    identity: string,
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Sends a GRaPPA proposal, which can be refused by the server if the sender has pending GroupMessages to process.
   * @param folderId the folderId we want to share this message with.
   * @param proposal the proposal, composed by control and application messages depending on the command generating it.
   * @returns the message ids of the created proposals.
   */
  sendProposal(
    identity: string,
    folderId: Uint8Array,
    proposal: Proposal
  ): Promise<number[]>;

  /**
   * Adds the receiver to the server ACL for the folder as well as send the attached proposal.
   * @param folderId the folder id we want to share with the receiver.
   * @param receiver the receiver of the folder.
   * @param proposal the proposal to add the receiver to GRaPPA.
   * @returns the message ids of the creted proposals.
   */
  shareProposal(
    identity: string,
    folderId: Uint8Array,
    proposal: MemberAddGroupMessage
  ): Promise<number[]>;

  /**
   * Fetch the eldest pending proposal for the caller in a given folder.
   * @param folderId folder id / member group id
   */
  fetchPendingProposal(
    identity: string,
    folderId: Uint8Array
  ): Promise<AcceptedProposalWithApplicationMessage>;

  /**
   * Ack a proposal back to the server, thus completing the transaction and deleting the entry from the persistent storage.
   * @param folderId the folder id / member group id.
   * @param proposal the proposal to ack.
   */
  ackProposal(
    identity: string,
    folderId: Uint8Array,
    proposal: AcceptedProposalWithApplicationMessage
  ): Promise<void>;

  /**
   * @param folderId the folder id this message refers to.
   * @param applicationMsg the application message to send to the server.
   */
  sendApplicationMessage(
    identity: string,
    folderId: Uint8Array,
    applicationMsg: ApplicationMessageForPendingProposals
  ): Promise<void>;

  /**
   * Remove self from folder.
   */
  sendRemoveSelf(identity: string, folderId: Uint8Array): Promise<void>;
}

export interface GKP {
  createGroup(groupId: string): Promise<void>;
  createGroup(
    groupId: string,
    maximumIntervalLengthWithoutBlocks: number
  ): Promise<void>;
  execCtrl(cmd: ControlCommand): Promise<void>;
  procCtrl(
    controlMessage: AcceptedProposalWithApplicationMessage
  ): Promise<GKP | undefined>;
  getEpochKey(epoch?: Epoch): Promise<CryptoKey>;
  getCurrentEpoch(): Epoch;
  getEpochInterval(): EpochInterval;
  getRole(): ClientState['role'];
  getUserId(): string;
}

interface BaseState {
  cgkaMemberGroupId: Uint8Array;
}

export interface MemberState extends BaseState {
  role: 'member';
  interval: DoubleChainsInterval;
}

export interface AdminState extends BaseState {
  role: 'admin';
  cgkaAdminGroupId: Uint8Array;
  kp: KP;
}

export type ClientState = AdminState | MemberState;

export interface BaseControlCommand {
  uid: Uint8Array;
}

export interface AddControlCommand extends BaseControlCommand {
  type: 'ADD';
}

export interface RemControlCommand extends BaseControlCommand {
  type: 'REM';
}

export interface AddAdmControlCommand extends BaseControlCommand {
  type: 'ADD_ADM';
}

export interface RemAdmControlCommand extends BaseControlCommand {
  type: 'REM_ADM';
}

export interface UpdAdmControlCommand {
  type: 'UPD_ADM';
}

export interface RotKeysControlCommand {
  type: 'ROT_KEYS';
}

export interface UpdUserControlCommand {
  type: 'UPD_USER';
}

type AdminControlCommand =
  | AddControlCommand
  | RemControlCommand
  | AddAdmControlCommand
  | RemAdmControlCommand
  | UpdAdmControlCommand
  | RotKeysControlCommand;

export type AdminControlCommandTypes = AdminControlCommand['type'];

type UserControlCommand = UpdUserControlCommand;

export type ControlCommand = AdminControlCommand | UserControlCommand;

export interface BasicGroupMessage {
  // The member control message (T_M)
  memberControlMsg: Uint8Array;
}

export interface MemberGroupMessage extends BasicGroupMessage {
  cmd: UpdUserControlCommand | RemControlCommand;
}

export interface WithMemberWelcomeMessage extends BasicGroupMessage {
  // W_M
  memberWelcomeMsg: Uint8Array;
}

export interface MemberAddGroupMessage extends WithMemberWelcomeMessage {
  cmd: AddControlCommand;
}

export interface WithAdminControlMessage {
  // T_A
  adminControlMsg: Uint8Array;
}

export interface WithAdminWelcomeMessage {
  // W_A
  adminWelcomeMsg: Uint8Array;
}

export interface AddAdmGroupMessage
  extends WithAdminControlMessage,
    WithAdminWelcomeMessage,
    BasicGroupMessage {
  cmd: AddAdmControlCommand;
}

export interface AdminGroupMessage
  extends WithAdminControlMessage,
    BasicGroupMessage {
  cmd:
    | RemControlCommand
    | RotKeysControlCommand
    | RemAdmControlCommand
    | UpdAdmControlCommand;
}

export type Proposal =
  | AddAdmGroupMessage
  | AdminGroupMessage
  | MemberAddGroupMessage
  | MemberGroupMessage;

export function proposalIsAdminGroupMessage(
  proposal: Proposal
): proposal is Proposal & WithAdminControlMessage {
  return 'adminControlMsg' in proposal;
}

export function proposalIsAdminGroupMessageWithNonEmptyBlock(
  proposal: Proposal
): proposal is AdminGroupMessage {
  return (
    proposal.cmd.type === 'ROT_KEYS' ||
    proposal.cmd.type === 'REM_ADM' ||
    proposal.cmd.type === 'REM'
  );
}

/**
 * All messages that we process through procCtrl.
 */
export type AcceptedProposal = {
  // The id of the message in the DS table, used to ack the processing.
  messageId: number;
} & Proposal;

/**
 * An empty application message. No DKR state needs to be comunicated.
 */
export interface UpdMemberApplicationMessage {
  cmd: UpdUserControlCommand;
}

interface BasicApplicationMessage {
  // The member application message (C_M), for members of the group.
  memberApplicationMsg: Uint8Array;
}

export interface AddMemberApplicationMessage extends BasicApplicationMessage {
  cmd: AddControlCommand;
  // The DKR interval for the new member.(C_omega)
  memberApplicationIntMsg: Uint8Array;
}

interface BasicAdminApplicationMessage extends BasicApplicationMessage {
  // The admin application message (C_A), for admins of the group.
  adminApplicationMsg: Uint8Array;
}

export interface AdminApplicationMessage extends BasicAdminApplicationMessage {
  cmd: RotKeysControlCommand | RemAdmControlCommand;
}

export interface AddAdminApplicationMessage
  extends BasicAdminApplicationMessage {
  cmd: AddAdmControlCommand;
}

export interface RemMemberApplicationMessage
  extends BasicAdminApplicationMessage {
  cmd: RemControlCommand;
}

export interface UpdAdminApplicationMessage extends BasicApplicationMessage {
  cmd: UpdAdmControlCommand;
}

export type ApplicationMessageWithAdminApplicationMsg =
  | AdminApplicationMessage
  | AddAdminApplicationMessage
  | RemMemberApplicationMessage;

export type ApplicationMessageWithMemberApplicationMsg =
  | UpdAdminApplicationMessage
  | AddMemberApplicationMessage
  | ApplicationMessageWithAdminApplicationMsg;

export type ApplicationMessage =
  | ApplicationMessageWithMemberApplicationMsg
  | UpdMemberApplicationMessage;

export function applicationMessageHasMemberApplicationMsg(
  applicationMessage: ApplicationMessage
): applicationMessage is ApplicationMessageWithMemberApplicationMsg {
  return 'memberApplicationMsg' in applicationMessage;
}

export function applicationMessageHasAdminApplicationMsg(
  applicationMessage: ApplicationMessage
): applicationMessage is ApplicationMessageWithAdminApplicationMsg {
  return 'adminApplicationMsg' in applicationMessage;
}

export type ApplicationMessageForPendingProposals =
  | ApplicationMessage & {
      messageIds: number[];
    };

export type AcceptedProposalWithApplicationMessage = {
  readonly proposal: AcceptedProposal;
  readonly applicationMsg: ApplicationMessageForPendingProposals;
};

export function proposalIsMemberAddGroupMessage(
  proposal: Proposal
): proposal is MemberAddGroupMessage {
  return proposal.cmd.type === 'ADD';
}

export function applicationMessageIsAddMemberApplicationMessage(
  applicationMessage: ApplicationMessage
): applicationMessage is AddMemberApplicationMessage {
  return applicationMessage.cmd.type === 'ADD';
}

export function proposalIsAcceptedWelcomeAdminGroupMessage(
  proposal: Proposal
): proposal is AddAdmGroupMessage {
  return proposal.cmd.type === 'ADD_ADM';
}

export function applicationMessageIsAddAdminApplicationMessage(
  applicationMessage: ApplicationMessage
): applicationMessage is AddAdminApplicationMessage {
  return applicationMessage.cmd.type === 'ADD_ADM';
}
