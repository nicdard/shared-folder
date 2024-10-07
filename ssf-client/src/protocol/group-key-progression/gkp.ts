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
  sendKeyPackage(keyPackage: Uint8Array): Promise<void>;

  /**
   * @param uid the email of the user to retrieve the key package of.
   * @param folderId the folderId we want to invite `uid` to. This is requested by the server to perform ACL check and guarantee data consistency.
   */
  fetchKeyPackageForUidWithFolder(
    uid: Uint8Array,
    folderId: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Sends a GRaPPA proposal, which can be refused by the server if the sender has pending GroupMessages to process.
   * @param folderId the folderId we want to share this message with.
   * @param proposal the proposal, composed by control and application messages depending on the command generating it.
   */
  sendProposal(folderId: Uint8Array, proposal: Proposal): Promise<void>;

  /**
   * Adds the receiver to the server ACL for the folder as well as send the attached proposal.
   * @param folderId the folder id we want to share with the receiver.
   * @param receiver the receiver of the folder.
   * @param proposal the proposal to add the receiver to GRaPPA.
   */
  shareProposal(folderId: Uint8Array, proposal: MemberJoinGroupMessage): Promise<void>;

  /**
   * Fetch the eldest pending proposal for the caller in a given folder.
   * @param folderId folder id / member group id
   */
  fetchPendingProposal(folderId: Uint8Array): Promise<AcceptedProposal>;

  /**
   * Ack a proposal back to the server, thus completing the transaction and deleting the entry from the persistent storage.
   * @param folderId the folder id / member group id.
   * @param proposal the proposal to ack.
   */
  ackProposal(folderId: Uint8Array, proposal: AcceptedProposal): Promise<void>;
}

export interface GKP {
  createGroup(groupId: string): Promise<void>;
  createGroup(
    groupId: string,
    maximumIntervalLengthWithoutBlocks: number
  ): Promise<void>;
  execCtrl(cmd: ControlCommand): Promise<void>;
  procCtrl(controlMessage: AcceptedProposal): Promise<GKP | void>;
  getEpochKey(epoch?: Epoch): Promise<CryptoKey>;
  getCurrentEpoch(): Epoch;
  getEpochInterval(): EpochInterval;
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

export interface MemberUpdGroupMessage extends BasicGroupMessage {
  cmd: UpdUserControlCommand;
}

export interface WithMemberApplicationMessage extends BasicGroupMessage {
  // C_M
  memberApplicationMsg: Uint8Array;
}

export interface MemberJoinGroupMessage extends WithMemberApplicationMessage {
  cmd: AddControlCommand;
  // W_M
  memberWelcomeMsg: Uint8Array;
  // C_omega
  memberApplicationIntMsg: Uint8Array;
}

export interface MemberRemGroupMessage extends WithMemberApplicationMessage {
  cmd: RemControlCommand;
}

export interface WithAdminApplicationlMessage {
  // C_A
  adminApplicationMsg: Uint8Array;
}

export interface WithAdminControlMessage {
  // T_A
  adminControlMsg: Uint8Array;
}

export interface AddAdmGroupMessage
  extends WithAdminControlMessage,
    WithAdminApplicationlMessage,
    WithMemberApplicationMessage {
  cmd: AddAdmControlCommand;
  // W_A
  adminWelcomeMsg: Uint8Array;
}

export interface AdminGroupMessage
  extends WithAdminControlMessage,
    WithAdminApplicationlMessage,
    WithMemberApplicationMessage {
  cmd: RemControlCommand | RotKeysControlCommand | RemAdmControlCommand;
}

export interface UpdAdminGroupMessage
  extends WithAdminControlMessage,
    WithMemberApplicationMessage {
  cmd: UpdAdmControlCommand;
}

export type Proposal =
  | AdminGroupMessage
  | AddAdmGroupMessage
  | UpdAdminGroupMessage
  | MemberRemGroupMessage
  | MemberJoinGroupMessage
  | MemberUpdGroupMessage;

export function proposalIsAddAdmGroupMessage(
  proposal: Proposal
): proposal is AddAdmGroupMessage {
  return proposal.cmd.type === 'ADD_ADM';
}

export function proposalIdAdminGroupMessage(
  proposal: Proposal
): proposal is AdminGroupMessage {
  return (
    proposal.cmd.type === 'ROT_KEYS' ||
    proposal.cmd.type === 'REM_ADM' ||
    proposal.cmd.type === 'REM'
  );
}

export function proposalHasMemberApplicationMsg(
  proposal: Proposal
): proposal is
  | MemberJoinGroupMessage
  | MemberRemGroupMessage
  | AdminGroupMessage
  | AddAdmGroupMessage
  | UpdAdminGroupMessage {
  return 'memberApplicationMsg' in proposal;
}

/**
 * All messages that we process through procCtrl.
 */
export type AcceptedProposal = {
  // The id of the message in the DS table, used to ack the processing.
  messageId: number;
} & Proposal;
