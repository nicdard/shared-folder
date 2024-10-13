import { arrayBuffer2string, string2Uint8Array } from '../commonCrypto';
import { KaPPA } from '../key-progression/kappa';
import {
  BlockType,
  DoubleChainsInterval,
  Epoch,
  EpochInterval,
} from '../key-progression/kp';
import {
  AddAdmControlCommand,
  AddControlCommand,
  AdminState,
  ClientState,
  ControlCommand,
  GKP,
  RemAdmControlCommand,
  RemControlCommand,
  RotKeysControlCommand,
  UpdAdmControlCommand,
  UpdUserControlCommand,
  proposalIsAdminGroupMessageWithNonEmptyBlock,
  GKPMiddleware,
  AcceptedProposalWithApplicationMessage,
  proposalIsMemberAddGroupMessage,
  applicationMessageIsAddMemberApplicationMessage,
  proposalIsAcceptedWelcomeAdminGroupMessage,
  applicationMessageIsAddAdminApplicationMessage,
  applicationMessageHasMemberApplicationMsg,
  applicationMessageHasAdminApplicationMsg,
} from './gkp';
import {
  ApplicationMsgAuthenticatedData,
  mlsCgkaAddProposal,
  mlsCgkaApplyPendingCommit,
  mlsCgkaDeletePendingCommit,
  mlsCgkaInit,
  mlsCgkaJoinGroup,
  mlsCgkaRemoveProposal,
  mlsCgkaUpdateKeys,
  mlsGenerateKeyPackage,
  mlsInitClient,
  mlsPrepareAppMsg,
  mlsProcessIncomingMsg,
} from 'ssf';
import { GKPFileStorage } from './storage';

// 32 as default, we can change it later. The smaller the heavier the protocol to run.
const DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK = 32;

export class GRaPPA implements GKP {
  private state: ClientState;

  private constructor(
    readonly uid: Uint8Array,
    readonly userId: string,
    readonly middleware: GKPMiddleware
  ) {}

  /**
   * @param userId the user id to be initialised.
   * @param middleware abstractions for server communications.
   * @returns a new {@link GKP} instance that can be used to either create a group, or listen for a join invitation to an unknown group.
   */
  public static async initUser(
    userId: string,
    middleware: GKPMiddleware
  ): Promise<GKP> {
    const uid = GRaPPA.getUidFromUserId(userId);
    // This will fetch the existing mls client if any. Therefore we can instantiate multiple GRaPPAs.
    await mlsInitClient(uid);
    await this.publishKeyPackage(userId, middleware);
    return new GRaPPA(uid, userId, middleware);
  }

  public static async load(
    userId: string,
    groupId: string,
    middleware: GKPMiddleware
  ): Promise<GKP> {
    const state = await GKPFileStorage.load(userId, string2Uint8Array(groupId));
    const grappa = new GRaPPA(
      GRaPPA.getUidFromUserId(userId),
      userId,
      middleware
    );
    grappa.state = state;
    console.log(`Loaded state for ${userId} in group ${groupId}: role '${state.role}'`);
    return grappa;
  }

  /**
   * Creates a new group. The user is an administrator of the group.
   * Initialise the dual key regression state and both member and admin CGKA.
   * Saves the state to be loaded afterwards.
   * @param groupId The group name.
   * @param maximumIntervalLengthWithoutBlocks the maximum length for the backward chains in dual key regression.
   */
  public async createGroup(
    groupId: string,
    maximumIntervalLengthWithoutBlocks: number = DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK
  ): Promise<void> {
    const cgkaMemberGroupId = string2Uint8Array(groupId);
    const cgkaAdminGroupId =
      GRaPPA.getCgkaAdminGroupIdFromMemberGroupId(groupId);
    await mlsCgkaInit(this.uid, cgkaMemberGroupId);
    await mlsCgkaInit(this.uid, cgkaAdminGroupId);
    const kp = await KaPPA.init(maximumIntervalLengthWithoutBlocks);
    this.state = {
      role: 'admin',
      cgkaMemberGroupId,
      cgkaAdminGroupId,
      kp,
    };
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * Creates or fetches an existing CGKA/MLS client for the uid.
   * Creates and publish a key package.
   * @param userId the user id to fetch the CGKA/MLS client.
   * @param middleware abstractions for server communications.
   */
  public static async publishKeyPackage(
    userId: string,
    middleware: GKPMiddleware
  ): Promise<void> {
    const uid = string2Uint8Array(userId);
    const keyPackageMsg = await mlsGenerateKeyPackage(uid);
    return middleware.sendKeyPackage(keyPackageMsg);
  }

  /**
   * Process a welcome message and adds userId to the group.
   * @param userId
   * @param middleware
   * @param welcome
   * @returns
   */
  public static async joinCtrl(
    userId: string,
    middleware: GKPMiddleware,
    proposal: AcceptedProposalWithApplicationMessage,
  ): Promise<GKP> {
    if (proposalIsMemberAddGroupMessage(proposal.proposal) && applicationMessageIsAddMemberApplicationMessage(proposal.applicationMsg)) {
      // Publish a new key package to allow for new joins.
      // await this.publishKeyPackage(userId, middleware);
      // Try to join the group.
      const uid = string2Uint8Array(userId);
      if (proposal.proposal.cmd.type !== 'ADD' || proposal.applicationMsg.cmd.type !== 'ADD') {
        throw new Error('Only ADD proposals/messages can be processed during a join.');
      }
      const cgkaMemberGroupId = await mlsCgkaJoinGroup(
        uid,
        proposal.proposal.memberWelcomeMsg
      );
      const intervalMessage = await mlsProcessIncomingMsg(
        uid,
        cgkaMemberGroupId,
        proposal.applicationMsg.memberApplicationIntMsg
      );
      const { data, authenticatedData } = intervalMessage;
      if (authenticatedData !== ApplicationMsgAuthenticatedData.KpInt) {
        throw new Error(
          'During a join, the application msg should contain an interval.'
        );
      }
      const interval = await KaPPA.deserializeExported(data);
      const grappa = new GRaPPA(uid, userId, middleware);
      grappa.state = {
        role: 'member',
        cgkaMemberGroupId,
        interval,
      };
      // Save the new group state.
      await GKPFileStorage.save(userId, grappa.state);
      await middleware.ackProposal(cgkaMemberGroupId, proposal);
      return grappa;
    } else {
      throw new Error('Invalid proposal or application message.');
    }
  }

  public async execCtrl(cmd: ControlCommand): Promise<void> {
    try {
      switch (cmd.type) {
        case 'ADD':
          await this.execAddCtrl(cmd);
          break;
        case 'REM':
          await this.execRemCtrl(cmd);
          break;
        case 'ADD_ADM':
          await this.execAddAdminCtrl(cmd);
          break;
        case 'REM_ADM':
          await this.execRemAdminCtrl(cmd);
          break;
        case 'UPD_ADM':
          await this.execUpdAdminCtrl(cmd);
          break;
        case 'ROT_KEYS':
          await this.execRotateKeysCtrl(cmd);
          break;
        case 'UPD_USER':
          await this.execUpdUserCtrl(cmd);
          break;
        default:
          throw new Error('Not yet implemented.');
      }
    } catch (error) {
      console.error(
        `Couldn't execute operation ${cmd.type}, due to error: '${
          error as unknown as string
        }'. Fetching the latest state`
      );
      // Cleanup pending changes.
      await mlsCgkaDeletePendingCommit(this.uid, this.state.cgkaMemberGroupId);

      if (this.state.role === 'admin') {
        await mlsCgkaDeletePendingCommit(this.uid, this.state.cgkaAdminGroupId);
      }
      // Revert DKR state by loading the previous one saved.
      this.state = await GKPFileStorage.load(
        this.userId,
        this.state.cgkaMemberGroupId
      );
      // Fetch latest state?
      try {
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const pendingProposal = await this.middleware.fetchPendingProposal(
            this.state.cgkaMemberGroupId
          );
          await this.procCtrl(pendingProposal);
        }
      } catch (error) {
        console.debug('The client is synced, you can now retry.');
      }
    }
  }

  /**
   * Admin command. Add a new user to the member group.
   * The user can then become an admin later if an admin propose the addition to the admin group.
   * This command executes in two phases:
   * - prepare the new CGKA state (without applying it - meaning discarding the old one) and the welcome message.
   * - persist locally the welcome message, so that if an interruption happen, this can be retrieved after applying the CGKA state.
   * - send a proposal (with the new GRaPPA state) to the group, using the DS for synchronization. The proposal is sent to all current members, not the new one.
   * - if the proposal is accepted (meaning, the proposing admin is up to date with the state):
   * -- apply CGKA state, serialize and store the GRaPPA state.
   * -- send the welcome message to the new member, including the initial DKR interval that is now encrypted under a CGKA secret that is accessible to the new member.
   * -- if there is an interruption between the two steps above, restore the welcome message upon restart and send it to the server.
   * @param cmd {@link AddAdmControlCommand}
   */
  private async execAddCtrl(cmd: AddControlCommand): Promise<void> {
    if (this.state.role != 'admin') {
      throw new Error('Only admins can add new users to the group.');
    }
    // retrieve the keyPackage for the given user.
    const keyPackageRawMsg =
      await this.middleware.fetchKeyPackageForUidWithFolder(
        cmd.uid,
        this.state.cgkaMemberGroupId
      );
    // create the proposal.
    const { controlMsg, welcomeMsg } = await mlsCgkaAddProposal(
      this.uid,
      this.state.cgkaMemberGroupId,
      keyPackageRawMsg
    );
    // send the proposal to the server.
    const messageIds = await this.middleware.shareProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For all users.
      memberControlMsg: controlMsg,
      // For Joining member.
      memberWelcomeMsg: welcomeMsg,
    });
    console.log('Proposal sent');
    // if there is no error, this means that the proposal can be applied,
    // as it was accepted by the server. I.e. the client state is up to date.
    await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    // TODO: persist the welcome message to be sure to be able to send it after the CGKA state is applied.
    // console.debug('Add proposal', controlMsg, welcomeMsg);
    const extension = await this.runKP(BlockType.EMPTY);
    const interval = await this.state.kp.getInterval({
      left: this.state.kp.getMaxEpoch(),
      right: this.state.kp.getMaxEpoch(),
    });
    const extensionPayload = await KaPPA.serializeExported(extension);
    const intervalPayload = await KaPPA.serializeExported(interval);
    // C_M create the extension for the existing users.
    const extensionMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      extensionPayload,
      ApplicationMsgAuthenticatedData.KpExt
    );
    // Now let's encrypt the initial DKR state for the new member, under a CGKA epoch secret that is accessible.
    const intervalMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      intervalPayload,
      ApplicationMsgAuthenticatedData.KpInt
    );
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
      memberApplicationIntMsg: intervalMessage,
      // For all users.
      memberApplicationMsg: extensionMessage,
    });
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * Admin command. Remove a user from the member group.
   * First use {@link RemAdmControlCommand} if the member is also an admin.
   * @param cmd {@link RemControlCommand}
   */
  private async execRemCtrl(cmd: RemControlCommand): Promise<void> {
    if (this.state.role != 'admin') {
      throw new Error('Only admins can remove users from the group.');
    }
    const controlMsg = await mlsCgkaRemoveProposal(
      this.uid,
      this.state.cgkaMemberGroupId,
      cmd.uid
    );
     // send the proposal to the server.
    const messageIds = await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For all users
      memberControlMsg: controlMsg,
    });
    await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    // TODO: Save the current operation.
    const extension = await this.runKP(BlockType.FORWARD_BLOCK);
    const extensionPayload = await KaPPA.serializeExported(extension);
    const extensionMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      extensionPayload,
      ApplicationMsgAuthenticatedData.KpExt
    );
    const kpStatePayload = await this.state.kp.serialize();
    const kpStateMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaAdminGroupId,
      kpStatePayload,
      ApplicationMsgAuthenticatedData.KpState
    );
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
      memberApplicationMsg: extensionMessage,
      adminApplicationMsg: kpStateMessage,
    });
    // if there is no error, this means that the proposal can be applied,
    // as it was accepted by the server. I.e. the client state is up to date.
    // TODO clear the current operation.
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * Admin command. Elevate the member to admin.
   * @param cmd {@link AddAdmControlCommand} containing the uid of the target member.
   */
  private async execAddAdminCtrl(cmd: AddAdmControlCommand) {
    console.log("Adding admin");
    if (this.state.role != 'admin') {
      throw new Error('Only admins can add new users to the group.');
    }
    const keyPackage = await this.middleware.fetchKeyPackageForUidWithFolder(
      cmd.uid, this.state.cgkaMemberGroupId
    );
    const { controlMsg: adminControlMsg, welcomeMsg: adminWelcomeMsg } =
      await mlsCgkaAddProposal(this.uid, this.state.cgkaAdminGroupId, keyPackage);
    console.log("Generated welcome message and commit for admin group.");
    // TODO store welcome message in local persistent storage.
    // FIXME: this is failing because of HPKE DeriveKeyPair not working with P-256, P-384, P-521.
    /*const controlMessage = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaMemberGroupId
    );
    console.log("Updated the keys in member group");
    */
    // This proposal will be received also by the new admin.
    // This will signal that a new admin welcome message is present to the new admin.
    const messageIds = await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For the admins.
      adminControlMsg,
      // For all users.
      memberControlMsg: new Uint8Array(),// FIXME: controlMessage,
      // For the new admin.
      adminWelcomeMsg,
    });
    await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
    //await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    // FIXME(protocol): Give access to all state anyway, should we remove this empty block?
    const extension = await this.runKP(BlockType.EMPTY);
    const extensionPayload = await KaPPA.serializeExported(extension);
    const kpStatePayload = await this.state.kp.serialize();
    console.log("Preparing extension data");
    const extensionMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      extensionPayload,
      ApplicationMsgAuthenticatedData.KpExt
    );
    console.log("KPExt prepared.");
    const kpStateMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaAdminGroupId,
      kpStatePayload,
      ApplicationMsgAuthenticatedData.KpState
    );
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
      adminApplicationMsg: kpStateMessage,
      memberApplicationMsg: extensionMessage,
    });
    
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * Admin command. Remove admin privileges from a member.
   * @param cmd {@link RemAdmControlCommand} containin the uid of the target admin.
   */
  private async execRemAdminCtrl(cmd: RemAdmControlCommand) {
    if (this.state.role != 'admin') {
      throw new Error('Only admins can add new users to the group.');
    }
    const adminControlMsg = await mlsCgkaRemoveProposal(
      this.uid,
      this.state.cgkaAdminGroupId,
      cmd.uid
    );
    // FIXME: this is failing because of HPKE DeriveKeyPair not working with P-256, P-384, P-521.
    /*const controlMessage = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaMemberGroupId
    );*/
    const messageIds = await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For the admins.
      adminControlMsg,
      // For all users.
      memberControlMsg: new Uint8Array(),//FIXME: controlMessage,
    });
    await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
    //await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    const extension = await this.runKP(BlockType.BACKWARD_BLOCK);
    const extensionPayload = await KaPPA.serializeExported(extension);
    const kpStatePayload = await this.state.kp.serialize();
    const extensionMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      extensionPayload,
      ApplicationMsgAuthenticatedData.KpExt
    );
    const kpStateMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      kpStatePayload,
      ApplicationMsgAuthenticatedData.KpState
    );
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
      adminApplicationMsg: kpStateMessage,
      memberApplicationMsg: extensionMessage,
    });
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * Admin command. Refresh the admin state and progress the DKR state.
   * @param cmd {@link UpdAdmControlCommand}
   */
  private async execUpdAdminCtrl(cmd: UpdAdmControlCommand) {
    if (this.state.role != 'admin') {
      throw new Error('Only admins can add new users to the group.');
    }
    const adminControlMsg = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaAdminGroupId
    );
    /*const controlMessage = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaMemberGroupId
    );*/
    const messageIds = await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For the admins.
      adminControlMsg,
      // For all users.
      memberControlMsg: new Uint8Array(),// FIXME: controlMessage,
    });
    //await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
    const extension = await this.runKP(BlockType.EMPTY);
    const extensionPayload = await KaPPA.serializeExported(extension);
    const extensionMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      extensionPayload,
      ApplicationMsgAuthenticatedData.KpExt
    );
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
      memberApplicationMsg: extensionMessage,
    });
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * Admin command.
   * Rotate the key material for the entire shared folder.
   * @param cmd {@link RotKeysControlCommand}
   */
  private async execRotateKeysCtrl(cmd: RotKeysControlCommand) {
    if (this.state.role != 'admin') {
      throw new Error('Only admins can add new users to the group.');
    }
    const adminControlMsg = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaAdminGroupId
    );
    /*const controlMessage = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaMemberGroupId
    );*/
    const messageIds = await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For the admins.
      adminControlMsg,
      // For all users.
      memberControlMsg: new Uint8Array()// FIXME: controlMessage,
    });
    //await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
    const extension = await this.runKP(BlockType.BACKWARD_BLOCK);
    const extensionPayload = await KaPPA.serializeExported(extension);
    const kpStatePayload = await this.state.kp.serialize();
    const extensionMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      extensionPayload,
      ApplicationMsgAuthenticatedData.KpExt
    );
    const kpStateMessage = await mlsPrepareAppMsg(
      this.uid,
      this.state.cgkaMemberGroupId,
      kpStatePayload,
      ApplicationMsgAuthenticatedData.KpState
    );
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
      adminApplicationMsg: kpStateMessage,
      memberApplicationMsg: extensionMessage,
    });
    await GKPFileStorage.save(this.userId, this.state);
  }

  /**
   * The only non-admin command of the protocol.
   * It allows a user to update its own local CGKA state.
   * @param cmd {@link UpdUserControlCommand}
   * @see ControlCommand
   */
  private async execUpdUserCtrl(cmd: UpdUserControlCommand): Promise<void> {
    if (this.state.role !== 'member') {
      throw new Error(
        "Only users can update user state, if you are an admin user 'UpdAdm' command instead."
      );
    }
    // FIXME: this is failing because of HPKE DeriveKeyPair not working with P-256, P-384, P-521.
    /*const controlMsg = await mlsCgkaUpdateKeys(
      this.uid,
      this.state.cgkaMemberGroupId
    );*/
    const messageIds = await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
      cmd,
      // For all users.
      memberControlMsg: new Uint8Array(),// FIXME controlMsg,
    });
    //await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    await this.middleware.sendApplicationMessage(this.state.cgkaMemberGroupId, {
      cmd,
      messageIds,
    });
    // await GKPFileStorage.save(this.userId, this.state);
  }

  async procCtrl(msg: AcceptedProposalWithApplicationMessage): Promise<GKP | void> {
    // FIXME: this is needed because we are removing the update of the state as it is failing.
    if (msg.proposal.memberControlMsg.length > 0) {
      await mlsProcessIncomingMsg(
        this.uid,
        this.state.cgkaMemberGroupId,
        msg.proposal.memberControlMsg
      );
    }
    if (msg.proposal.cmd.type === 'UPD_USER') {
      await this.middleware.ackProposal(this.state.cgkaMemberGroupId, msg);
      return;
    }
    if (msg.proposal.cmd.type === 'REM') {
      const msgUid = arrayBuffer2string(msg.proposal.cmd.uid);
      const userId = arrayBuffer2string(this.uid);
      if (msgUid === userId) {
        // Clear internal state of MLS client. TODO: verify
        await mlsCgkaInit(this.uid, this.state.cgkaMemberGroupId);
        await this.middleware.ackProposal(this.state.cgkaMemberGroupId, msg);
        await GKPFileStorage.delete(
          this.userId,
          arrayBuffer2string(this.state.cgkaMemberGroupId)
        );
        return GRaPPA.initUser(userId, this.middleware);
      }
    }
    switch (this.state.role) {
      case 'admin':
        await this.procAdminCtrl(msg);
        break;
      case 'member':
        await this.procMemberCtrl(msg);
        break;
      default:
        throw new Error('A client can be either an admin or a member.');
    }
    // Apply the new state.
    await GKPFileStorage.save(this.userId, this.state);
    await this.middleware.ackProposal(this.state.cgkaMemberGroupId, msg);
    // TODO verify if needs to write to storage for CGKA. process incoming msg already writes to storage if it is a commit. Maybe we need to change it.
  }

  private async procAdminCtrl(proposal: AcceptedProposalWithApplicationMessage): Promise<void> {
    if (this.state.role !== 'admin') {
      throw new Error(
        'Only admin members can process messages through procAdminCtrl.'
      );
    }
    if (proposalIsAdminGroupMessageWithNonEmptyBlock(proposal.proposal) && applicationMessageHasAdminApplicationMsg(proposal.applicationMsg)) {
      if (proposal.proposal.cmd.type === 'REM_ADM') {
        const msgUid = arrayBuffer2string(proposal.proposal.cmd.uid);
        const userId = arrayBuffer2string(this.uid);
        if (msgUid === userId) {
          const result = await mlsProcessIncomingMsg(
            this.uid,
            this.state.cgkaAdminGroupId,
            proposal.proposal.adminControlMsg
          );
          if (result != null) {
            throw new Error(
              'A REM_ADM operation should just remove this user from the admin group.'
            );
          }
          // Discard the admin group state.
          await mlsCgkaInit(this.uid, this.state.cgkaAdminGroupId);
          const { data, authenticatedData } = await mlsProcessIncomingMsg(
            this.uid,
            this.state.cgkaMemberGroupId,
            proposal.applicationMsg.memberApplicationMsg
          );
          if (authenticatedData != ApplicationMsgAuthenticatedData.KpExt) {
            throw new Error(
              'An admin that was removed should receive the interval to initialise its member state!'
            );
          }
          // Deserialize the member state and overwrite locally.
          // It might be better to send the interval directly instead of computing it here, especially
          // if we want to give only partial access to the state when the user is made an admin.
          const extension = await KaPPA.deserializeExported(data);
          const currentInterval = await this.state.kp.getInterval({ left: 0, right: this.state.kp.getMaxEpoch() });
          const updated = KaPPA.processExtension(currentInterval, extension);
          this.state = {
            role: 'member',
            cgkaMemberGroupId: this.state.cgkaMemberGroupId,
            interval: updated,
          };
          console.log(`Admin removed, new role: ${this.state.role}`);
          return;
        }
      }
      // cmd is REM_ADM, REM or ROT_KEYS
      // Deserialize the whole state.
      const { data, authenticatedData } = await mlsProcessIncomingMsg(
        this.uid,
        this.state.cgkaAdminGroupId,
        proposal.applicationMsg.adminApplicationMsg
      );
      if (authenticatedData != ApplicationMsgAuthenticatedData.KpState) {
        throw new Error('An admin always receive the complete state!');
      }
      const kp = await KaPPA.deserialize(data);
      this.state.kp = kp;
    } else {
      await this.state.kp.progress(BlockType.EMPTY);
    }
  }

  private async procMemberCtrl(msg: AcceptedProposalWithApplicationMessage): Promise<void> {
    if (this.state.role !== 'member') {
      throw new Error(
        'Only members can process messages through procMemberCtrl.'
      );
    }
    if (proposalIsAcceptedWelcomeAdminGroupMessage(msg.proposal) && applicationMessageIsAddAdminApplicationMessage(msg.applicationMsg)) {
      const msgUid = arrayBuffer2string(msg.proposal.cmd.uid);
      const userId = arrayBuffer2string(this.uid);
      if (msgUid === userId) {
        const cgkaAdminGroupId = await mlsCgkaJoinGroup(
          this.uid,
          msg.proposal.adminWelcomeMsg
        );
        // TODO: remove this additional check. Just for testing purposes.
        if (
          arrayBuffer2string(cgkaAdminGroupId) !=
          arrayBuffer2string(GRaPPA.getCgkaAdminGroupIdFromMemberGroupId(
            this.state.cgkaMemberGroupId
          ))
        ) {
          throw new Error('The admin group id is not the expected one.');
        }
        const { data, authenticatedData } = await mlsProcessIncomingMsg(
          this.uid,
          cgkaAdminGroupId,
          msg.applicationMsg.adminApplicationMsg
        );
        if (authenticatedData != ApplicationMsgAuthenticatedData.KpState) {
          throw new Error(
            'A member becoming an admin should receive the full state!'
          );
        }
        const kp = await KaPPA.deserialize(data);
        const state: AdminState = {
          kp,
          cgkaMemberGroupId: this.state.cgkaMemberGroupId,
          cgkaAdminGroupId,
          role: 'admin',
        };
        // Update the internal state.
        this.state = state;
      }
      // else we can just ignore this message.
    } else if (applicationMessageHasMemberApplicationMsg(msg.applicationMsg)) {
      const extensionApplicationMsg = await mlsProcessIncomingMsg(
        this.uid,
        this.state.cgkaMemberGroupId,
        msg.applicationMsg.memberApplicationMsg
      );
      const { data, authenticatedData } = extensionApplicationMsg;
      if (authenticatedData != ApplicationMsgAuthenticatedData.KpExt) {
        throw new Error('A member should only receive extensions!');
      }
      const extension = await KaPPA.deserializeExported(data);
      const updated = KaPPA.processExtension(this.state.interval, extension);
      // Update the internal state.
      this.state.interval = updated;
    } else {
      console.error('Unknown message type.');
    }
  }

  /**
   * Generates a GRaPPA key for a given epoch.
   * @param epoch the epoch for which to generate a key.
   * @returns the crypto key from DKR state.
   */
  public getEpochKey(epoch?: Epoch): Promise<CryptoKey> {
    if (epoch == null) {
      epoch = this.getCurrentEpoch();
    }
    switch (this.state.role) {
      case 'admin':
        return this.state.kp.getKey(epoch);
      case 'member':
        return KaPPA.getKey(epoch, this.state.interval);
      default:
        throw new Error('A client can be either an admin or a member.');
    }
  }

  /**
   * Useful to perform file encryption.
   * @returns the current epoch.
   */
  public getCurrentEpoch(): Epoch {
    switch (this.state.role) {
      case 'admin':
        return this.state.kp.getMaxEpoch();
      case 'member':
        return this.state.interval.epochs.right;
      default:
        throw new Error('A client can be either an admin or a member.');
    }
  }

  /**
   * Useful to perform file encryption.
   * @returns the current epoch.
   */
  public getEpochInterval(): EpochInterval {
    switch (this.state.role) {
      case 'admin':
        return { left: 0, right: this.state.kp.getMaxEpoch() };
      case 'member':
        // Copy the object
        return { ...this.state.interval.epochs };
      default:
        throw new Error('A client can be either an admin or a member.');
    }
  }

  /**
   * @returns the current local role of the client in GRaPPA.
   */
  public getRole(): ClientState['role'] {
    return this.state.role;
  }

  /**
   * Admin operation only.
   * Progress in the KP and create an extension given the epoch in input.
   * @param blockType the block type to use while progressing one step in KP.
   * @returns the extension of one epoch.
   */
  private async runKP(blockType: BlockType): Promise<DoubleChainsInterval> {
    if (this.state.role != 'admin') {
      return Promise.reject('Only admins can run KP');
    }
    const { kp } = this.state;
    await kp.progress(blockType);
    return kp.createExtension({
      left: kp.getMaxEpoch(),
      right: kp.getMaxEpoch(),
    });
  }

  private static getCgkaAdminGroupIdFromMemberGroupId(
    groupId: string | Uint8Array
  ): Uint8Array {
    return typeof groupId === 'string'
      ? string2Uint8Array('ADMIN-' + groupId)
      : string2Uint8Array('ADMIN-' + arrayBuffer2string(groupId));
  }

  public static getUidFromUserId(userId: string) {
    return string2Uint8Array(userId);
  }
}
