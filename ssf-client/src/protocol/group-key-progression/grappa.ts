import { arrayBuffer2string, string2Uint8Array } from "../commonCrypto";
import { KaPPA } from "../key-progression/kappa";
import { BlockType, DoubleChainsInterval } from "../key-progression/kp";
import { AddAdmControlCommand, AddControlCommand, AdminState, ClientState, ControlCommand, GKP, AcceptedProposal, RemAdmControlCommand, RemControlCommand, RotKeysControlCommand, Proposal, UpdAdmControlCommand, UpdUserControlCommand, proposalIsAddAdmGroupMessage, proposalHasMemberApplicationMsg, proposalIdAdminGroupMessage } from "./gkp";
import { ApplicationMsgAuthenticatedData, mlsCgkaAddProposal, mlsCgkaApplyPendingCommit, mlsCgkaDeletePendingCommit, mlsCgkaInit, mlsCgkaJoinGroup, mlsCgkaRemoveProposal, mlsCgkaUpdateKeys, mlsGenerateKeyPackage, mlsInitClient, mlsPrepareAppMsg, mlsProcessIncomingMsg } from "ssf";
import { GKPFileStorage } from "./storage";
import { fetchKeyPackage, publishKeyPackage, sendProposal, fetchPendingProposal, ackPendingProposal } from "../../../src/ds";
import { decodeObject, encodeObject } from "../marshaller";


// 32 as default, we can change it later. The smaller the heavier the protocol to run.
const DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK = 32;

/**
 * Abstract the communication with the other clients through a Server used for synchronization.
 */
interface GKPMiddleware {
    /**
     * Sends a keyPackage to the server to be stored and consumed for future joins from other users.
     * @param keyPackage the serialized key package to store in the server.
     */
    sendKeyPackage(keyPackage: Uint8Array): Promise<void>;

    /**
     * @param uid the email of the user to retrieve the key package of.
     * @param folderId the folderId we want to invite `uid` to. This is requested by the server to perform ACL check and guarantee data consistency.
     */
    fetchKeyPackageForUidWithFolder(uid: Uint8Array, folderId: Uint8Array): Promise<Uint8Array>;

    /**
     * Sends a GRaPPA proposal, which can be refused by the server if the sender has pending GroupMessages to process.
     * @param folderId the folderId we want to share this message with.
     * @param proposal the proposal, composed by control and application messages depending on the command generating it.
     */
    sendProposal(folderId: Uint8Array, proposal: Proposal): Promise<void>;

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

class DsMiddleware implements GKPMiddleware {

    fetchKeyPackageForUidWithFolder(uid: Uint8Array, folderId: Uint8Array): Promise<Uint8Array> {
        const identity = arrayBuffer2string(uid);
        const serverFolderId = Number(arrayBuffer2string(folderId));
        return fetchKeyPackage(identity, serverFolderId);
    }

    async sendProposal(folderId: Uint8Array, proposal: Proposal): Promise<void> {
        const serverFolderId = Number(arrayBuffer2string(folderId));
        const payload = await encodeObject<Proposal>(proposal);
        await sendProposal(serverFolderId, payload);
    }

    sendKeyPackage(keyPackage: Uint8Array): Promise<void> {
        return publishKeyPackage(keyPackage);
    }

    async fetchPendingProposal(folderId: Uint8Array): Promise<AcceptedProposal> {
        const serverFolderId = Number(arrayBuffer2string(folderId));
        const raw = await fetchPendingProposal(serverFolderId);
        const msg = await decodeObject<AcceptedProposal>(raw.payload as unknown as ArrayBuffer);
        // Add the message id.
        msg.messageId = raw.message_id;
        return msg
    }

    async ackProposal(folderId: Uint8Array, proposal: AcceptedProposal): Promise<void> {
        const serverFolderId = Number(arrayBuffer2string(folderId));
        await ackPendingProposal(serverFolderId, proposal.messageId);
    }
}

export class GRaPPA implements GKP {

    private state: ClientState;

    private constructor(
        readonly uid: Uint8Array,
        readonly userId: string,
        readonly middleware: GKPMiddleware,
    ) {}
    
    /**
     * @param userId the user id to be initialised.
     * @param middleware abstractions for server communications.
     * @returns a new {@link GKP} instance that can be used to either create a group, or listen for a join invitation to an unknown group.
     */
    public static async initUser(userId: string, middleware: GKPMiddleware): Promise<GKP> {
        const uid = string2Uint8Array(userId);
        // This will fetch the existing mls client if any. Therefore we can instantiate multiple GRaPPAs.
        await mlsInitClient(uid);
        await this.publishKeyPackage(userId, middleware);
        return new GRaPPA(uid, userId, middleware);
    }

    /**
     * Creates a new group. The user is an administrator of the group.
     * Initialise the dual key regression state and both member and admin CGKA.
     * @param groupId The group name.
     * @param maximumIntervalLengthWithoutBlocks the maximum length for the backward chains in dual key regression.
     */
    public async createGroup(groupId: string, maximumIntervalLengthWithoutBlocks: number = DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK): Promise<void> {
        const cgkaMemberGroupId = string2Uint8Array(groupId);
        const cgkaAdminGroupId = GRaPPA.getCgkaAdminGroupIdFromMemberGroupId(groupId);
        await mlsCgkaInit(this.uid, cgkaMemberGroupId);
        await mlsCgkaInit(this.uid, cgkaAdminGroupId);
        const kp = await KaPPA.init(maximumIntervalLengthWithoutBlocks);
        this.state = {
            role: 'admin',
            cgkaMemberGroupId,
            cgkaAdminGroupId,
            kp,
        };
    }

    /**
     * Creates or fetches an existing CGKA/MLS client for the uid.
     * Creates and publish a key package.
     * @param userId the user id to fetch the CGKA/MLS client. 
     * @param middleware abstractions for server communications.
     */
    public static async publishKeyPackage(userId: string, middleware: GKPMiddleware): Promise<void> {
        const uid = string2Uint8Array(userId);
        const keyPackageMsg = await mlsGenerateKeyPackage(uid);
        return middleware.sendKeyPackage(keyPackageMsg);
    }
    
   /**
    * Process a welcome message and adds userId to the group.
    * @param userId 
    * @param middleware 
    * @param welcomeMsg 
    * @param applicationMsg 
    * @returns 
    */
    public static async joinCtrl(userId: string, middleware: GKPMiddleware, welcomeMsg: Uint8Array, applicationMsg: Uint8Array): Promise<GKP> {
        // Publish a new key package to allow for new joins.
        await this.publishKeyPackage(userId, middleware);
        // Try to join the group.
        const uid = string2Uint8Array(userId);
        const cgkaMemberGroupId = await mlsCgkaJoinGroup(uid, welcomeMsg);
        const intervalMessage = await mlsProcessIncomingMsg(uid, cgkaMemberGroupId, applicationMsg);
        const { data, authenticatedData } = intervalMessage;
        if (authenticatedData !== ApplicationMsgAuthenticatedData.KpInt) {
            throw new Error("During a join, the application msg should contain an interval.");
        }
        const interval = await KaPPA.deserializeExported(data);
        const grappa = new GRaPPA(uid, userId, middleware);
        grappa.state = {
            role: 'member',
            cgkaMemberGroupId,
            interval,
        }
        // Save the new group state.
        await GKPFileStorage.save(userId, grappa.state);
        return grappa;
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
                    throw new Error("Not yet implemented.")
            }
        } catch(error) {
            console.error(`Couldn't execute operation ${cmd.type}, due to error ${error as unknown as string}, fetching the latest state`);
            // Cleanup pending changes.
            await mlsCgkaDeletePendingCommit(this.uid, this.state.cgkaMemberGroupId);

            if (this.state.role === 'admin') {
                await mlsCgkaDeletePendingCommit(this.uid, this.state.cgkaAdminGroupId);
            }
            // Revert DKR state by loading the previous one saved.
            this.state = await GKPFileStorage.load(this.userId, this.state.cgkaMemberGroupId);
            // Fetch latest state?
            try {
                // eslint-disable-next-line no-constant-condition
                while (true) {
                    const pendingProposal = await this.middleware.fetchPendingProposal(this.state.cgkaMemberGroupId);
                    await this.procCtrl(pendingProposal);
                }
            } catch (error) {
                console.debug("the client is synced, you can now retry.")
            }
        }
    }



    /**
     * Admin command. Add a new user to the member group.
     * The user can then become a member if an admin propose the addition to the admin group.
     * @param cmd {@link AddAdmControlCommand}
     */
    private async execAddCtrl(cmd: AddControlCommand): Promise<void> {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        // retrieve the keyPackage for the given user.
        const keyPackageRawMsg = await this.middleware.fetchKeyPackageForUidWithFolder(cmd.uid, this.state.cgkaMemberGroupId);
        // create the proposal.
        const { controlMsg, welcomeMsg } = await mlsCgkaAddProposal(this.uid, this.state.cgkaMemberGroupId, keyPackageRawMsg);
        const extension = await this.runKP(BlockType.EMPTY);
        const interval = await this.state.kp.getInterval({ left: this.state.kp.getMaxEpoch(), right: this.state.kp.getMaxEpoch() });
        const extensionPayload = await KaPPA.serializeExported(extension);
        const intervalPayload = await KaPPA.serializeExported(interval);
        // C_M
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const intervalMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, intervalPayload, ApplicationMsgAuthenticatedData.KpInt);
        // send the proposal to the server.
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For all users.
            memberControlMsg: controlMsg,
            memberApplicationMsg: extensionMessage,
            // For Joining member.
            memberWelcomeMsg: welcomeMsg,
            memberApplicationIntMsg: intervalMessage,
        });
        // if there is no error, this means that the proposal can be applied,
        // as it was accepted by the server. I.e. the client state is up to date.
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        await GKPFileStorage.save(this.userId, this.state);
    }

    /**
     * Admin command. Remove a user from the member group.
     * First use {@link RemAdmControlCommand} if the member is also an admin.
     * @param cmd {@link RemControlCommand}
     */
    private async execRemCtrl(cmd: RemControlCommand): Promise<void> {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        const controlMsg = await mlsCgkaRemoveProposal(this.uid, this.state.cgkaMemberGroupId, cmd.uid);
        const extension = await this.runKP(BlockType.FORWARD_BLOCK);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        // send the proposal to the server.
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For all users 
            memberControlMsg: controlMsg,
            memberApplicationMsg: extensionMessage,
        });
        // if there is no error, this means that the proposal can be applied,
        // as it was accepted by the server. I.e. the client state is up to date.
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        await GKPFileStorage.save(this.userId, this.state);
    }

    /**
     * Admin command. Elevate the member to admin.
     * @param cmd {@link AddAdmControlCommand} containing the uid of the target member.
     */
    private async execAddAdminCtrl(cmd: AddAdmControlCommand) {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        const { controlMsg: adminControlMsg, welcomeMsg: adminWelcomeMsg } = await mlsCgkaAddProposal(this.uid, this.state.cgkaAdminGroupId, cmd.uid);
        const controlMessage = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);
        // FIXME(protocol): Give access to all state anyway, should we remove this empty block?
        const extension = await this.runKP(BlockType.EMPTY);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const kpStatePayload = await this.state.kp.serialize();
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const kpStateMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, kpStatePayload, ApplicationMsgAuthenticatedData.KpState);
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For the admins.
            adminControlMsg,
            adminWelcomeMsg,
            adminApplicationMsg: kpStateMessage,
            // For all users.
            memberControlMsg: controlMessage,
            memberApplicationMsg: extensionMessage,
        });
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        await GKPFileStorage.save(this.userId, this.state);
    }

    /**
     * Admin command. Remove admin privileges from a member.
     * @param cmd {@link RemAdmControlCommand} containin the uid of the target admin.
     */
    private async execRemAdminCtrl(cmd: RemAdmControlCommand) {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        const adminControlMsg = await mlsCgkaRemoveProposal(this.uid, this.state.cgkaAdminGroupId, cmd.uid);
        const controlMessage = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);

        const extension = await this.runKP(BlockType.BACKWARD_BLOCK);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const kpStatePayload = await this.state.kp.serialize();
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const kpStateMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, kpStatePayload, ApplicationMsgAuthenticatedData.KpState);
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For the admins.
            adminControlMsg,
            adminApplicationMsg: kpStateMessage,
            // For all users.
            memberControlMsg: controlMessage,
            memberApplicationMsg: extensionMessage,
        });

        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        await GKPFileStorage.save(this.userId, this.state);
    }

    /**
     * Admin command. Refresh the admin state and progress the DKR state.
     * @param cmd {@link UpdAdmControlCommand}
     */
    private async execUpdAdminCtrl(cmd: UpdAdmControlCommand) {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        const adminControlMsg = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaAdminGroupId);
        const controlMessage = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);
        const extension = await this.runKP(BlockType.EMPTY);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For the admins.
            adminControlMsg,
            // For all users.
            memberControlMsg: controlMessage,
            memberApplicationMsg: extensionMessage,
        });

        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        await GKPFileStorage.save(this.userId, this.state);
    }

    

    /**
     * Admin command.
     * Rotate the key material for the entire shared folder.
     * @param cmd {@link RotKeysControlCommand}
     */
    private async execRotateKeysCtrl(cmd: RotKeysControlCommand) {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        const adminControlMsg = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaAdminGroupId);
        const controlMessage = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);
        const extension = await this.runKP(BlockType.BACKWARD_BLOCK);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const kpStatePayload = await this.state.kp.serialize();
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const kpStateMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, kpStatePayload, ApplicationMsgAuthenticatedData.KpState);
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For the admins.
            adminControlMsg,
            adminApplicationMsg: kpStateMessage,
            // For all users.
            memberControlMsg: controlMessage,
            memberApplicationMsg: extensionMessage,
        });
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        await GKPFileStorage.save(this.userId, this.state);
    }

    /**
     * The only non-admin command of the protocol.
     * It allows a user to update its own local CGKA state.
     * @param cmd {@link UpdUserControlCommand}
     * @see ControlCommand
     */
    private async execUpdUserCtrl(cmd: UpdUserControlCommand): Promise<void> {
        if (this.state.role !== 'member' ) {
            throw new Error("Only users can update user state, if you are an admin user 'UpdAdm' command instead.");
        }
        const controlMsg = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);
        await this.middleware.sendProposal(this.state.cgkaMemberGroupId, {
            cmd,
            // For all users.
            memberControlMsg: controlMsg,
        });
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        // await GKPFileStorage.save(this.userId, this.state);
    }


    async procCtrl(msg: AcceptedProposal): Promise<GKP | void> {
        await mlsProcessIncomingMsg(this.uid, this.state.cgkaMemberGroupId, msg.memberControlMsg);
        if (msg.cmd.type === 'UPD_USER') {
            return;
        }
        if (msg.cmd.type === 'REM') {
            const msgUid = arrayBuffer2string(msg.cmd.uid);
            const userId = arrayBuffer2string(this.uid);
            if (msgUid === userId) {
                // Clear internal state of MLS client. TODO: verify
                await mlsCgkaInit(this.uid, this.state.cgkaMemberGroupId);
                await this.middleware.ackProposal(this.state.cgkaMemberGroupId, msg);
                await GKPFileStorage.delete(this.userId, arrayBuffer2string(this.state.cgkaMemberGroupId));
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
                throw new Error("A client can be either an admin or a member.");
        }
        // Apply the new state.
        await GKPFileStorage.save(this.userId, this.state);
        await this.middleware.ackProposal(this.state.cgkaMemberGroupId, msg);
        // TODO verify if needs to write to storage for CGKA. process incoming msg already writes to storage if it is a commit. Maybe we need to change it.
    }

    private async procAdminCtrl(proposal: AcceptedProposal): Promise<void> {
        if (this.state.role !== 'admin') {
            throw new Error("Only admin members can process messages through procAdminCtrl.");
        }
        if (proposalIdAdminGroupMessage(proposal)) {
            if (proposal.cmd.type === 'REM_ADM') {
                const msgUid = arrayBuffer2string(proposal.cmd.uid);
                const userId = arrayBuffer2string(this.uid);
                if (msgUid === userId) {
                    const result = await mlsProcessIncomingMsg(this.uid, this.state.cgkaAdminGroupId, proposal.adminControlMsg);
                    if (result != null) {
                        throw new Error("A REM_ADM operation should just remove this user from the admin group.");
                    }
                    // Discard the admin group state.
                    await mlsCgkaInit(this.uid, this.state.cgkaAdminGroupId);
                    const { data, authenticatedData } = await mlsProcessIncomingMsg(this.uid, this.state.cgkaMemberGroupId, proposal.memberApplicationMsg);
                    if (authenticatedData != ApplicationMsgAuthenticatedData.KpInt) {
                        throw new Error("An admin that was removed should receive the interval to initialise its member state!");
                    }
                    // Deserialize the member state and overwrite locally.
                    const interval = await KaPPA.deserializeExported(data);
                    this.state = {
                        role: 'member',
                        cgkaMemberGroupId: this.state.cgkaMemberGroupId,
                        interval,
                    };
                    return;
                }
            }
            // Deserialize the whole state.
            const { data, authenticatedData } = await mlsProcessIncomingMsg(this.uid, this.state.cgkaAdminGroupId, proposal.adminApplicationMsg);
            if (authenticatedData != ApplicationMsgAuthenticatedData.KpState) {
                throw new Error("An admin always receive the complete state!");
            }            
            const kp = await KaPPA.deserialize(data);
            this.state.kp = kp;
        } else {
            await this.state.kp.progress(BlockType.EMPTY);
        }
    }

    private async procMemberCtrl(msg: AcceptedProposal): Promise<void> {
        if (this.state.role !== 'member') {
            throw new Error("Only members can process messages through procMemberCtrl.");
        }
        if (proposalIsAddAdmGroupMessage(msg)) {
            if (this.uid === msg.cmd.uid) {
                const cgkaAdminGroupId = await mlsCgkaJoinGroup(this.uid, msg.adminWelcomeMsg);
                // TODO: remove this additional check. Just for testing purposes.
                if (cgkaAdminGroupId != GRaPPA.getCgkaAdminGroupIdFromMemberGroupId(this.state.cgkaMemberGroupId)) {
                    throw new Error("The admin group id is not the expected one.");
                }
                const { data, authenticatedData } = await mlsProcessIncomingMsg(this.uid, cgkaAdminGroupId, msg.adminApplicationMsg);
                if (authenticatedData != ApplicationMsgAuthenticatedData.KpInt) {
                    throw new Error("A member should only receive intervals!");
                }
                const kp = await KaPPA.deserialize(data);
                const state: AdminState = {
                    kp,
                    cgkaMemberGroupId: this.state.cgkaMemberGroupId,
                    cgkaAdminGroupId,
                    role: 'admin',
                }
                // Update the internal state.
                this.state = state;
            }
            // else we can just ignore this message.
        } else if (proposalHasMemberApplicationMsg(msg)) {
            const extensionApplicationMsg = await mlsProcessIncomingMsg(this.uid, this.state.cgkaMemberGroupId, msg.memberApplicationMsg);
            const { data, authenticatedData } = extensionApplicationMsg;
            if (authenticatedData != ApplicationMsgAuthenticatedData.KpExt) {
                throw new Error("A member should only receive extensions!");
            }
            const extension = await KaPPA.deserializeExported(data);
            const updated = KaPPA.processExtension(this.state.interval, extension);
            // Update the internal state.
            this.state.interval = updated;
        } else {
            console.error("Unknown message type.");
        }
    }

    /**
     * Generates a GRaPPA key for a given epoch.
     * @param epoch the epoch for which to generate a key.
     * @returns the crypto key from DKR state.
     */
    public getEpochKey(epoch: number): Promise<CryptoKey> {
        switch (this.state.role) {
            case "admin":
                return this.state.kp.getKey(epoch);
            case "member":
                return KaPPA.getKey(epoch, this.state.interval);
            default:
                throw new Error("A client can be either an admin or a member.");
        }
    }

    /**
     * Admin operation only.
     * Progress in the KP and create an extension given the epoch in input.
     * @param blockType the block type to use while progressing one step in KP.
     * @returns the extension of one epoch.
     */
    private async runKP(blockType: BlockType): Promise<DoubleChainsInterval> {
        if (this.state.role != 'admin') {
            return Promise.reject("Only admins can run KP");
        }
        const { kp } = this.state;
        await kp.progress(blockType);
        return kp.createExtension({ left: kp.getMaxEpoch(), right: kp.getMaxEpoch() });
    }

    private static getCgkaAdminGroupIdFromMemberGroupId(groupId: string | Uint8Array): Uint8Array {
        return typeof groupId === 'string' 
            ? string2Uint8Array("ADMIN-" + groupId) 
            : string2Uint8Array("ADMIN-" + arrayBuffer2string(groupId));
    }

}
