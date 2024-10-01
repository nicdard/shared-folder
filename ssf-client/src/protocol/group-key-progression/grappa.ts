import { string2ArrayBuffer } from "../commonCrypto";
import { KaPPA } from "../key-progression/kappa";
import { BlockType, DoubleChainsInterval } from "../key-progression/kp";
import { AddAdmControlCommand, AddControlCommand, ClientState, ControlCommand, GKP, RemAdmControlCommand, RemControlCommand, RotKeysControlCommand, UpdAdmControlCommand, UpdUserControlCommand } from "./gkp";
import { ApplicationMsgAuthenticatedData, mlsCgkaAddProposal, mlsCgkaApplyPendingCommit, mlsCgkaDeletePendingCommit, mlsCgkaInit, mlsCgkaRemoveProposal, mlsCgkaUpdateKeys, mlsGenerateKeyPackage, mlsInitClient, mlsPrepareAppMsg } from "ssf";

// We can remove it later.
const DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK = 5;

interface GKPMiddleware {
    fetchKeyPackageForUid(uid: Uint8Array): Promise<Uint8Array>;
    sendProposal(proposals: Uint8Array[]): Promise<void>;
    sendApplicationMessages(messages: Uint8Array[]): Promise<void>;
    sendKeyPackage(keyPackage: Uint8Array): Promise<void>;
    fetchPendingNotifications(): Promise<Uint8Array[]>;
}

class DummyMiddleware implements GKPMiddleware {

    private pending_proposals: Uint8Array[];

    fetchKeyPackageForUid(uid: Uint8Array): Promise<Uint8Array> {
        return mlsGenerateKeyPackage(uid);
    }

    sendProposal(proposals: Uint8Array[]): Promise<void> {
        this.pending_proposals = proposals;
        return Promise.resolve();
    }

    sendApplicationMessages(messages: Uint8Array[]): Promise<void> {
        console.log(messages);
        return Promise.resolve();
    }

    sendKeyPackage(keyPackage: Uint8Array): Promise<void> {
        console.log(keyPackage);
        return Promise.resolve();
    }

    fetchPendingNotifications(): Promise<Uint8Array[]> {
        return Promise.resolve<Uint8Array[]>([]);
    }
}

class GRaPPA implements GKP {

    private state: ClientState;

    private constructor(
        readonly uid: Uint8Array,
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
        return new GRaPPA(uid, middleware);
    }

    /**
     * Creates a new group. The user is an administrator of the group.
     * Initialise the dual key regression state and both member and admin CGKA.
     * @param groupId The group name.
     * @param maximumIntervalLengthWithoutBlocks the maximum length for the backward chains in dual key regression.
     */
    public async createGroup(groupId: string, maximumIntervalLengthWithoutBlocks: number = DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK): Promise<void> {
        const cgkaMemberGroupId = string2Uint8Array(groupId);
        const cgkaAdminGroupId = string2Uint8Array("ADMIN-" + groupId);
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
     * Waits for incoming JoinGroup messages from the DS.
     * @param userId the user id to fetch the CGKA/MLS client. 
     * @param middleware abstractions for server communications.
     */
    /*public static async joinCtrl(userId: string, middleware: GKPMiddleware): Promise<number> {
        const uid = string2Uint8Array(userId);
        const keyPackageMsg = await mlsGenerateKeyPackage(userId);
        await middleware.sendKeyPackage(keyPackageMsg);

    }*/

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
            // Fetch latest state.
            const pendingNotifications = await this.middleware.fetchPendingNotifications();
            for (const notification of pendingNotifications) {
                // this.procCtrl(notification);
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
        const keyPackageRawMsg = await this.middleware.fetchKeyPackageForUid(cmd.uid);
        // create the proposal.
        const { controlMsg, welcomeMsg } = await mlsCgkaAddProposal(this.uid, this.state.cgkaMemberGroupId, keyPackageRawMsg);
        // send the proposal to the server.
        await this.middleware.sendProposal([controlMsg, welcomeMsg]);
        // if there is no error, this means that the proposal can be applied,
        // as it was accepted by the server. I.e. the client state is up to date.
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        // If there is an error, the client needs to pull the latest state.
        const extension = await this.runKP(BlockType.EMPTY);
        const interval = await this.state.kp.getInterval({ left: this.state.kp.getMaxEpoch(), right: this.state.kp.getMaxEpoch() });
        const extensionPayload = await KaPPA.serializeExported(extension);
        const intervalPayload = await KaPPA.serializeExported(interval);
        // C_M
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const intervalMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, intervalPayload, ApplicationMsgAuthenticatedData.KpInt);
        await this.middleware.sendApplicationMessages([extensionMessage, intervalMessage]);
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
        await this.middleware.sendProposal([controlMsg]);
        // if there is no error, this means that the proposal can be applied,
        // as it was accepted by the server. I.e. the client state is up to date.
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        const extension = await this.runKP(BlockType.FORWARD_BLOCK);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        await this.middleware.sendApplicationMessages([extensionMessage]);
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
        await this.middleware.sendProposal([adminControlMsg, adminWelcomeMsg, controlMessage]);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        // FIXME(protocol): Give access to all state anyway, should we remove this empty block?
        const extension = await this.runKP(BlockType.EMPTY);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const kpStatePayload = await this.state.kp.serialize();
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const kpStateMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, kpStatePayload, ApplicationMsgAuthenticatedData.KpState);
        await this.middleware.sendApplicationMessages([extensionMessage, kpStateMessage]);
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
        await this.middleware.sendProposal([adminControlMsg, controlMessage]);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        const extension = await this.runKP(BlockType.BACKWARD_BLOCK);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const kpStatePayload = await this.state.kp.serialize();
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const kpStateMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, kpStatePayload, ApplicationMsgAuthenticatedData.KpState);
        await this.middleware.sendApplicationMessages([extensionMessage, kpStateMessage]);
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
        const controlMsg = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);
        await this.middleware.sendProposal([adminControlMsg, controlMsg]);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        const extension = await this.runKP(BlockType.EMPTY);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        await this.middleware.sendApplicationMessages([extensionMessage]);
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
        const controlMsg = await mlsCgkaUpdateKeys(this.uid, this.state.cgkaMemberGroupId);
        await this.middleware.sendProposal([adminControlMsg, controlMsg]);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
        const extension = await this.runKP(BlockType.BACKWARD_BLOCK);
        const extensionPayload = await KaPPA.serializeExported(extension);
        const kpStatePayload = await this.state.kp.serialize();
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const kpStateMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, kpStatePayload, ApplicationMsgAuthenticatedData.KpState);
        await this.middleware.sendApplicationMessages([extensionMessage, kpStateMessage]);
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
        await this.middleware.sendProposal([controlMsg]);
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaMemberGroupId);
    }


    procCtrl(controlMessage: Uint8Array): Promise<void> {
        throw new Error("Method not implemented.");
    }


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

}



function string2Uint8Array(str: string) {
    return new Uint8Array(string2ArrayBuffer(str));
}