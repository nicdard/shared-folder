// Somehow ts-lint is not able to infer the types even though TS server does (try hover the functions from ssf to see their types).
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { string2ArrayBuffer } from "../commonCrypto";
import { KaPPA } from "../key-progression/kappa";
import { BlockType, DoubleChainsInterval, Epoch } from "../key-progression/kp";
import { AddControlCommand, ClientState, ControlCommand, GKP, RemControlCommand } from "./gkp";
import { ApplicationMsgAuthenticatedData, mlsCgkaAddProposal, mlsCgkaApplyPendingCommit, mlsCgkaInit, mlsGenerateKeyPackage, mlsInitClient, mlsPrepareAppMsg } from "ssf";

// We can remove it later.
const DEFAULT_MAXIMUM_INTERVAL_WITHOUT_BLOCK = 5;

interface GKPMiddleware {
    fetchKeyPackageForUid(uid: Uint8Array): Promise<Uint8Array>;
    sendProposal(proposals: Uint8Array[]): Promise<void>;
    sendApplicationMessages(messages: Uint8Array[]): Promise<void>;
    sendKeyPackage(keyPackage: Uint8Array): Promise<void>;
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
}

class GRaPPA implements GKP {

    private state: ClientState;
    private epoch: number;

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
        this.epoch = 0;
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

    public async execCtrl(cmd: ControlCommand, arg: any): Promise<void> {
        switch (cmd.type) {
            case 'ADD':
                await this.execAddCtrl(cmd);
                break;
            default:
                throw new Error("Not yet implemented.")
        }
    }

    private async execAddCtrl(cmd: AddControlCommand): Promise<void> {
        if (this.state.role != 'admin') {
            throw new Error("Only admins can add new users to the group.");
        }
        // retrieve the keyPackage.
        const keyPackageRawMsg = await this.middleware.fetchKeyPackageForUid(cmd.uid);
        // create the proposal.
        const { controlMsg, welcomeMsg } = await mlsCgkaAddProposal(cmd.uid, this.state.cgkaMemberGroupId, keyPackageRawMsg);
        // send the proposal to the server.
        await this.middleware.sendProposal([controlMsg, welcomeMsg]);
        // if there is no error, this means that the proposal can be applied,
        // as it was accepted by the server.
        await mlsCgkaApplyPendingCommit(this.uid, this.state.cgkaAdminGroupId);
        const extension = await this.runKP(++this.epoch, BlockType.EMPTY);
        const interval = await this.state.kp.getInterval({ left: this.epoch, right: this.epoch });
        const extensionPayload = await KaPPA.serializeExported(extension);
        const intervalPayload = await KaPPA.serializeExported(interval);
        // C_M
        const extensionMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, extensionPayload, ApplicationMsgAuthenticatedData.KpExt);
        const intervalMessage = await mlsPrepareAppMsg(this.uid, this.state.cgkaMemberGroupId, intervalPayload, ApplicationMsgAuthenticatedData.KpInt);
        await this.middleware.sendApplicationMessages([extensionMessage, intervalMessage]);
    }

    private async execRemCtrl(cmd: RemControlCommand): Promise<void> {

    }

    procCtrl(controlMessage: string): void {
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
     * @param epoch the epoch to create an extension containing only this epoch (TODO/FIXME: we can probably remove this as it is always the latest epoch)
     * @param blockType the block type to use while progressing one step in KP.
     * @returns the extension of one epoch.
     */
    private async runKP(epoch: Epoch, blockType: BlockType): Promise<DoubleChainsInterval> {
        if (this.state.role != 'admin') {
            return Promise.reject("Only admins can run KP");
        }
        const { kp } = this.state;
        await kp.progress(blockType);
        return kp.createExtension({ left: epoch, right: epoch });
    }

}



function string2Uint8Array(str: string) {
    return new Uint8Array(string2ArrayBuffer(str));
}