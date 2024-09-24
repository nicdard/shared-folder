import { string2ArrayBuffer } from "../commonCrypto";
import { ExecCtrlResult, GKP, UserState } from "./gkp";
import { mlsCgkaInit } from "ssf";

class GRaPPA implements GKP {
    
    /**
     * @param userId the user id to be initialised.
     * @param groupId the group id to be created.
     * @returns 
     */
    async initUser(userId: string, groupId: string): Promise<void> {
        const identity = string2Uint8Array(userId);
        await mlsCgkaInit(identity, string2Uint8Array(groupId));
        return mlsCgkaInit(identity, string2Uint8Array("ADMIN-" + groupId));
    }
    createGroup(userState: UserState): void {
        throw new Error("Method not implemented.");
    }
    execCtrl(cmd: ("ADD" | "REM" | "ADD_ADM" | "REM_ADM" | "UPD_ADM" | "ROT_KEYS") | "UPD_USER", arg: any): ExecCtrlResult {
        throw new Error("Method not implemented.");
    }
    procCtrl(controlMessage: string): void {
        throw new Error("Method not implemented.");
    }
    joinCtrl(welcomeMessage: string): void {
        throw new Error("Method not implemented.");
    }
    getEpochKey(epoch: number): Promise<CryptoKey> {
        throw new Error("Method not implemented.");
    }


}

function string2Uint8Array(str: string) {
    return new Uint8Array(string2ArrayBuffer(str));
}