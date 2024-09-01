import { ExecCtrlResult, GKP, UserState } from "./gkp";

class GRaPPA implements GKP {
    
    initUser(uid: string): void {
        throw new Error("Method not implemented.");
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