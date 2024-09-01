import { Epoch, KP } from '../key-progression/kp';

export interface GKP {
  initUser(uid: string): void;
  createGroup(userState: UserState): void;
  execCtrl(cmd: ControlCommand, arg: any): ExecCtrlResult;
  procCtrl(controlMessage: string): void;
  joinCtrl(welcomeMessage: string): void;
  getEpochKey(epoch: Epoch): Promise<CryptoKey>;
}

export interface UserState {
  uid: string;
  currentEpoch: Epoch;
  kpState: KP;
  groupState: any; // CGKA state
}

type AdminControlCommand =
  | 'ADD'
  | 'REM'
  | 'ADD_ADM'
  | 'REM_ADM'
  | 'UPD_ADM'
  | 'ROT_KEYS';
type UserControlCommand = 'UPD_USER';
type ControlCommand = AdminControlCommand | UserControlCommand;

export interface ExecCtrlResult {
  controlMessage: string;
  welcomeMessage: string | undefined;
}
