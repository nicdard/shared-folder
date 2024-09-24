import { DoubleChainsInterval, Epoch, KP } from '../key-progression/kp';

export interface GKP {
  createGroup(groupId: string): Promise<void>;
  createGroup(groupId: string, maximumIntervalLengthWithoutBlocks: number): Promise<void>;
  execCtrl(cmd: ControlCommand, arg: any): Promise<void>;
  procCtrl(controlMessage: string): void;
  getEpochKey(epoch: Epoch): Promise<CryptoKey>;
}

interface BaseState {
  cgkaMemberGroupId: Uint8Array,
}

export interface MemberState extends BaseState {
  role: 'member',
  interval: DoubleChainsInterval,
}

export interface AdminState extends BaseState {
  role: 'admin',
  cgkaAdminGroupId: Uint8Array,
  kp: KP,
}

export type ClientState = AdminState | MemberState;

export interface UserState {
  uid: Uint8Array;
  currentEpoch: Epoch;
  kpState: KP;
  groupState: Uint8Array; // CGKA state
}

/*export type AdminControlCommand =
  | 'ADD'
  | 'REM'
  | 'ADD_ADM'
  | 'REM_ADM'
  | 'UPD_ADM'
  | 'ROT_KEYS';
export type UserControlCommand = 'UPD_USER';
export type ControlCommand = AdminControlCommand | UserControlCommand;
*/

export interface BaseControlCommand {
  uid: Uint8Array,
}

export interface AddControlCommand extends BaseControlCommand {
  type: 'ADD',
}

export interface RemControlCommand  extends BaseControlCommand{
  type: 'REM',
}

export interface AddAdmControlCommand  extends BaseControlCommand{
  type: 'ADD_ADM',
}

export interface RemAdmControlCommand  extends BaseControlCommand{
  type: 'REM_ADM',
}

export interface UpdAdmControlCommand  extends BaseControlCommand{
  type: 'UPD_ADM',
}

export interface RotKeysControlCommand extends BaseControlCommand {
  type: 'ROT_KEYS',
}

export interface UpdUserControlCommand extends BaseControlCommand {
  type: 'UPD_USER',
}

type AdminControlCommand = 
  | AddControlCommand 
  | RemControlCommand 
  | AddAdmControlCommand 
  | RemAdmControlCommand 
  | UpdAdmControlCommand 
  | RotKeysControlCommand;

type UserControlCommand =
  | UpdUserControlCommand;

export type ControlCommand = AdminControlCommand | UserControlCommand;


export interface ExecCtrlResult {
  controlMessage: string;
  welcomeMessage: string | undefined;
}
