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
import { getClientFolder } from '../../cli';
import { CLIENTS_CERT_DIR } from '../authentication';
import { decodeObject, encodeObject } from '../marshaller';
import { ClientState } from './gkp';
import * as fspromise from 'fs/promises';
import path from 'path';
import { arrayBuffer2string } from '../commonCrypto';
import { KaPPA } from '../key-progression/kappa';

export interface GKPStorage {
  save(userId: string, state: ClientState): Promise<void>;
  load(userId: string, groupId: string | Uint8Array): Promise<ClientState>;
  delete(userId: string, groupId: string): Promise<void>;
}

type SerializedGKPState = {
  role: ClientState['role'];
  cgkaMemberGroupId: Uint8Array;
  cgkaAdminGroupId: Uint8Array | undefined;
  interval: Buffer | undefined;
  kp: Buffer | undefined;
};

/**
 * An implementation for NodeJS based environments of the storage for a GKP.
 * This rely on the filesystem.
 */
export const GKPFileStorage: GKPStorage = {
  async save(userId: string, state: ClientState): Promise<void> {
    switch (state.role) {
      case 'admin': {
        const serialized: SerializedGKPState = {
          role: state.role,
          cgkaAdminGroupId: state.cgkaAdminGroupId,
          cgkaMemberGroupId: state.cgkaMemberGroupId,
          kp: await state.kp.serialize(),
          interval: undefined,
        };
        const s = await encodeObject<SerializedGKPState>(serialized);
        const clientStatePath = await getClientStatePath(
          userId,
          arrayBuffer2string(state.cgkaMemberGroupId)
        );
        await fspromise.writeFile(clientStatePath, s);
        break;
      }
      case 'member': {
        const serialized: SerializedGKPState = {
          role: state.role,
          cgkaAdminGroupId: undefined,
          cgkaMemberGroupId: state.cgkaMemberGroupId,
          kp: undefined,
          interval: await KaPPA.serializeExported(state.interval),
        };
        const s = await encodeObject<SerializedGKPState>(serialized);
        const clientStatePath = await getClientStatePath(
          userId,
          arrayBuffer2string(state.cgkaMemberGroupId)
        );
        await fspromise.writeFile(clientStatePath, s);
        break;
      }
      default:
        throw new Error('A client can only be a member or an admin.');
    }
  },

  async load(
    userId: string,
    groupId: string | Uint8Array
  ): Promise<ClientState> {
    const guid =
      typeof groupId === 'string' ? groupId : arrayBuffer2string(groupId);
    const clientStatePath = await getClientStatePath(userId, guid);
    const content = await fspromise.readFile(clientStatePath);
    const serialized = await decodeObject<SerializedGKPState>(content);
    switch (serialized.role) {
      case 'admin': {
        return {
          role: serialized.role,
          kp: await KaPPA.deserialize(serialized.kp),
          cgkaAdminGroupId: serialized.cgkaAdminGroupId,
          cgkaMemberGroupId: serialized.cgkaMemberGroupId,
        };
      }
      case 'member': {
        return {
          role: serialized.role,
          interval: await KaPPA.deserializeExported(serialized.interval),
          cgkaMemberGroupId: serialized.cgkaMemberGroupId,
        };
      }
      default:
        throw new Error(`Invalid state for user ${userId}.`);
    }
  },

  async delete(userId: string, groupId: string): Promise<void> {
    const clientStatePath = await getClientStatePath(userId, groupId);
    await fspromise.rm(clientStatePath);
  },
};

async function getClientStatePath(userId: string, groupId: string) {
  const clientFolder = getClientFolder(CLIENTS_CERT_DIR, userId);
  const statePath = path.join(clientFolder, 'state');
  await fspromise.mkdir(statePath, { recursive: true });
  const filePath = path.join(statePath, groupId);
  return filePath;
}
