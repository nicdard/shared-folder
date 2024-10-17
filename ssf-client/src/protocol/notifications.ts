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
import { loadCaTLSCredentials, loadTLSCredentials } from './authentication';
import { OpenAPI } from '../gen/clients/ds';
import EventSource = require('eventsource');

export function createSSENotificationReceiver(
  onmessage: (data: bigint) => void,
  mTlSOptions?: {
    ca: Buffer | string;
    key: Buffer | string;
    cert: Buffer | string;
  }
): Promise<EventSource> {
  return new Promise((resolve, reject) => {
    if (mTlSOptions == null) {
      const ca = loadCaTLSCredentials();
      const [key, cert] = loadTLSCredentials();
      mTlSOptions = {
        ca,
        key,
        cert,
      };
    }
    const https = mTlSOptions;
    const receiver = new EventSource(OpenAPI.BASE + '/notifications', {
      https,
    });
    receiver.addEventListener('open', () => resolve(receiver));
    receiver.addEventListener('error', (e) => {
      console.error(e);
      receiver.close();
      reject();
    });
    receiver.addEventListener('message', (data: MessageEvent<string>) => {
      try {
        onmessage(BigInt(data?.data));
      } catch (e) {
        console.log(data);
        console.error(e);
      }
    });
  });
}
