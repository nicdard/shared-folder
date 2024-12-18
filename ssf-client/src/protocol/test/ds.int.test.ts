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
import { WebSocket } from 'isomorphic-ws';
import {
  CLIENTS_CERT_DIR,
  loadCaTLSCredentials,
  loadDefaultCaTLSCredentialsInterceptor,
  loadDsTLSInterceptor,
  loadTLSCredentials,
} from '../authentication';
import { OpenAPI as pkiOpenAPI } from '../../gen/clients/pki';
import { OpenAPI as dsOpenAPI } from '../../gen/clients/ds';
import { createFolder, register, shareFolder } from '../../ds';
import { pkiCreateIdentityAction, switchIdentity } from '../../cli';
import {
  arrayBuffer2string,
  importECDHPublicKeyPEMFromCertificate,
  importECDHSecretKey,
  string2ArrayBuffer,
  crypto,
} from '../commonCrypto';
import { decodeObject, encodeObject } from '../marshaller';
import EventSource = require('eventsource');
import { createSSENotificationReceiver } from '../notifications';
import { CrateService as dsclient } from '../../gen/clients/ds';

interface GruoupMessage {
  folder_id: number;
  payload: Uint8Array;
}

/**
 * This test requires both the pki and the ds servers to be up and running.
 */
it.skip('can connect to the websocket, also multiple clients', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const email = crypto.randomUUID() + '@test.com';
  await pkiCreateIdentityAction(email, {
    clientsDir: CLIENTS_CERT_DIR,
    reThrow: true,
  });
  await switchIdentity(email, { clientsDir: CLIENTS_CERT_DIR });
  const [key, cert] = loadTLSCredentials();
  await register(email);
  const ws = new WebSocket('wss://127.0.0.1:8001/groups/ws', {
    ca: loadCaTLSCredentials(),
    key,
    cert,
  });
  ws.onmessage = (e) => {
    console.log('received by ws:', arrayBuffer2string(e.data as ArrayBuffer));
  };
  const email2 = crypto.randomUUID() + '@test2.com';
  await pkiCreateIdentityAction(email2, {
    clientsDir: CLIENTS_CERT_DIR,
    reThrow: true,
  });
  await switchIdentity(email2, { clientsDir: CLIENTS_CERT_DIR });
  const [key2, cert2] = loadTLSCredentials();
  await register(email2);
  const { id, etag } = await createFolder({
    senderIdentity: email,
    senderPkPEM: await importECDHPublicKeyPEMFromCertificate(cert),
  });
  await shareFolder(id, email, key.toString(), cert.toString(), email2);
  const ws2 = new WebSocket('wss://127.0.0.1:8001/groups/ws', {
    ca: loadCaTLSCredentials(),
    key: key2,
    cert: cert2,
  });
  ws2.onmessage = (e) => {
    console.log('received by ws2', arrayBuffer2string(e.data as ArrayBuffer));
  };
  const p1 = new Promise((resolve, reject) => {
    ws.addEventListener('open', () => {
      const a = () =>
        setTimeout(() => {
          encodeObject<GruoupMessage>({
            folder_id: id,
            payload: new Uint8Array(string2ArrayBuffer('Hello world from ws!')),
          })
            .then((data) => {
              ws.send(data);
            })
            .catch((error) => console.error(error));
        }, 1000);

      for (let i = 0; i < 10; ++i) {
        a();
      }

      setTimeout(() => {
        if (ws.readyState == 1) {
          ws.close();
          resolve('ciao');
        } else {
          console.error(
            'The server detected an authentiation problem, check the DS logs.'
          );
          reject();
        }
      }, 10000);
    });
  });
  const p2 = await new Promise((resolve, reject) => {
    ws2.addEventListener('open', () => {
      const a = () => {
        encodeObject<GruoupMessage>({
          folder_id: id,
          payload: new Uint8Array(string2ArrayBuffer('Hello world from ws2!')),
        })
          .then((data) => {
            ws2.send(data);
          })
          .catch((error) => console.error(error));
      };
      for (let i = 0; i < 10; ++i) {
        a();
      }
      setTimeout(() => {
        if (ws2.readyState == 1) {
          ws2.close();
          resolve('ciao');
        } else {
          console.error(
            'The server detected an authentication problem, check the DS logs.'
          );
          reject();
        }
      }, 10000);
    });
  });
  await Promise.all([p1, p2]);
});

it.skip('Client receive SSE notifications', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const email = crypto.randomUUID() + '@test.com';
  await pkiCreateIdentityAction(email, {
    clientsDir: CLIENTS_CERT_DIR,
    reThrow: true,
  });
  await switchIdentity(email, { clientsDir: CLIENTS_CERT_DIR });
  const [key, cert] = loadTLSCredentials();
  await register(email);
  const email2 = crypto.randomUUID() + '@test2.com';
  await pkiCreateIdentityAction(email2, {
    clientsDir: CLIENTS_CERT_DIR,
    reThrow: true,
  });
  await switchIdentity(email2, { clientsDir: CLIENTS_CERT_DIR });
  const [key2, cert2] = loadTLSCredentials();
  await register(email2);
  const { id, etag } = await createFolder({
    senderIdentity: email,
    senderPkPEM: await importECDHPublicKeyPEMFromCertificate(cert),
  });
  const notifications = new Promise<void>((resolve, reject) => {
    const eventSource = createSSENotificationReceiver(
      (data) => {
        console.log('Receiver 1: ', data);
        reject();
      },
      {
        key,
        cert,
        ca: loadCaTLSCredentials(),
      }
    );
    const eventSource2 = createSSENotificationReceiver(
      (data) => {
        console.log('Receiver 2: ', data);
        resolve();
      },
      {
        key: key2,
        cert: cert2,
        ca: loadCaTLSCredentials(),
      }
    );
    setTimeout(() => {
      // Create an hard limit.
      eventSource2.then((e) => e.close()).catch(reject);
      eventSource.then((e) => e.close()).catch(reject);
      reject();
    }, 3000);
  });
  await shareFolder(id, email, key.toString(), cert.toString(), email2);
  await notifications;
});

it.skip('Can upload and download key packages', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const email = crypto.randomUUID() + '@test.com';
  await pkiCreateIdentityAction(email, {
    clientsDir: CLIENTS_CERT_DIR,
    reThrow: true,
  });
  await switchIdentity(email, { clientsDir: CLIENTS_CERT_DIR });
  await register(email);
  const keyPackagePayload = 'asdadsads';
  await dsclient.publishKeyPackage({
    formData: {
      key_package: new Blob([string2ArrayBuffer(keyPackagePayload)]),
    },
  });
  const folder = await dsclient.createFolder({
    formData: {
      metadata: new Blob([string2ArrayBuffer('metadata')]),
    },
  });
  const keyPackage = await dsclient.fetchKeyPackage({
    folderId: folder.id,
    requestBody: {
      user_email: email,
    },
  });
  const k = arrayBuffer2string(
    new Uint8Array(keyPackage.payload as unknown as ArrayBuffer)
  );
  console.log(k);
  expect(k).toEqual(keyPackagePayload);
});
