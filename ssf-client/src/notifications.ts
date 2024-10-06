import { loadCaTLSCredentials, loadTLSCredentials } from './authentication';
import { OpenAPI } from './gen/clients/ds';
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
      onmessage(BigInt(data.data));
    });
  });
}
