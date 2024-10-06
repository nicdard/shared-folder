import { string2ArrayBuffer } from '../../commonCrypto';
import { mlsCgkaInit, mls_example } from 'ssf';

it('Can create a client', async () => {
  await mls_example();
  await mlsCgkaInit(string2Uint8Array('alice'), string2Uint8Array('groupid'));
});

function string2Uint8Array(str: string) {
  return new Uint8Array(string2ArrayBuffer(str));
}
