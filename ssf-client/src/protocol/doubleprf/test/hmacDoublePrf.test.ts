import { HMAC_PARAMS, subtle } from '../../commonCrypto';
import { doublePRFderiveKeyFromRaw } from '../hmacDoublePrf';

it('double-PRF can combine two HMAC raw keys', async () => {
  const hmacKey1 = await subtle.generateKey(HMAC_PARAMS, true, [
    'sign',
    'verify',
  ]);
  const hmacKey2 = await subtle.generateKey(HMAC_PARAMS, true, [
    'sign',
    'verify',
  ]);
  const key1Raw = await subtle.exportKey('raw', hmacKey1);
  const key2Raw = await subtle.exportKey('raw', hmacKey2);
  const derivedKey = await doublePRFderiveKeyFromRaw(key1Raw, key2Raw);
  expect(derivedKey.algorithm).toEqual({ name: 'HKDF' });
});
