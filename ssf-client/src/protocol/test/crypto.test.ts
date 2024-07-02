import { subtle } from 'crypto';
import {
  exportPublicCryptoKey,
  exportPrivateCryptoKeyToPem,
  importECDHSecretKey,
  importECDHPublicKey,
} from '../crypto';

test('Exported key can be imported into the same key', async () => {
  const { privateKey, publicKey } = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  const pemSk = await exportPrivateCryptoKeyToPem(privateKey);
  const importedSk = await importECDHSecretKey(Buffer.from(pemSk));
  expect(importedSk).toEqual(privateKey);
  const pemPk = await exportPublicCryptoKey(publicKey);
  const importedPk = await importECDHPublicKey(Buffer.from(pemPk));
  console.log(publicKey.usages);
  expect(importedPk).toEqual(publicKey);
});
