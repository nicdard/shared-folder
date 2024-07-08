import { subtle } from 'crypto';
import {
  exportPublicCryptoKey,
  exportPrivateCryptoKeyToPem,
  importECDHSecretKey,
  importECDHPublicKey,
} from '../commonCrypto';

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
  expect(importedSk).toStrictEqual(privateKey);
  const pemPk = await exportPublicCryptoKey(publicKey);
  const importedPk = await importECDHPublicKey(Buffer.from(pemPk));
  expect(importedPk).toStrictEqual(publicKey);
});
