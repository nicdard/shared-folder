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
