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
import { string2ArrayBuffer } from '../commonCrypto';
import {
  importAesGcmKey,
  exportAesGcmKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  generateSymmetricKey,
} from '../symmetricCrypto';

it('Import an exported key should give the same object', async () => {
  const key = await generateSymmetricKey();
  expect(key.algorithm.name).toEqual('AES-GCM');
  const exportedKey = await exportAesGcmKey(key);
  const importedKey = await importAesGcmKey(exportedKey);
  expect(importedKey).toStrictEqual(key);
});

it('Decrypt an encrypted buffer of data should return the original data', async () => {
  const key = await generateSymmetricKey();
  const data = string2ArrayBuffer('some testing data');
  const encryptedData = await aesGcmEncrypt(key, data);
  expect(encryptedData.iv).toHaveLength(12);
  const decryptedData = await aesGcmDecrypt(key, encryptedData);
  expect(decryptedData).toStrictEqual(data);
});

it('Decrypt an encrypted buffer of data wihout passing the same additionalData fails', async () => {
  const key = await generateSymmetricKey();
  const data = string2ArrayBuffer('some testing data');
  const additionalData = string2ArrayBuffer('additional Authenticated data');
  const encryptedData = await aesGcmEncrypt(key, data, additionalData);
  expect(encryptedData.iv).toHaveLength(12);
  // eslint-disable-next-line @typescript-eslint/no-floating-promises
  expect(aesGcmDecrypt(key, encryptedData)).rejects.toThrow();
});
