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
