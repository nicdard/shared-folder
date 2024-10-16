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
import { generateEphemeralKeyPair, string2ArrayBuffer } from '../commonCrypto';
import { kemKdfDecap, kemKdfEncap } from '../kemKdf';

it('KEM+KDF encap and decap derive the same key', async () => {
  const KEM_KDF_TEST_LABEL = string2ArrayBuffer('KDF_KDF_TEST');
  const a = await generateEphemeralKeyPair();
  const encapResult = await kemKdfEncap(a.publicKey, KEM_KDF_TEST_LABEL);
  const decapsulated = await kemKdfDecap(a, encapResult.c, KEM_KDF_TEST_LABEL);
  expect(encapResult.k).toStrictEqual(decapsulated);
});
