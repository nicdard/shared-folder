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
import {
  HMAC_PARAMS,
  getHkdfParams,
  string2ArrayBuffer,
  subtle,
} from '../commonCrypto';

const DOUBLE_PRF_LABEL = string2ArrayBuffer('HMAC-doublePRF');

/**
 * @param key1 bytes of a {@link CryptoKey} to be used in the derivation
 * @param key2 bytes of a {@link CryptoKey} to be used in the derivation
 * @returns the HKDF {@link CryptoKey} derived by applying HMAC (which is a double PRF) to the input key materials.
 */
export async function doublePRFderiveKeyFromRaw(
  key1: ArrayBuffer,
  key2: ArrayBuffer
): Promise<CryptoKey> {
  // We use the HMAC algorithm to combine forward and backward key into a key
  // which is used as a key for HKDF to then derive the final AES-GCM key.
  const doublePRFKey = await subtle.importKey('raw', key1, HMAC_PARAMS, false, [
    'sign',
  ]);
  const keyBytes = await subtle.sign(HMAC_PARAMS, doublePRFKey, key2);
  const k = await subtle.importKey(
    'raw',
    keyBytes,
    getHkdfParams(DOUBLE_PRF_LABEL, new Uint8Array()),
    false,
    ['deriveKey', 'deriveBits']
  );
  return k;
}
