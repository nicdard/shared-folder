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
import { AES_GCM_PARAMS, subtle } from './commonCrypto';

/**
 * The result of an encryption using AES-GCM.
 */
export interface AesGcmEncryptResult {
  ctxt: ArrayBuffer;
  iv: Uint8Array;
}

/**
 * The size of the authentication tag generated in the encryption operation
 */
const TAG_LENGTH = 96;

/**
 * @returns an exportable {@link CryptoKey} for AES_GCM with encrypt and decrypt capabilities.
 */
export function generateSymmetricKey(): Promise<CryptoKey> {
  return subtle.generateKey(AES_GCM_PARAMS, true, ['encrypt', 'decrypt']);
}

/**
 * @returns the generated random IV values as a {@link Uint8Array}. Use the reccomended length of 96 bits.
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * @param k the AES-GCM crypto key
 * @param msg the message to encrypt
 * @returns the {@link AesGcmEncryptResult} containing the initialisation vector and the ciphertext.
 */
export async function aesGcmEncrypt(
  k: CryptoKey,
  msg: ArrayBufferLike,
  additionalData?: BufferSource
): Promise<AesGcmEncryptResult> {
  const iv = generateIV();
  const additionalProps =
    additionalData != null ? { additionalData, tagLength: TAG_LENGTH } : {};
  const ctxt = await subtle.encrypt(
    { name: AES_GCM_PARAMS.name, iv, ...additionalProps },
    k,
    msg
  );
  return { iv, ctxt };
}

/**
 * @param k the AES-GCM crypto key
 * @param encResult the result of an encryption with {@link aesGcmEncrypt}.
 * @returns the buffer containing the decrypted message.
 */
export async function aesGcmDecrypt(
  k: CryptoKey,
  encResult: AesGcmEncryptResult,
  additionalData?: BufferSource
): Promise<ArrayBuffer> {
  const additionalProps =
    additionalData != null ? { additionalData, tagLength: TAG_LENGTH } : {};
  return subtle.decrypt(
    { name: AES_GCM_PARAMS.name, iv: encResult.iv, ...additionalProps },
    k,
    encResult.ctxt
  );
}

/**
 * @param rawK the key exported in raw format.
 * @returns the {@link CryptoKey} imported.
 */
export function importAesGcmKey(rawK: ArrayBufferLike): Promise<CryptoKey> {
  return subtle.importKey('raw', rawK, AES_GCM_PARAMS, true, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * @param k the {@link CryptoKey} to export.
 * @returns the raw representation of the key.
 */
export function exportAesGcmKey(k: CryptoKey): Promise<ArrayBuffer> {
  return subtle.exportKey('raw', k);
}
