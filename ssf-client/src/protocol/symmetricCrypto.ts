import { AES_GCM_PARAMS, subtle } from './commonCrypto';

/**
 * The result of an encryption using AES-GCM.
 */
export interface AesGcmEncryptResult {
  ctxt: ArrayBuffer;
  iv: Uint8Array;
}

/**
 * @returns an exportable {@link CryptoKey} for AES_GCM with encrypt and decrypt capabilities.
 */
export function generateSymmetricKey(): Promise<CryptoKey> {
  return subtle.generateKey(AES_GCM_PARAMS, true, ['encrypt', 'decrypt']);
}

/**
 * @returns the generated random IV values as a {@link Uint8Array}.
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
  msg: ArrayBufferLike
): Promise<AesGcmEncryptResult> {
  const iv = generateIV();
  const ctxt = await subtle.encrypt({ name: AES_GCM_PARAMS.name, iv }, k, msg);
  return { iv, ctxt };
}

/**
 * @param k the AES-GCM crypto key
 * @param encResult the result of an encryption with {@link aesGcmEncrypt}.
 * @returns the buffer containing the decrypted message.
 */
export async function aesGcmDecrypt(
  k: CryptoKey,
  encResult: AesGcmEncryptResult
): Promise<ArrayBuffer> {
  return subtle.decrypt(
    { name: AES_GCM_PARAMS.name, iv: encResult.iv },
    k,
    encResult.ctxt
  );
}
