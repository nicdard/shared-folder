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
