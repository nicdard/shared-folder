const crypto = globalThis.crypto;
export const { subtle } = crypto;

/**
 * The name of Elliptic Curve Diffie-Hellman algorithm.
 */
const ECDH = 'ECDH';

/**
 * The parameters for Elliptic curve Diffie-Hellman.
 */
export const ECDH_PARAMS = {
  name: ECDH,
  namedCurve: 'P-256', // PKCS_ECDSA_P256_SHA256
};

/**
 * The parameters for AES-GCM.
 */
const AES_GCM_PARAMS = {
  name: 'AES-GCM',
  length: 256,
};

/**
 * The parameters for HKDF.
 */
const HKDF_PARAMS = {
  name: 'HKDF',
  hash: 'SHA-256',
};

/**
 * @returns CryptoKeyPair generated with deriveKey usage.
 */
export function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey(ECDH_PARAMS, true, ['deriveKey']);
}

/**
 * @param pk Public key
 * @param sk Secret key
 * @returns HKDF CryptoKey generated using DH
 */
export function deriveHKDFKeyWithDH(
  pk: CryptoKey,
  sk: CryptoKey
): Promise<CryptoKey> {
  const ecdhKeyDeriveParams = {
    name: ECDH,
    public: pk,
  };
  return subtle.deriveKey(ecdhKeyDeriveParams, sk, HKDF_PARAMS, false, [
    'deriveKey',
  ]);
}

/**
 * @param k the HKDF key
 * @param label the label to be set during derivation
 * @returns a HKDF key
 */
export function deriveHKDFKeyWithHKDF(
  k: CryptoKey,
  label: ArrayBuffer | Uint8Array,
  salt: Uint8Array
): Promise<CryptoKey> {
  const hkdfParams = getHkdfParams(label, salt);
  console.log(hkdfParams);
  return subtle.deriveKey(hkdfParams, k, HKDF_PARAMS, false, ['deriveKey']);
}

/**
 * @param k the key material
 * @param pk the public key
 * @param pe the epehemeral public key
 * @param salt the salt for the HKDF function, you can generate one using {@link generateSalt} function.
 * @returns The AES-GCM key using HKDF where we set the label to contain the concatenation of `pk` and `pe`.
 */
export async function deriveAesGcmKeyFromEphemeralAndPublicKey(
  k: CryptoKey,
  pk: CryptoKey,
  pe: CryptoKey,
  salt: Uint8Array
): Promise<CryptoKey> {
  const rawPk = await subtle.exportKey('raw', pk);
  const rawPe = await subtle.exportKey('raw', pe);
  const info = appendBuffers(rawPe, rawPk);
  const hkdfParams = getHkdfParams(info, salt);
  console.log(hkdfParams);
  return subtle.deriveKey(hkdfParams, k, AES_GCM_PARAMS, true, [
    'encrypt',
    'decrypt',
  ]);
}


/* 
type PEM = string & { _brand: 'PEM' };

function isPEM(str: string): str is PEM {
  return true;
}

type PublicPEM = `-----BEGIN PUBLIC KEY-----${string}-----END PUBLIC KEY-----`;
type PrivatePEM = `-----BEGIN PRIVATE KEY-----${string}-----END PRIVATE KEY-----`;
*/

/**
 * @param pem the PEM encoded certificate public key
 * @returns the imported key from the certificate
 */
export function importECDHPublicKey(pem: Buffer | string): Promise<CryptoKey> {
  // fetch the part of the PEM string between header and footer
  const pemHeader = '-----BEGIN PUBLIC KEY-----';
  const pemFooter = '-----END PUBLIC KEY-----';
  const pemContents = pem
    .toString()
    .substring(pemHeader.length, pem.length - pemFooter.length - 1);
  // base64 decode the string to get the binary data
  const binaryDerString = base64decode(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = string2ArrayBuffer(binaryDerString);

  return subtle.importKey('spki', binaryDer, ECDH_PARAMS, true, []);
}

/**
 * @param pem the PEM encoded certificate containing the private key.
 * @returns the imported crypto key object.
 */
export function importECDHSecretKey(pem: Buffer | string): Promise<CryptoKey> {
  console.debug(pem);
  // fetch the part of the PEM string between header and footer
  const pemHeader = '-----BEGIN PRIVATE KEY-----';
  const pemFooter = '-----END PRIVATE KEY-----';
  const pemContents = pem
    .toString()
    .substring(pemHeader.length, pem.length - pemFooter.length - 1);
  // base64 decode the string to get the binary data
  const binaryDerString = base64decode(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = string2ArrayBuffer(binaryDerString);

  return subtle.importKey('pkcs8', binaryDer, ECDH_PARAMS, true, ['deriveKey']);
}

const nodeBtoa = (b: string) => Buffer.from(b).toString('base64');
const base64encode =
  typeof globalThis.btoa === 'undefined' ? nodeBtoa : globalThis.btoa;

const nodeAtob = (b: string) => Buffer.from(b, 'base64').toString();
const base64decode =
  typeof globalThis.atob === 'undefined' ? nodeAtob : globalThis.atob;

/**
 * from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
 * @param str the string to convert
 * @returns the {@link ArrayBuffer} containing the string
 */
export function string2ArrayBuffer(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * Convert an {@link ArrayBuffer} into a string
 * from https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string/
 * @param buf ArrayBuffer to convert to string
 * @returns the string conversion
 */
export function arrayBuffer2string(buf: ArrayBuffer): string {
  return String.fromCharCode(...new Uint8Array(buf));
}

/**
 * Export the given key and write it into the "exported-key" space.
 * @param key secret {@link CryptoKey} to export
 * @returns the PEM formatted exported key
 */
export async function exportPrivateCryptoKeyToPem(
  key: CryptoKey
): Promise<string> {
  const exported = await subtle.exportKey('pkcs8', key);
  const exportedAsString = arrayBuffer2string(exported);
  console.log(exportedAsString);
  const exportedAsBase64 = base64encode(exportedAsString);
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  return pemExported;
}

/**
 * Export the given key and write it into the "exported-key" space.
 * @param key public {@link CryptoKey} to export
 * @returns the PEM formatted exported key
 */
export async function exportPublicCryptoKey(key: CryptoKey) {
  const exported = await subtle.exportKey('spki', key);
  const exportedAsString = arrayBuffer2string(exported);
  const exportedAsBase64 = base64encode(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  return pemExported;
}

/**
 * @returns the generated random IV values as a {@link Uint8Array}.
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * @param lengthInBits the length of the
 * @returns the {@link Uint8Array} with the random value of size `lengthInBits` / 8.
 */
export function generateSalt(lengthInBits: number): Uint8Array {
  if (lengthInBits % 8 != 0) {
    throw new Error('The salt length needs to be a multiple of 8');
  }
  return crypto.getRandomValues(new Uint8Array(lengthInBits / 8));
}

/**
 * @param info the label to be used in HKDF
 * @returns HKDF parameters, with a random salt using SHA-256
 */
function getHkdfParams(info: ArrayBuffer | Uint8Array, salt: Uint8Array) {
  return {
    ...HKDF_PARAMS,
    salt,
    info,
  };
}

/**
 *
 * @param buffer1 the first ArrayBuffer
 * @param buffer2 the second ArrayBuffer
 * @returns the concatenation of `buffer1` and `buffer2`
 */
export function appendBuffers(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
  const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp.buffer;
}
