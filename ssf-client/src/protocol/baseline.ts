import { Decoder, Encoder } from "cbor";
import { FolderResponse } from "../gen/clients/ds";
import { write } from "fs";
import { ExtendedResults } from "cbor/types/lib/decoder";

// https://davidmyers.dev/blog/a-practical-guide-to-the-web-cryptography-api

const { subtle } = globalThis?.crypto || window.crypto;
const ALGO_NAME = 'AES-GCM';

/**
 * The parameters for Elliptic curve Diffie-Hellman. 
 */
const ECDH_PARAMS = {
  name: 'ECDH',
  namedCurve: 'P-256' // PKCS_ECDSA_P256_SHA256
};

/**
 * The metadata of a file.
 * Holds the cryptographic state associated with a file and sensitive metadata information.
 */
export interface FileMetadata {
    // The file symmetric encryption key.
    fileKey: CryptoKey,
    // The file name.
    fileName: string,
}

/**
 * The type of an encrypted {@link FileMetadata} object.
 */
type EncryptedFileMetadata = Uint8Array;

/**
 * The type of an asymmetric encrypted folder key.
 */
type EncryptedFolderKey = { cipher: ArrayBuffer, iv: Uint8Array };

/**
 * The Metadata file is associated with a sharable folder and stored at the root of the folder.
 * This contains the cryptographic state:
 * - a folder key encrypted for each user
 * - a map from each file id (known to the DS server) to the corresponding encrypted {@link FileMetadata} object. Those are represented using {@link EncryptedFileMetadata}.
 */
export interface Metadata {
    /**
     * All the folder keys that are encrypted for the user.
     * The map is indexed by the user's identity.
     * The value is the asymmetrically encrypted key of the folder that can be decrypted by the user's private key.
     */
    folderKeysByUser: { [key: string]: EncryptedFolderKey },
    /**
     * For each file id, maps to the metadata of the file.
     * The index is the id of the file (a GUID).
     */
    fileMetadatas: { [key: string]: EncryptedFileMetadata },
}

export async function addUsers(metadata: Metadata, [currentEmail, currentSk]: [string, Buffer], ...others: [string, Buffer][]): Promise<Metadata> {
    const encryptedFolderKey = metadata.folderKeysByUser[currentEmail];
    const { pem, folderKey } = await decryptFolderKey(encryptedFolderKey, currentSk);
    for ( const [otherEmail, otherPk] of others ) {
        const otherEncryptedFolderKey = await encryptFolderKey(new Buffer(pem), otherPk, currentSk);
        metadata.folderKeysByUser[otherEmail] = otherEncryptedFolderKey;
    }
    return metadata;
}

async function encryptFolderKey(pem: Buffer, otherPk: Buffer, currentSk: Buffer): Promise<{ cipher: ArrayBuffer, iv: Uint8Array}> {
    const otherCryptoPk = await importECDHPublicKey(otherPk);
    // const currentCryptoSk = await importECDHSecretKey(currentSk);
    const ephemeralKey = await generateEphemeralDeriveKeyPair();
    const otherEncryptedFolderKey = await agreeAndEncrypt(ephemeralKey.privateKey, otherCryptoPk, pem);
    return otherEncryptedFolderKey;

}

/**
 * @returns CryptoKeyPair generated with deriveKey usage.
 */
function generateEphemeralDeriveKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    ECDH_PARAMS,
    false,
    ["deriveKey"],
  );
}

/**
 * @returns CryptoKeyPair generated with deriveKey usage.
 */
function generateEphemeralEncryptionKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    ECDH_PARAMS,
    false,
    ["encrypt", "decrypt"],
  );
}

/*
Derive an AES key, given:
- our ECDH private key
- their ECDH public key
*/
function deriveSecretKey(privateKey: CryptoKey, publicKey: CryptoKey) {
    return subtle.deriveKey(
      {
        name: "ECDH",
        public: publicKey,
      },
      privateKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"],
    );
  }
  
/**
 * @returns the generated random IV values as a {@link Uint8Array}.
 */
function generateIV() {
    return (globalThis?.crypto || window.crypto).getRandomValues(new Uint8Array(12));
}

async function agreeAndEncrypt(currentSk: CryptoKey, otherPk: CryptoKey, encoded: Buffer) {
    if (currentSk.algorithm.name != 'ECDH' || otherPk.algorithm.name != 'ECDH') {
        throw new Error(`Unsupported algorithm`);
    }
    const key = await deriveSecretKey(currentSk, otherPk);
    const iv = generateIV();
    const cipher = await subtle.encrypt({
        name: ALGO_NAME,
        iv,
    }, key, encoded);
    return {
        cipher,
        iv
    };
}

// from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
function str2ab(str: string) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

/**
 * @param pem the PEM encoded certificate public key
 * @returns the imported key from the certificate
 */
function importECDHPublicKey(pem: Buffer): Promise<CryptoKey> {
    // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.toString().substring(
    pemHeader.length,
    pem.length - pemFooter.length - 1
  );
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return subtle.importKey(
    "spki",
    binaryDer,
    ECDH_PARAMS,
    true,
    ["encrypt"],
  );

}

/**
 * @param pem the PEM encoded certificate containing the private key.
 * @returns the imported crypto key object.
 */
function importECDHSecretKey(pem: Buffer): Promise<CryptoKey> {
    // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.toString().substring(
    pemHeader.length,
    pem.length - pemFooter.length - 1,
  );
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    ECDH_PARAMS,
    true,
    ["encrypt", "decrypt"],
  );
}

async function decryptFolderKey(encryptedFolderKey: EncryptedFolderKey, sk: Buffer): Promise<{ pem: string, folderKey: CryptoKey}> {
    const { cipher, iv } = encryptedFolderKey;
    
}



export async function encryptFileKey(fileKey: CryptoKey, ...otherEmails: string[]) {
    if (otherEmails.length == 0) {
        throw new Error("There should be at least one email to share the key with.");
    }
    //const 
    const {window} = globalThis;


    // Retrieve public key
    // subtle.decrypt();

    const key = await subtle.generateKey({
        name: 'AES-CBC',
        length,
    }, true, ['encrypt', 'decrypt']);
}


/**
 * @param metadata the {@link Metadata} object to encode
 * @returns CBOR encoding of the metadata object
 */
export async function encodeMetadata(metadata: Metadata): Promise<Buffer> {
    /* TODO: when server supports stream api, use stream: https://nodejs.org/api/stream.html
    const encoder = new Encoder({ canonical: true, detectLoops: false });
    encoder.pushAny(metadata);
    */
    const encoded = await Encoder.encodeAsync(metadata, { canonical: true, detectLoops: false });
    return encoded;
}

/**
 * @param metadata the {@link Metadata} object searialized by {@link encodeMetadata}
 * @returns the {@link Metadata} object
 */
export async function decodeMetadata(metadata: Uint8Array): Promise<Metadata> {
    const decoded: Metadata = (await Decoder.decodeFirst(metadata, { preventDuplicateKeys: false, extendedResults: false })) as Metadata;
    console.debug(decoded);
    return decoded;
}
 