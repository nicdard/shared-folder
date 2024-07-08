import { Decoder, Encoder } from 'cbor';
import {
  Metadata,
  agreeAndEncryptFolderKey,
  decodeMetadata,
  decryptFolderKey,
  encodeMetadata,
  shareFolder,
} from '../baseline';
import {
  base64encode,
  exportPrivateCryptoKeyToPem,
  exportPublicCryptoKey,
  generateIV,
  generateSalt,
  string2ArrayBuffer,
  subtle,
} from '../commonCrypto';

test('Encoding and decoding of a non-empty Metadata works', async () => {
  const pe = `-----BEGIN PUBLIC KEY-----\npe1\n-----END PUBLIC KEY-----`;
  const pe2 = `-----BEGIN PUBLIC KEY-----\npe1\n-----END PUBLIC KEY-----`;

  const metadata: Metadata = {
    folderKeysByUser: {
      'user1@test.com': {
        ctxt: new TextEncoder().encode('KEncryptedForUser1'),
        pe,
        iv: generateIV(),
        salt: generateSalt(256),
      },
      'user2@test.com': {
        ctxt: new TextEncoder().encode('KEncryptedForUser2'),
        pe: pe2,
        iv: generateIV(),
        salt: generateSalt(256),
      },
    },
    fileMetadatas: {},
  };
  const encodedMetadata = await encodeMetadata(metadata);
  const decodedMetadata = await decodeMetadata(new Uint8Array(encodedMetadata));
  expect(decodedMetadata).toEqual(metadata);
});

it('Encrypt folder key from a user and decrypting it from the receiver works', async () => {
  const { privateKey: bSk, publicKey: bPk } = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  const folderKey = string2ArrayBuffer('AFolderKeyWhichIsUnsecure');
  const encryptedFolderKey = await agreeAndEncryptFolderKey(
    bPk,
    Buffer.from(folderKey)
  );
  const decrypted = await decryptFolderKey(bSk, bPk, encryptedFolderKey);
  expect(decrypted).toStrictEqual(folderKey);
});

it('Sharing a folder will add the folder key under the other user identity, ecrypted for it\'s long term identity', async () => {
  const aIdentity = base64encode("a@test.com");
  const bIdentity = base64encode("b@test.com");
  const { privateKey: aSk, publicKey: aPk } = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  const aSkPEM = await exportPrivateCryptoKeyToPem(aSk);
  const aPkPEM = await exportPublicCryptoKey(aPk);
  const { privateKey: bSk, publicKey: bPk } = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  const folderKey = await subtle.generateKey({
    name: "AES-GCM",
    length: 256,
  },
  true,
  ["encrypt", "decrypt"]);
  // const bSkPEM = await exportPrivateCryptoKeyToPem(bSk);
  const bPkPEM = await exportPublicCryptoKey(bPk);
  const exportedFolderKey = await subtle.exportKey('raw', folderKey);
  const encryptedFolderKeyForA = await agreeAndEncryptFolderKey(aPk, exportedFolderKey);
  const metadata: Metadata = {
    folderKeysByUser: {
      [aIdentity]: encryptedFolderKeyForA
    },
    fileMetadatas: {}
  };
  const encodedMetadata = await encodeMetadata(metadata);
  const encodedUpdatedMetadata = await shareFolder(aIdentity, aSkPEM, aPkPEM, bIdentity, bPkPEM, encodedMetadata);
  const updatedMetadata = await decodeMetadata(encodedUpdatedMetadata);
  // check that all properties before are still there
  expect(updatedMetadata).toMatchObject(metadata);
  // check the new added entry for the shared folder key
  expect(updatedMetadata.folderKeysByUser[base64encode(bIdentity)]).not.toBeNull();
  // check that there are only the two expected encrypted folder keys
  // TODO: base64 the emails because we don't want the dots inside the names of the object properties.
  expect(updatedMetadata.folderKeysByUser).toHaveProperty(bIdentity);
});

it('cbor does not supports js Map', async () => {
  const a = new Map<string, string>();
  const b = { "a": a };
  const s = await Encoder.encodeAsync(b);
  const d = await Decoder.decodeFirst(s) as { "a": Map<string, string> };
  expect(d).not.toEqual(b);
});
