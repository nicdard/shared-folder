import {
  Metadata,
  agreeAndEncryptFolderKey,
  decodeMetadata,
  decryptFolderKey,
  encodeMetadata,
} from '../baseline';
import {
  generateIV,
  generateSalt,
  string2ArrayBuffer,
  subtle,
} from '../crypto';

test('Encoding and decoding of a non-empty Metadata works', async () => {
  const pe = `-----BEGIN PUBLIC KEY-----\npe1\n-----END PUBLIC KEY-----`;
  const pe2 = `-----BEGIN PUBLIC KEY-----\npe1\n-----END PUBLIC KEY-----`;

  const metadata: Metadata = {
    folderKeysByUser: {
      'user1@test.com': {
        cipher: new TextEncoder().encode('KEncryptedForUser1'),
        pe,
        iv: generateIV(),
        salt: generateSalt(256),
      },
      'user2@test.com': {
        cipher: new TextEncoder().encode('KEncryptedForUser2'),
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
  const { privateKey: aSk, publicKey: aPk } = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
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
  console.log(encryptedFolderKey);
  const decrypted = await decryptFolderKey(bSk, bPk, encryptedFolderKey);
  console.log(decrypted);
});
