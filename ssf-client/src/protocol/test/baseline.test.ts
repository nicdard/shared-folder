import { Decoder, Encoder } from 'cbor';
import {
  Metadata,
  encryptFolderKeyForUser,
  decodeMetadata,
  decryptFolderKey,
  encodeMetadata,
  shareFolder,
  encodeIdentityAsMetadataMapKey,
  createInitialMetadataFile,
} from '../baseline';
import {
  base64encode,
  exportPrivateCryptoKeyToPem,
  exportPublicCryptoKey,
  generateSalt,
  string2ArrayBuffer,
  subtle,
} from '../commonCrypto';
import { generateIV } from '../symmetricCrypto';

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
  const encryptedFolderKey = await encryptFolderKeyForUser(bPk, folderKey);
  const decrypted = await decryptFolderKey(
    { privateKey: bSk, publicKey: bPk },
    encryptedFolderKey
  );
  expect(decrypted).toStrictEqual(folderKey);
});

it("Sharing a folder will add the folder key under the other user identity, encrypted for it's long term identity", async () => {
  const aIdentity = base64encode('a@test.com');
  const bIdentity = base64encode('b@test.com');
  const senderKeyPair = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  const aSkPEM = await exportPrivateCryptoKeyToPem(senderKeyPair.privateKey);
  const aPkPEM = await exportPublicCryptoKey(senderKeyPair.publicKey);
  const receiverKeyPair = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  // const bSkPEM = await exportPrivateCryptoKeyToPem(bSk);
  const bPkPEM = await exportPublicCryptoKey(receiverKeyPair.publicKey);
  const senderIdentity = encodeIdentityAsMetadataMapKey(aIdentity);
  // create the initial metadata file.
  const metadata: Metadata = await createInitialMetadataFile({
    senderIdentity,
    senderPkPEM: aPkPEM,
  });
  const exportedFolderKey = await decryptFolderKey(
    senderKeyPair,
    metadata.folderKeysByUser[senderIdentity]
  );
  const receiverIdentity = encodeIdentityAsMetadataMapKey(bIdentity);
  const encodedMetadata = await encodeMetadata(metadata);
  const encodedUpdatedMetadata = await shareFolder({
    senderIdentity,
    senderSkPEM: aSkPEM,
    senderPkPEM: aPkPEM,
    receiverIdentity,
    receiverPkPEM: bPkPEM,
    metadataContent: encodedMetadata,
  });
  const updatedMetadata = await decodeMetadata(encodedUpdatedMetadata);
  // check that all properties before are still there
  expect(updatedMetadata).toMatchObject(metadata);
  // check the new added entry for the shared folder key
  expect(updatedMetadata.folderKeysByUser[receiverIdentity]).not.toBeNull();
  // check that there are only the two expected encrypted folder keys
  // TODO: base64 the emails because we don't want the dots inside the names of the object properties.
  expect(updatedMetadata.folderKeysByUser).toHaveProperty(receiverIdentity);
  // Check that the encrypted key of the sender didn't change
  expect(
    new Uint8Array(updatedMetadata.folderKeysByUser[senderIdentity].ctxt)
  ).toStrictEqual(
    new Uint8Array(metadata.folderKeysByUser[senderIdentity].ctxt)
  );
  // Check that the keys are the same once decrypted.
  const decryptedKeyForReceiver = await decryptFolderKey(
    receiverKeyPair,
    updatedMetadata.folderKeysByUser[receiverIdentity]
  );
  expect(decryptedKeyForReceiver).toStrictEqual(exportedFolderKey);
});

it('cbor does not supports js Map', async () => {
  const a = new Map<string, string>();
  const b = { a: a };
  const s = await Encoder.encodeAsync(b);
  const d = (await Decoder.decodeFirst(s)) as { a: Map<string, string> };
  expect(d).not.toEqual(b);
});
