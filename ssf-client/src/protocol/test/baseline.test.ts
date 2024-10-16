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
import { Decoder, Encoder } from 'cbor';
import {
  Metadata,
  encryptFolderKeyForUser,
  decryptFolderKey,
  shareFolder,
  encodeIdentityAsMetadataMapKey,
  createInitialMetadataFile,
  addFile,
  readFile,
  createEncodedInitialMetadataFile,
  FileMetadata,
  decryptFileMetadata,
} from '../baseline';
import {
  arrayBuffer2string,
  base64encode,
  exportPrivateCryptoKeyToPem,
  exportPublicCryptoKey,
  generateSalt,
  importECDHPublicKeyFromCertificate,
  importECDHPublicKeyPEMFromCertificate,
  importECDHSecretKey,
  string2ArrayBuffer,
  subtle,
} from '../commonCrypto';
import { generateIV, importAesGcmKey } from '../symmetricCrypto';
import * as fs from 'fs';
import * as path from 'path';
import { parseEmailsFromCertificate } from 'common';
import { decodeObject, encodeObject } from '../marshaller';

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
  const encodedMetadata = await encodeObject(metadata);
  const decodedMetadata = await decodeObject<Metadata>(
    new Uint8Array(encodedMetadata)
  );
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
  const encodedMetadata = await encodeObject(metadata);
  const encodedUpdatedMetadata = await shareFolder({
    senderIdentity,
    senderSkPEM: aSkPEM,
    senderPkPEM: aPkPEM,
    receiverIdentity,
    receiverPkPEM: bPkPEM,
    metadataContent: encodedMetadata,
  });
  const updatedMetadata = await decodeObject<Metadata>(encodedUpdatedMetadata);
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

it('Decrypting an encrypted file gives back the original content.', async () => {
  const senderCertPEM = fs.readFileSync(
    path.join(__dirname, 'fixtures', 't_t_com', 'cert.pem')
  );
  const senderSkPEM = fs.readFileSync(
    path.join(__dirname, 'fixtures', 't_t_com', 'key.pem')
  );
  const email = parseEmailsFromCertificate(senderCertPEM.toString())[0];
  const senderPkPEM = await importECDHPublicKeyPEMFromCertificate(
    senderCertPEM
  );
  const senderIdentity = encodeIdentityAsMetadataMapKey(email);
  const fileName = 'TestFile.md';
  const fileId = '1';
  const fileStringContent = '# TEST FILE\nLorem ipsum.';
  const fileContent = new Buffer(fileStringContent);
  const metadataContent = await createEncodedInitialMetadataFile({
    senderIdentity,
    senderPkPEM,
  });
  const { metadataContent: updatedMetadata, fileCtxt } = await addFile({
    senderIdentity,
    senderCertPEM: senderCertPEM.toString(),
    senderSkPEM: senderSkPEM.toString(),
    fileName,
    file: fileContent,
    fileId,
    metadataContent,
  });
  const decryptedFile = await readFile({
    identity: senderIdentity,
    certPEM: senderCertPEM.toString(),
    skPEM: senderSkPEM.toString(),
    metadataContent: updatedMetadata,
    encryptedFileContent: fileCtxt,
    fileId,
  });
  expect(new Uint8Array(fileContent)).toStrictEqual(
    new Uint8Array(decryptedFile)
  );
  expect(arrayBuffer2string(decryptedFile)).toStrictEqual(fileStringContent);
});

it('After a file updload, the file metadata are written in the updated metadata', async () => {
  const senderCertPEM = fs.readFileSync(
    path.join(__dirname, 'fixtures', 't_t_com', 'cert.pem')
  );
  const senderSkPEM = fs.readFileSync(
    path.join(__dirname, 'fixtures', 't_t_com', 'key.pem')
  );
  const email = parseEmailsFromCertificate(senderCertPEM.toString())[0];
  const senderPkPEM = await importECDHPublicKeyPEMFromCertificate(
    senderCertPEM
  );
  const senderIdentity = encodeIdentityAsMetadataMapKey(email);
  const fileName = 'TestFile.md';
  const fileId = '1';
  const fileContent = new Buffer('# TEST FILE\nLorem ipsum.');
  const metadata = await createInitialMetadataFile({
    senderIdentity,
    senderPkPEM,
  });
  const metadataContent = await encodeObject<Metadata>(metadata);
  const { metadataContent: updatedMetadata } = await addFile({
    senderIdentity,
    senderCertPEM: senderCertPEM.toString(),
    senderSkPEM: senderSkPEM.toString(),
    fileName,
    file: fileContent,
    fileId,
    metadataContent,
  });
  const folderKey = await decryptFolderKey(
    {
      privateKey: await importECDHSecretKey(senderSkPEM),
      publicKey: await importECDHPublicKeyFromCertificate(senderCertPEM),
    },
    metadata.folderKeysByUser[encodeIdentityAsMetadataMapKey(email)]
  );
  const updatedMetadataObj = await decodeObject<Metadata>(updatedMetadata);
  const fileMetadata: FileMetadata = await decryptFileMetadata(
    await importAesGcmKey(folderKey),
    updatedMetadataObj.fileMetadatas[fileId],
    fileId
  );
  expect(fileMetadata).not.toBe(null);
  expect(fileMetadata).toHaveProperty('fileName');
  expect(fileMetadata.fileName).toStrictEqual(fileName);
});

it('cbor does not supports js Map', async () => {
  const a = new Map<string, string>();
  const b = { a: a };
  const s = await Encoder.encodeAsync(b);
  const d = (await Decoder.decodeFirst(s)) as { a: Map<string, string> };
  expect(d).not.toEqual(b);
});
