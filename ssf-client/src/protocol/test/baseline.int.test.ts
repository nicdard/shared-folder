import fs from 'fs';
import path from 'path';
import * as baseline from '../baseline';
import { parseEmailsFromCertificate } from 'common';
import {
  importECDHPublicKey,
  importECDHPublicKeyPEMFromCertificate,
  importECDHSecretKey,
} from '../commonCrypto';

it('Baseline: read metadata file from s3 works', async () => {
  const file = fs.readFileSync(
    path.join(__dirname, 'fixtures', 'metadata2users0Files')
  );
  const bytes = new Uint8Array(file);
  const tSkPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3vNjaEXtsmfVZpjF
C7dLg2ULZ3DTyVBSVB6J9nZVFUKhRANCAARQLfXZ0f//yRhx8ks672KdDELjqEcp
kUBHGS8Xnb8ymoMWYVPcVkYHzcIA5F9P92gXPBCAjHQmsK3Hgz0NdHAZ
-----END PRIVATE KEY-----
`;
  const tCert = `-----BEGIN CERTIFICATE-----
MIIBcTCCARegAwIBAgIUSOXdJ3+45XR0QUhr8Lm/iWBYPNgwCgYIKoZIzj0EAwIw
NjETMBEGA1UEAwwKRXhhbXBsZSBDQTEfMB0GA1UECgwWUnVzdGxzIFNlcnZlciBB
Y2NlcHRvcjAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0G
A1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABFAt9dnR///JGHHySzrvYp0MQuOoRymRQEcZLxedvzKagxZhU9xWRgfN
wgDkX0/3aBc8EICMdCawrceDPQ10cBmjFjAUMBIGA1UdEQQLMAmBB3RAdC5jb20w
CgYIKoZIzj0EAwIDSAAwRQIhALDgTVmPMKa6fNRqE9q3S+AuZQiQ+oCqfm6tjvOx
Off0AiA0WzpmAhkaoi4tpKPCZs9CgRFeFMi4dptIOXFl6qLIxA==
-----END CERTIFICATE-----
`;
  const t2SkPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga8b11OzMlhPUJCjE
1TG/dlFGI++NTo3iWZ6pijtuxTyhRANCAAQduG4MjGx+WzGWfRxPHOHU005Ye/Qr
L+l3qEMW53/c20sRT7EV3SUrXnN4G0rwyV4LOMsBJpVZ8D2QQ81PhNMU
-----END PRIVATE KEY-----`;
  const t2Cert = `-----BEGIN CERTIFICATE-----
MIIBczCCARigAwIBAgIUHX1vAEJCWH7+OkPgI5b2r4SgkpcwCgYIKoZIzj0EAwIw
NjETMBEGA1UEAwwKRXhhbXBsZSBDQTEfMB0GA1UECgwWUnVzdGxzIFNlcnZlciBB
Y2NlcHRvcjAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0G
A1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABB24bgyMbH5bMZZ9HE8c4dTTTlh79Csv6XeoQxbnf9zbSxFPsRXdJSte
c3gbSvDJXgs4ywEmlVnwPZBDzU+E0xSjFzAVMBMGA1UdEQQMMAqBCHQyQHQuY29t
MAoGCCqGSM49BAMCA0kAMEYCIQDtilzLNVobl844Ii8Sp5RTfSY4NWW848DEatjg
R6A2yAIhALlmYnGeoBo4o0Nzmji+T4eoe9I8yrjUNMbD8wtceNrp
-----END CERTIFICATE-----`;
  const metadata = await baseline.decodeObject<baseline.Metadata>(bytes);
  expect(Object.keys(metadata.fileMetadatas)).toHaveLength(0);
  expect(Object.keys(metadata.folderKeysByUser)).toHaveLength(2);
  const encryptedForT =
    metadata.folderKeysByUser[
      baseline.encodeIdentityAsMetadataMapKey(
        parseEmailsFromCertificate(tCert)[0]
      )
    ];
  const encryptedForT2 =
    metadata.folderKeysByUser[
      baseline.encodeIdentityAsMetadataMapKey(
        parseEmailsFromCertificate(t2Cert)[0]
      )
    ];
  const t2Pk = await importECDHPublicKey(
    await importECDHPublicKeyPEMFromCertificate(t2Cert)
  );
  const t2Sk = await importECDHSecretKey(t2SkPEM);
  const tPk = await importECDHPublicKey(
    await importECDHPublicKeyPEMFromCertificate(tCert)
  );
  const tSk = await importECDHSecretKey(tSkPEM);
  const folderKeyT2 = await baseline.decryptFolderKey(
    { publicKey: t2Pk, privateKey: t2Sk },
    encryptedForT2
  );
  const folderKeyT = await baseline.decryptFolderKey(
    { publicKey: tPk, privateKey: tSk },
    encryptedForT
  );
  expect(folderKeyT).toEqual(folderKeyT2);
});
