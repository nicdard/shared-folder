import { generateEphemeralKeyPair, string2ArrayBuffer } from '../commonCrypto';
import { kemKdfDecap, kemKdfEncap } from '../kemKdf';

it('KEM+KDF encap and decap derive the same key', async () => {
  const KEM_KDF_TEST_LABEL = string2ArrayBuffer('KDF_KDF_TEST');
  const a = await generateEphemeralKeyPair();
  const encapResult = await kemKdfEncap(a.publicKey, KEM_KDF_TEST_LABEL);
  const decapsulated = await kemKdfDecap(a, encapResult.c, KEM_KDF_TEST_LABEL);
  expect(encapResult.k).toStrictEqual(decapsulated);
});
