import { subtle } from 'crypto';
import { deriveAesGcmKey, string2ArrayBuffer } from '../../commonCrypto';
import { TreeSSKG } from '../treeSSKG';

it('A SSKG returns HKDF keys', async () => {
  const sskg = await TreeSSKG.genSSKG(16);
  const key = await sskg.getKey();
  expect(key.algorithm.name).toEqual('HKDF');
  expect(key.usages).toStrictEqual(['deriveKey', 'deriveBits']);
});

it('Seeking by n an SSKG equals to calling evolve n times (randomized over n)', async () => {
  const p = Math.random();
  const offset = Math.ceil(14 * p);
  const sskg = await TreeSSKG.genSSKG(16);
  const sskgSuperseek = sskg.clone('superseek');
  const sskgSeek = sskg.clone('seek');
  await sskgSuperseek.superseek(offset);
  await sskgSeek.seek(offset);
  for (let i = 0; i < offset; ++i) {
    await sskg.next();
  }
  await checkSSKGKeyEquality(sskg, sskgSuperseek);
  await checkSSKGKeyEquality(sskg, sskgSeek);
});

it('Seek by 10000 is equal to ten superseek by 1000', async () => {
  const sskg = await TreeSSKG.genSSKG(Math.pow(2, 32));
  const sskgClone = sskg.clone('clone');
  await sskg.seek(10000);
  for (let i = 0; i < 10; ++i) {
    await sskgClone.superseek(1000);
  }
  await checkSSKGKeyEquality(sskg, sskgClone);
});

it('Seeking multiple times corresponds to evolving each offset and seeking the total amount (randomized)', async () => {
  const sskg = await TreeSSKG.genSSKG(Math.pow(2, 32));
  const sskgSuperseek = sskg.clone('superseek');
  const sskgSeek = sskg.clone('seek');
  let total = 0;
  for (let i = 1; i < 10; ++i) {
    const p = Math.random();
    const offset = Math.ceil(998 * p);
    total += offset;
    await sskgSuperseek.superseek(offset);
    for (let i = 0; i < offset; i++) {
      await sskg.next();
    }
    await checkSSKGKeyEquality(sskg, sskgSuperseek);
  }
  await sskgSeek.seek(total);
  await checkSSKGKeyEquality(sskg, sskgSeek);
});

it('Serialize and deserialize return the same SSGK', async () => {
  const sskg = await TreeSSKG.genSSKG(Math.pow(2, 32));
  const serialized = await sskg.serialize();
  const deserialized = await TreeSSKG.deserialize(serialized);
  expect(sskg.name).toEqual(deserialized.name);
  await checkSSKGKeyEquality(sskg, deserialized);
  await sskg.superseek(1000);
  await deserialized.superseek(1000);
  await checkSSKGKeyEquality(sskg, deserialized);
  const serialized2 = await sskg.serialize();
  const deserialized2 = await TreeSSKG.deserialize(serialized2);
  await checkSSKGKeyEquality(sskg, deserialized2);
});

/**
 * The {@link TreeSSKG} getKey operation returns an HKDF key.
 * Those keys cannot be extracted and thus compared.
 * Therefore we generate an AES key from the HKDF key and compare that one, given the same salt and label.
 */
async function checkSSKGKeyEquality(sskg: TreeSSKG, sskgClone: TreeSSKG) {
  const hkdfKey = await sskg.getKey();
  const hkdfKeyClone = await sskgClone.getKey();
  const salt = new Uint8Array();
  const label = string2ArrayBuffer('test');
  const aesKey = await deriveAesGcmKey({ k: hkdfKey, salt, label });
  const aesKeyClone = await deriveAesGcmKey({ k: hkdfKeyClone, salt, label });
  const rawAesKey = await subtle.exportKey('raw', aesKey);
  const rawAesKeyClone = await subtle.exportKey('raw', aesKeyClone);
  expect(rawAesKey).toStrictEqual(rawAesKeyClone);
}
