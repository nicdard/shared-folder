import { subtle } from '../../commonCrypto';
import { KaPPA } from '../kappa';
import { BlockType } from '../kp';

it('A KaPPA instance and its deserialized version (after serialization) give the same key', async () => {
  const kappa = await KaPPA.init(1024);
  const serailized = await kappa.serialize();
  const deserialized = await KaPPA.deserialize(serailized);
  const epochInterval = { left: 0, right: 0 };
  const interval = await kappa.getInterval(epochInterval);
  const intervalFromDeserialized = await deserialized.getInterval(
    epochInterval
  );
  expect(interval.epochs).toStrictEqual(intervalFromDeserialized.epochs);
});

it('A KaPPA instance which progresses to a new epoch should still give the same key afterwards for the same epochs', async () => {
  const kappa = await KaPPA.init(1000);
  expect(kappa.getMaxEpoch()).toEqual(0);
  const keyAt0 = await kappa.getKey(0);
  await kappa.progress(BlockType.EMPTY);
  expect(kappa.getMaxEpoch()).toEqual(1);
  const keyAt1 = await kappa.getKey(1);
  await kappa.progress(BlockType.FORWARD_BLOCK);
  const keyAt2 = await kappa.getKey(2);
  await kappa.progress(BlockType.BACKWARD_BLOCK);
  const keyAt3 = await kappa.getKey(3);
  await kappa.progress(BlockType.FULL_BLOCK);
  const keyAt4 = await kappa.getKey(4);
  await kappa.progress(BlockType.FULL_BLOCK);
  const keyAt0copy = await kappa.getKey(0);
  const keyAt1copy = await kappa.getKey(1);
  const keyAt2copy = await kappa.getKey(2);
  const keyAt3copy = await kappa.getKey(3);
  const keyAt4copy = await kappa.getKey(4);
  await checkKeyEquality(keyAt0, keyAt0copy);
  await checkKeyEquality(keyAt1, keyAt1copy);
  await checkKeyEquality(keyAt2, keyAt2copy);
  await checkKeyEquality(keyAt3, keyAt3copy);
  await checkKeyEquality(keyAt4, keyAt4copy);
});

function exportKeyToRaw(key: CryptoKey): Promise<ArrayBuffer> {
  return subtle.exportKey('raw', key);
}

async function checkKeyEquality(key1: CryptoKey, key2: CryptoKey) {
  const key1Raw = await exportKeyToRaw(key1);
  const key2Raw = await exportKeyToRaw(key2);
  expect(key1Raw).toStrictEqual(key2Raw);
}
