import { subtle } from '../../commonCrypto';
import { KaPPA } from '../kappa';
import { BlockType, DoubleChainsInterval, EpochInterval, KP } from '../kp';

it('Asking for a key outside the epoch range throws an error', async () => {
  const kappa = await KaPPA.init(1024);
  await expect(kappa.getKey(3)).rejects.toThrow();
});

it('Creating an interval or an extension out of bound should throw', async () => {
  const kappa = await KaPPA.init(1024);
  await expect(kappa.getInterval({ left: 0, right: 2 })).rejects.toThrow();
  await expect(kappa.createExtension({ left: 0, right: 2 })).rejects.toThrow();
  await expect(kappa.getInterval({ left: 2, right: 0 })).rejects.toThrow();
  await expect(kappa.createExtension({ left: 2, right: 0 })).rejects.toThrow();
});

it.each<[BlockType, string]>([
  [BlockType.EMPTY, 'epsilon-block'],
  [BlockType.FULL_BLOCK, '||-block'],
  [BlockType.FORWARD_BLOCK, '<-block'],
  [BlockType.BACKWARD_BLOCK, '>-block'],
])(
  'An interval + an extension (from a progression using (%i) %s) should derive same keys as the original chains for the total covered epoch interval',
  async (blockType, blockName) => {
    const kappa = await KaPPA.init(100);
    for (let i = 0; i < 1000; ++i) {
      await kappa.progress(blockType);
    }
    let interval = await kappa.getInterval({ left: 0, right: 0 });
    for (let i = 1; i < 25; ++i) {
      const offset = interval.epochs.right + 1;
      const extension = await kappa.createExtension({
        left: offset,
        right: offset + i,
      });
      const compoundExtension = KaPPA.processExtension(interval, extension);
      interval = compoundExtension;
      expect(compoundExtension.epochs).toStrictEqual({
        left: 0,
        right: extension.epochs.right,
      });
      await checkInterval(kappa, compoundExtension);
    }
  }
);

it('A KaPPA instance and its deserialized version (after serialization) give the same key.', async () => {
  const kappa = await KaPPA.init(1024);
  const serialized = await kappa.serialize();
  const deserialized = await KaPPA.deserialize(serialized);
  const epochInterval = { left: 0, right: 0 };
  const interval = await kappa.getInterval(epochInterval);
  const intervalFromDeserialized = await deserialized.getInterval(
    epochInterval
  );
  expect(interval.epochs).toStrictEqual(intervalFromDeserialized.epochs);
});

it('A KaPPA instance which progresses to a new epoch should still give the same key afterwards for the same epochs.', async () => {
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

type ProgressWithUniqueBlockDataSet = [BlockType, string, number, number];

it.each<ProgressWithUniqueBlockDataSet>([
  [BlockType.EMPTY, 'epsilon-block', 4, 4],
  [BlockType.FULL_BLOCK, '||-block', 1025, 1025],
  [BlockType.FORWARD_BLOCK, '<-block', 1025, 4],
  [BlockType.BACKWARD_BLOCK, '>-block', 4, 1025],
])(
  'Progressing only with (%i) %s should create %i forward chains and %i backward chains.',
  async (blockType, _, expectedForawrdChains, expectedBackwardChains) => {
    const kappa: KP = await KaPPA.init(256);
    for (let i = 0; i < 1024; ++i) {
      await kappa.progress(blockType);
    }
    const epochInterval = { left: 0, right: 1024 };
    const interval = await kappa.getInterval(epochInterval);
    expect(interval.backwardChainsInterval).toHaveLength(
      expectedBackwardChains
    );
    expect(interval.forwardChainsInterval).toHaveLength(expectedForawrdChains);
    expect(interval.epochs).toStrictEqual(epochInterval);
  }
);

it.each<[BlockType, string]>([
  [BlockType.EMPTY, 'epsilon-block'],
  [BlockType.FULL_BLOCK, '||-block'],
  [BlockType.FORWARD_BLOCK, '<-block'],
  [BlockType.BACKWARD_BLOCK, '>-block'],
])(
  'A KaPPA schedule progressing only with (%i) %s should give same keys for the entire extracted interval as the original chains.',
  async (blockType) => {
    const kappa: KP = await KaPPA.init(256);
    for (let i = 0; i < 1024; ++i) {
      await kappa.progress(blockType);
    }
    const epochInterval = { left: 0, right: 1024 };
    const interval = await kappa.getInterval(epochInterval);
    const interval2 = await kappa.getInterval(epochInterval);
    for (let epoch = 0; epoch < 1024; ++epoch) {
      const key = await kappa.getKey(epoch);
      // Verify operations are idempotent as well.
      const keyClone = await kappa.getKey(epoch);
      const keyFromInterval = await KaPPA.getKey(epoch, interval);
      const keyFromInterval2 = await KaPPA.getKey(epoch, interval2);
      await checkKeyEquality(key, keyClone);
      await checkKeyEquality(key, keyFromInterval);
      await checkKeyEquality(key, keyFromInterval2);
    }
  }
);

it('Idempotency of GetKey on extracted intervals or on internal state, with different key schedule progressions', async () => {
  const maximumIntervalLengthWithoutBlocks = 1024;
  const kappa: KP = await KaPPA.init(maximumIntervalLengthWithoutBlocks);
  const blockTypes = [
    BlockType.EMPTY,
    BlockType.BACKWARD_BLOCK,
    BlockType.EMPTY,
    BlockType.FORWARD_BLOCK,
    BlockType.EMPTY,
    BlockType.FULL_BLOCK,
    BlockType.EMPTY,
    BlockType.BACKWARD_BLOCK,
    BlockType.FORWARD_BLOCK,
    BlockType.BACKWARD_BLOCK,
    BlockType.FULL_BLOCK,
    BlockType.BACKWARD_BLOCK,
    BlockType.FORWARD_BLOCK,
    BlockType.FULL_BLOCK,
    BlockType.FORWARD_BLOCK,
  ];
  const epochPerBlockType = 10;
  for (const block of blockTypes) {
    for (let i = 0; i < epochPerBlockType; i++) {
      await kappa.progress(block);
    }
  }
  const totalEpochs = blockTypes.length * epochPerBlockType;
  expect(totalEpochs < maximumIntervalLengthWithoutBlocks);
  const check = checkExportedEpochInterval(kappa);
  await Promise.all(
    Array.from({ length: totalEpochs - 1 }, (_, index) => index + 1).map(
      (left) => check({ left, right: totalEpochs })
    )
  );
  await Promise.all(
    Array.from({ length: totalEpochs - 1 }, (_, index) => index + 1)
      .reverse()
      .map((right) => check({ left: 0, right }))
  );
});

it('An extracted interval (either from GetInterval or GetInterval + Extensions) should give the same keys for the same epochs as the original long chain (randomized).', async () => {
  const kappa: KP = await KaPPA.init(1024);
  for (let i = 0; i < 1000; ++i) {
    const p = Math.random();
    const blockType = probabilityToBlockType(p);
    await kappa.progress(blockType);
  }
  const i1 = Math.random();
  const i2 = Math.random();
  const i3 = Math.random();
  const epochInterval1: EpochInterval = {
    left: Math.floor(i1 * 10),
    right: Math.floor(i2 * 1000),
  };
  const epochInterval2: EpochInterval = {
    left: Math.floor(i2 * 10),
    right: Math.floor(i3 * 1000),
  };
  const checkIntervalFromEpochInterval = checkExportedEpochInterval(kappa);
  await checkIntervalFromEpochInterval(epochInterval1);
  await checkIntervalFromEpochInterval(epochInterval2);
  const midInterval1 = Math.floor(epochInterval1.right / 2);
  const halfInterval1 = await kappa.getInterval({
    ...epochInterval1,
    right: midInterval1,
  });
  const extension = await kappa.createExtension({
    ...epochInterval1,
    left: midInterval1 + 1,
  });
  const compoundInterval1 = KaPPA.processExtension(halfInterval1, extension);
  expect(compoundInterval1.epochs).toStrictEqual(epochInterval1);
  await checkInterval(kappa, compoundInterval1);
});

const checkExportedEpochInterval =
  (kappa: KP) => async (epochInterval: EpochInterval) => {
    const interval = await kappa.getInterval(epochInterval);
    await checkInterval(kappa, interval);
  };

const checkInterval = async (kappa: KP, interval: DoubleChainsInterval) => {
  for (
    let epoch = interval.epochs.left;
    epoch <= interval.epochs.right;
    ++epoch
  ) {
    const keyFromInterval = await KaPPA.getKey(epoch, interval);
    const keyFromInternalState = await kappa.getKey(epoch);
    // console.log(epoch, interval, kappa);
    await checkKeyEquality(keyFromInternalState, keyFromInterval);
  }
};

function probabilityToBlockType(p: number): BlockType {
  if (p < 0.25) {
    return BlockType.FULL_BLOCK;
  } else if (p >= 0.25 && p < 0.5) {
    return BlockType.FORWARD_BLOCK;
  } else if (p >= 0.5 && p < 0.75) {
    return BlockType.BACKWARD_BLOCK;
  } else {
    return BlockType.EMPTY;
  }
}

function exportKeyToRaw(key: CryptoKey): Promise<ArrayBuffer> {
  return subtle.exportKey('raw', key);
}

async function checkKeyEquality(key1: CryptoKey, key2: CryptoKey) {
  const key1Raw = await exportKeyToRaw(key1);
  const key2Raw = await exportKeyToRaw(key2);
  // console.log(key1Raw, key2Raw);
  expect(key1Raw).toStrictEqual(key2Raw);
}
