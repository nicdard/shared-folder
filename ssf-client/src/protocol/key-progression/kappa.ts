import { deriveAesGcmKey, string2ArrayBuffer } from '../commonCrypto';
import { doublePRFderiveKeyFromRaw } from '../doubleprf/hmacDoublePrf';
import { decodeObject, encodeObject } from '../marshaller';
import { TreeSSKG } from '../sskg/treeSSKG';
import {
  BackwardChain,
  BlockType,
  DoubleChainsInterval,
  Epoch,
  EpochInterval,
  ForwardChain,
  KP,
} from './kp';

const KAPPA_LABEL = string2ArrayBuffer('KAPPA');

/**
 * A serialized forward chain, the buffer is a the {@link SSKG} serialized.
 */
type ForwardChainData = [Epoch, Buffer];
/**
 * A serialized backward chain, the buffer is the {@link SSKG} serialized.
 */
type BackwardChainData = [Epoch, Buffer, number];

/**
 * Visible for testing.
 * The format of a serialized KaPPA instance.
 */
export interface KaPPAData {
  readonly forwardChainsData: Array<ForwardChainData>;
  readonly backwardChainsData: Array<BackwardChainData>;
  readonly maxEpoch: Epoch;
  readonly maximumIntervalLengthWithoutBlocks: number;
}

/**
 * Represents an exported {@link DoubleChainsInterval}.
 * This is useful to share data with clients that should not
 * be able to generate new epoch secrets (non-admins).
 */
export interface KaPPAExportedData {
  readonly forwardChainsData: Array<ForwardChainData>;
  readonly backwardChainsData: Array<BackwardChainData>;
  readonly epochs: EpochInterval;
}

export class KaPPA implements KP {
  private forwardChains: Array<ForwardChain> = [];
  private backwardChains: Array<BackwardChain> = [];
  private maxEpoch: Epoch; // 2^53 - 1 is the maximum safe integer, but this is 285 million years if we change keys every seconds. 

  private constructor(
    private readonly maximumIntervalLengthWithoutBlocks: number // private readonly keyLength: number we do not really use the keyLength.
  ) {
    this.maxEpoch = -1;
  }

  public getMaxEpoch(): Epoch {
    return this.maxEpoch;
  }

  // In the paper, those are parameters to the scheme `N` and `kl`.
  public static async init(
    maximumIntervalLengthWithoutBlocks: number
    // keyLength: number
  ): Promise<KaPPA> {
    const kappa = new KaPPA(maximumIntervalLengthWithoutBlocks /*keyLength*/);
    await kappa.progress(BlockType.FULL_BLOCK);
    return kappa;
  }

  public async progress(block: BlockType): Promise<void> {
    const [eFs] =
      this.forwardChains.length > 0
        ? this.forwardChains[this.forwardChains.length - 1]
        : [0];
    const [eBs] =
      this.backwardChains.length > 0
        ? this.backwardChains[this.backwardChains.length - 1]
        : [0];
    this.maxEpoch++;
    /* Create a new forward chain if either:
        - 1: the block requires it
        - 2: the maximum interval of epochs without blocks is reached for the forward ones (calculate offset).
        */
    if (
      block == BlockType.FULL_BLOCK ||
      block == BlockType.FORWARD_BLOCK ||
      this.maxEpoch > eFs + this.maximumIntervalLengthWithoutBlocks
    ) {
      this.forwardChains.push([
        this.maxEpoch,
        await TreeSSKG.genSSKG(
          this.maximumIntervalLengthWithoutBlocks,
          'forward:' + this.maxEpoch.toString()
        ),
      ]);
    }
    /* Create a new backward chain if either:
        - 1: the block requires it
        - 2: the maximum interval of epochs without blocks for the backwards ones is reached (calculate offset).
         */
    if (
      block == BlockType.FULL_BLOCK ||
      block == BlockType.BACKWARD_BLOCK ||
      this.maxEpoch > eBs + this.maximumIntervalLengthWithoutBlocks
    ) {
      // Shorten the current chain to used keys
      this.backwardChains = await this.getBSeeds({
        left: 0,
        right: this.maxEpoch,
      });
      // move to new backward chain
      this.backwardChains.push([
        this.maxEpoch,
        await TreeSSKG.genSSKG(
          this.maximumIntervalLengthWithoutBlocks,
          'back:' + this.maxEpoch.toString()
        ),
        this.maximumIntervalLengthWithoutBlocks,
      ]);
    }
  }

  public async getInterval(
    interval: EpochInterval
  ): Promise<DoubleChainsInterval> {
    if (
      interval.left < 0 ||
      interval.right > this.maxEpoch ||
      interval.left > interval.right
    ) {
      throw new Error(
        'Precondition failed, the interval should be within bounds and left <= right should hold.'
      );
    }
    const forwardChainsInterval = await this.getFSeeds(interval);
    const backwardChainsInterval = await this.getBSeeds(interval);
    return { forwardChainsInterval, backwardChainsInterval, epochs: interval };
  }

  public async createExtension(
    interval: EpochInterval
  ): Promise<DoubleChainsInterval> {
    if (
      interval.left < 0 ||
      interval.right > this.maxEpoch ||
      interval.left > interval.right
    ) {
      throw new Error(
        'Precondition failed, the interval should be within bounds and left <= right should hold.'
      );
    }
    const extension = await this.getInterval(interval);
    // Reuse the old forward chain if it can derive the key at l.
    const existLeftInF = this.forwardChains.some(([e]) => e == interval.left);
    if (!existLeftInF) {
      extension.forwardChainsInterval.shift();
    }

    return extension;
  }

  /**
   * @param interval an interval to be extended
   * @param extension an extension calculated with {@link createExtension}. This should start at the same epoch + 1 as the interval ends.
   * @returns an interval {@link DoubleChainsInterval} containing the concatenation of the interval and the extension.
   */
  public static processExtension(
    interval: DoubleChainsInterval,
    extension: DoubleChainsInterval
  ): DoubleChainsInterval {
    if (interval.epochs.right + 1 != extension.epochs.left) {
      throw new Error(
        'The interval cannot be extended with the provided extension!'
      );
    }
    interval.forwardChainsInterval = interval.forwardChainsInterval.concat(
      extension.forwardChainsInterval
    );
    const [e] =
      interval.backwardChainsInterval[
        interval.backwardChainsInterval.length - 1
      ];
    const [e1] = extension.backwardChainsInterval[0];
    // reuse old backward chain if it can derive key at r
    if (e == e1) {
      interval.backwardChainsInterval.pop();
    }
    interval.backwardChainsInterval = interval.backwardChainsInterval.concat(
      extension.backwardChainsInterval
    );
    interval.epochs.right = extension.epochs.right;
    return interval;
  }

  public static async getKey(
    epoch: number,
    interval: DoubleChainsInterval
  ): Promise<CryptoKey> {
    if (epoch < interval.epochs.left || epoch > interval.epochs.right) {
      throw new Error('Epoch is out of bound.');
    }
    const forwardChains = await this.getFSeeds(
      { left: epoch, right: epoch },
      interval.forwardChainsInterval
    );
    if (forwardChains.length < 1) {
      throw new Error('Internal error');
    }
    const backwardChains = await this.getBSeeds(
      { left: epoch, right: epoch },
      interval.backwardChainsInterval
    );
    if (backwardChains.length < 1) {
      throw new Error('Internal error');
    }
    const [, fs] = forwardChains[forwardChains.length - 1];
    // This is already at the correct position, as we call superseek internally in getFSeeds.
    const fk = await fs.getRawKey();
    const [, bs] = backwardChains[backwardChains.length - 1];
    // This is already at the correct position, as we call superseek internally in getBSeeds.
    const bk = await bs.getRawKey();
    // console.log(fs, bs, fk, bk);
    if (fk.byteLength != bk.byteLength) {
      throw new Error('Incompatible lengths!');
    }
    const k = await doublePRFderiveKeyFromRaw(fk, bk);
    return deriveAesGcmKey({ k, salt: new Uint8Array(), label: KAPPA_LABEL });
  }

  public async getKey(epoch: number): Promise<CryptoKey> {
    // This should return the key for the last element.
    const interval = await this.getInterval({ left: 0, right: this.maxEpoch });
    return KaPPA.getKey(epoch, interval);
  }

  /**
   * @param forwardChains the interval of forward chains where to apply the update.
   * @returns the interval with the modification performed in place. The SSKG will not be seeked directly, but first it will be cloned.
   */
  private static async updateFChainsInterval(
    { left }: EpochInterval,
    forwardChains: Array<ForwardChain>
  ): Promise<Array<ForwardChain>> {
    const [ei, sskgi] = forwardChains[0];
    const sskgClone = sskgi.clone();
    await sskgClone.superseek(left - ei);
    forwardChains[0] = [left, sskgClone];
    return forwardChains;
  }

  /**
   *
   * @param backwardChains the interval of backward chains where to apply the update.
   * @returns the interval with the modification performed in place. The SSKG will not be seeked directly, but first it will be cloned.
   */
  private static async updateBChainsInterval(
    { right }: EpochInterval,
    backwardChains: Array<BackwardChain>
  ): Promise<Array<BackwardChain>> {
    if (backwardChains.length > 0) {
      const [ej, sskgj, nj] = backwardChains[backwardChains.length - 1];
      const shortenedNj = right - ej + 1;
      const sskgClone = sskgj.clone();
      await sskgClone.superseek(nj - shortenedNj);
      backwardChains[backwardChains.length - 1] = [ej, sskgClone, shortenedNj];
    }
    return backwardChains;
  }

  private getFSeeds(interval: EpochInterval): Promise<Array<ForwardChain>> {
    return KaPPA.getFSeeds(interval, this.forwardChains);
  }

  private static getFSeeds(
    interval: EpochInterval,
    forwardChains: Array<ForwardChain>
  ): Promise<Array<ForwardChain>> {
    const i = KaPPA.search(
      forwardChains,
      0,
      forwardChains.length - 1,
      interval.left
    );
    const j = KaPPA.search(
      forwardChains,
      0,
      forwardChains.length - 1,
      interval.right
    );
    const chainsInterval = forwardChains.slice(i, j + 1);
    return KaPPA.updateFChainsInterval(interval, chainsInterval);
  }

  private getBSeeds(interval: EpochInterval): Promise<Array<BackwardChain>> {
    return KaPPA.getBSeeds(interval, this.backwardChains);
  }

  private static getBSeeds(
    interval: EpochInterval,
    backwardChains: Array<BackwardChain>
  ): Promise<Array<BackwardChain>> {
    if (backwardChains.length == 0) {
      return Promise.resolve(backwardChains);
    }
    const i = KaPPA.search(
      backwardChains,
      0,
      backwardChains.length - 1,
      interval.left
    );
    const j = KaPPA.search(
      backwardChains,
      0,
      backwardChains.length - 1,
      interval.right
    );
    const chainsInterval = backwardChains.slice(i, j + 1);
    return KaPPA.updateBChainsInterval(interval, chainsInterval);
  }

  public async serialize(): Promise<Buffer> {
    const forwardChainsData = await Promise.all(
      this.forwardChains.slice().map(async ([e, sskg]) => {
        const data: ForwardChainData = [e, await sskg.serialize()];
        return data;
      })
    );
    const backwardChainsData = await Promise.all(
      this.backwardChains.slice().map(async ([e, sskg, N]) => {
        const data: BackwardChainData = [e, await sskg.serialize(), N];
        return data;
      })
    );
    const kappaData: KaPPAData = {
      maxEpoch: this.maxEpoch,
      maximumIntervalLengthWithoutBlocks:
        this.maximumIntervalLengthWithoutBlocks,
      forwardChainsData,
      backwardChainsData,
    };
    return await encodeObject<KaPPAData>(kappaData);
  }

  public static async deserialize(encoded: Buffer): Promise<KaPPA> {
    const {
      maxEpoch,
      maximumIntervalLengthWithoutBlocks,
      forwardChainsData,
      backwardChainsData,
    } = await decodeObject<KaPPAData>(encoded);
    const forwardChains = await KaPPA.deserializeForwardChainData(forwardChainsData);
    const backwardChains = await KaPPA.deserializeBackwardChainData(backwardChainsData);
    const kappa = new KaPPA(maximumIntervalLengthWithoutBlocks);
    kappa.maxEpoch = maxEpoch;
    kappa.backwardChains = backwardChains;
    kappa.forwardChains = forwardChains;
    return kappa;
  }

  public static async serializeExported(interval: DoubleChainsInterval): Promise<Buffer> {
    const forwardChainsData = await Promise.all(
      interval.forwardChainsInterval.slice().map(async ([e, sskg]) => {
        const data: ForwardChainData = [e, await sskg.serialize()];
        return data;
      })
    );
    const backwardChainsData = await Promise.all(
      interval.backwardChainsInterval.slice().map(async ([e, sskg, N]) => {
        const data: BackwardChainData = [e, await sskg.serialize(), N];
        return data;
      })
    );
    const kappaExportedData: KaPPAExportedData = {
      forwardChainsData,
      backwardChainsData,
      epochs: interval.epochs,
    };
    return encodeObject<KaPPAExportedData>(kappaExportedData);
  }

  public static async deserializeExported(encoded: Buffer): Promise<DoubleChainsInterval> {
    const {
      epochs,
      forwardChainsData,
      backwardChainsData,
    } = await decodeObject<KaPPAExportedData>(encoded);
    const forwardChainsInterval = await KaPPA.deserializeForwardChainData(forwardChainsData);
    const backwardChainsInterval = await KaPPA.deserializeBackwardChainData(backwardChainsData);
    const doubleChainsInterval: DoubleChainsInterval = {
      epochs,
      forwardChainsInterval,
      backwardChainsInterval,
    };
    return doubleChainsInterval;
  }

  private static async deserializeForwardChainData(forwardChainsData: ForwardChainData[]): Promise<ForwardChain[]> {
    const forwardChainsInterval = await Promise.all(
      forwardChainsData.map(async ([e, sskgData]) => {
        const forwardChain: ForwardChain = [
          e,
          await TreeSSKG.deserialize(sskgData),
        ];
        return forwardChain;
      })
    );
    return forwardChainsInterval;
  }

  private static async deserializeBackwardChainData(backwardChainsData: BackwardChainData[]): Promise<BackwardChain[]> {
    const backwardChainsInterval = await Promise.all(
      backwardChainsData.map(async ([e, sskgData, N]) => {
        const backwardChain: BackwardChain = [
          e,
          await TreeSSKG.deserialize(sskgData),
          N,
        ];
        return backwardChain;
      })
    );
    return backwardChainsInterval;
  }

  private static search<T extends [Epoch, ...unknown[]]>(
    chain: T[],
    start: number,
    end: number,
    epoch: Epoch
  ): number {
    if (start == end) return chain[start][0] <= epoch ? start : -1;
    const mid = start + Math.floor((end - start) / 2);
    if (epoch < chain[mid][0])
      return KaPPA.search(chain, start, mid, epoch);
    const ret = KaPPA.search(chain, mid + 1, end, epoch);
    return ret == -1 ? mid : ret;
  }
}
