import { deriveAesGcmKey, string2ArrayBuffer } from '../commonCrypto';
import { doublePRFderiveKeyFromRaw } from '../doubleprf/hmacDoublePrf';
import { decodeObject, encodeObject } from '../marshaller';
import { TreeSSKG } from '../sskg/treeSSKG';
import {
  BackwardChain,
  BlockType,
  ChainsInterval,
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

export class KaPPA implements KP {
  private forwardChains: Array<ForwardChain> = [];
  private backwardChains: Array<BackwardChain> = [];
  private maxEpoch: Epoch;

  private constructor(
    private readonly maximumIntervalLengthWithoutBlocks: number
  ) // private readonly keyLength: number we do not really use the keyLength.
  {
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
      this.backwardChains = (
        await this.getBSeeds({
          left: 0,
          right: this.maxEpoch,
        })
      ).slice;
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
    const existLeftInF = extension.forwardChainsInterval.slice.some(([e]) => {
      e == interval.left;
    });
    if (!existLeftInF) {
      extension.forwardChainsInterval.interval = [
        extension.forwardChainsInterval.interval[0],
        extension.forwardChainsInterval.interval[1] - 1,
      ];
      extension.forwardChainsInterval.slice.shift();
    }

    return extension;
  }

  processExtension(
    interval: DoubleChainsInterval,
    extension: DoubleChainsInterval
  ): DoubleChainsInterval {
    if (interval.epochs.right + 1 != extension.epochs.left) {
      throw new Error('An interval can be extended ');
    }
    interval.forwardChainsInterval.slice =
      interval.forwardChainsInterval.slice.concat(
        extension.forwardChainsInterval.slice
      );
    const [e] =
      interval.backwardChainsInterval.slice[
        interval.backwardChainsInterval.slice.length - 1
      ];
    const [e1] = extension.backwardChainsInterval.slice[0];
    if (e == e1) {
      interval.backwardChainsInterval.slice =
        interval.backwardChainsInterval.slice.slice(0, -1);
    }
    interval.backwardChainsInterval.slice =
      interval.backwardChainsInterval.slice.concat(
        extension.backwardChainsInterval.slice
      );
    interval.epochs.right = extension.epochs.right;
    return interval;
  }

  public async getKey(
    epoch: number,
    interval: DoubleChainsInterval
  ): Promise<CryptoKey>;
  public async getKey(epoch: number): Promise<CryptoKey>;
  public async getKey(
    epoch: number,
    interval?: DoubleChainsInterval
  ): Promise<CryptoKey> {
    if (interval == null) {
      // This should return the key for the last element.
      interval = await this.getInterval({ left: 0, right: this.maxEpoch });
    }
    if (epoch < interval.epochs.left || epoch > interval.epochs.right) {
      throw new Error('Epoch is out of bound.');
    }
    const forwardChains = await this.getFSeeds(
      { left: epoch, right: epoch },
      interval.forwardChainsInterval
    );
    if (forwardChains.slice.length < 1) {
      throw new Error('Internal error');
    }
    const backwardChains = await this.getBSeeds(
      { left: epoch, right: epoch },
      interval.backwardChainsInterval
    );
    if (backwardChains.slice.length < 1) {
      throw new Error('Internal error');
    }
    const [, fs] = forwardChains.slice[forwardChains.slice.length - 1];
    // This is already at the correct position, as we call superseek internally in getFSeeds.
    const fk = await fs.getRawKey();
    const [, bs] = backwardChains.slice[backwardChains.slice.length - 1];
    // This is already at the correct position, as we call superseek internally in getBSeeds.
    const bk = await bs.getRawKey();
    if (fk.byteLength != bk.byteLength) {
      throw new Error('Incompatible lengths!');
    }
    // We use the sign algorithm to combine forward and backward key
    // the signature is used as a key for HKDF to then derive the final AES-GCM key.
    const k = await doublePRFderiveKeyFromRaw(fk, bk);
    return deriveAesGcmKey({ k, salt: new Uint8Array(), label: KAPPA_LABEL });
  }

  /**
   * @param forwardChains the interval of forward chains where to apply the update.
   * @returns the interval with the modification performed in place. The SSKG will not be seeked directly, but first it will be cloned.
   */
  private async updateFChainsInterval(
    forwardChains: ChainsInterval<ForwardChain>
  ): Promise<ChainsInterval<ForwardChain>> {
    const [i] = forwardChains.interval;
    const [ei, sskgi] = forwardChains.slice[0];
    const sskgClone = sskgi.clone();
    await sskgClone.superseek(i - ei);
    forwardChains.slice[0] = [ei, sskgClone];
    return forwardChains;
  }

  /**
   *
   * @param backwardChains the interval of backward chains where to apply the update.
   * @returns the interval with the modification performed in place. The SSKG will not be seeked directly, but first it will be cloned.
   */
  private async updateBChainsInterval(
    backwardChains: ChainsInterval<BackwardChain>
  ): Promise<ChainsInterval<BackwardChain>> {
    if (backwardChains.slice.length > 0) {
      const [, j] = backwardChains.interval;
      const [ej, sskgj, nj] =
        backwardChains.slice[backwardChains.slice.length - 1];
      const shortenedNj = j - ej + 1;
      const sskgClone = sskgj.clone();
      await sskgClone.superseek(nj - shortenedNj);
      backwardChains.slice[backwardChains.slice.length - 1] = [
        ej,
        sskgClone,
        shortenedNj,
      ];
    }
    return backwardChains;
  }

  private getFSeeds(
    interval: EpochInterval,
    forwardChains?: ChainsInterval<ForwardChain>
  ): Promise<ChainsInterval<ForwardChain>> {
    if (forwardChains == null) {
      forwardChains = {
        interval: [0, this.forwardChains.length - 1],
        // Don't need to slice here, we do it in the end.
        slice: this.forwardChains,
      };
    }
    const chainsInterval = forwardChains.slice.reduce(
      (p, el, index) => {
        const [ei] = el;
        if (ei <= interval.left && ei <= interval.right) {
          p.slice.push(el);
          p.interval[0] = Math.min(
            p.interval[0],
            index + forwardChains.interval[0]
          );
          p.interval[1] = Math.max(
            p.interval[1],
            index + forwardChains.interval[0]
          );
        }
        return p;
      },
      {
        interval: [this.backwardChains.length, 0],
        slice: [],
      } as ChainsInterval<ForwardChain>
    );
    return this.updateFChainsInterval(chainsInterval);

    /*const lastIndex = forwardChains.interval[1];
    // When applying binary search, we need to use the original sequence, as indexes are referring to it and not the slice.
    const i = KaPPA.binarySearch(
      this.forwardChains,
      forwardChains.interval[0],
      lastIndex,
      interval.left
    ) ?? forwardChains.interval[0];
    if (lastIndex >= 0) {
      const j = KaPPA.binarySearch(
        this.forwardChains,
        i,
        lastIndex,
        interval.right
      ) ?? lastIndex;
      const chainsInterval: ChainsInterval<ForwardChain> = {
        interval: [i, j],
        slice: this.forwardChains.slice(i, j + 1),
      };
      return this.updateFChainsInterval(chainsInterval);
    } else {
      return forwardChains;
    }
    */
  }

  private getBSeeds(
    interval: EpochInterval,
    backwardChains?: ChainsInterval<BackwardChain>
  ): Promise<ChainsInterval<BackwardChain>> {
    if (backwardChains == null) {
      backwardChains = {
        interval: [0, this.backwardChains.length - 1],
        // Don't need to slice here, we do it in the end.
        slice: this.backwardChains,
      };
    }
    const chainsInterval = backwardChains.slice.reduce(
      (p, el, index) => {
        const [ei] = el;
        if (ei <= interval.left && ei <= interval.right) {
          p.slice.push(el);
          p.interval[0] = Math.min(
            p.interval[0],
            index + backwardChains.interval[0]
          );
          p.interval[1] = Math.max(
            p.interval[1],
            index + backwardChains.interval[0]
          );
        }
        return p;
      },
      {
        interval: [this.backwardChains.length, 0],
        slice: [],
      } as ChainsInterval<BackwardChain>
    );

    // const lastIndex = backwardChains.interval[1];
    //if (lastIndex >= 0) {
    /*const i = KaPPA.binarySearch(
        this.backwardChains,
        backwardChains.interval[0],
        lastIndex,
        interval.left
      ) ?? backwardChains.interval[0];
      const j = KaPPA.binarySearch(
        this.backwardChains,
        i,
        lastIndex,
        interval.right
      ) ?? lastIndex;
      */
    /*const chainsInterval: ChainsInterval<BackwardChain> = {
        interval: [i, j],
        slice: this.backwardChains.slice(i, j + 1),
      };*/
    return this.updateBChainsInterval(chainsInterval);
    /*} else {
      return backwardChains;
    }*/
  }

  private static binarySearch<T extends unknown[]>(
    arr: Array<[Epoch, ...T]>,
    l: number,
    r: number,
    x: Epoch
  ): number | undefined {
    while (l <= r) {
      const mid = Math.floor(l + (r - l) / 2);
      const midElement = arr[mid];
      if (midElement[0] == x) {
        return mid;
      }
      if (midElement[0] < x) {
        l = mid + 1;
      } else {
        r = mid - 1;
      }
    }
    return undefined;
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
    const forwardChains = await Promise.all(
      forwardChainsData.map(async ([e, sskgData]) => {
        const forwardChain: ForwardChain = [
          e,
          await TreeSSKG.deserialize(sskgData),
        ];
        return forwardChain;
      })
    );
    const backwardChains = await Promise.all(
      backwardChainsData.map(async ([e, sskgData, N]) => {
        const backwardChain: BackwardChain = [
          e,
          await TreeSSKG.deserialize(sskgData),
          N,
        ];
        return backwardChain;
      })
    );
    const kappa = new KaPPA(maximumIntervalLengthWithoutBlocks);
    kappa.maxEpoch = maxEpoch;
    kappa.backwardChains = backwardChains;
    kappa.forwardChains = forwardChains;
    return kappa;
  }
}
