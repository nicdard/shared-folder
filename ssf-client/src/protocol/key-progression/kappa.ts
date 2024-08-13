import { TreeSSKG } from '../sskg/treeSSKG';
import { BackwardChain, BlockType, ChainsInterval, DoubleChainsInterval, Epoch, EpochInterval, ForwardChain, KP } from './kp';

class KaPPA implements KP {

    private readonly forwardChains: Array<ForwardChain> = [];
    private readonly backwardChains: Array<BackwardChain> = [];
    private maxEpoch: Epoch;

    private constructor(
        private readonly maximumIntervalLengthWithoutBlocks: number,
        private readonly keyLength: number,
    ) {
        this.maxEpoch = -1;
    }
    
    public async init(maximumIntervalLengthWithoutBlocks: number, keyLength: number): Promise<KP> {
        const kappa = new KaPPA(maximumIntervalLengthWithoutBlocks, keyLength);
        await kappa.progress(BlockType.FULL_BLOCK);
        return kappa;
    }

    public async progress(block: BlockType): Promise<void> {
        const [eFs, fs] = this.forwardChains[this.forwardChains.length - 1];
        const [eBs, bs, Nbs] = this.backwardChains[this.backwardChains.length - 1];
        this.maxEpoch++;
        /* Create a new forward chain if either:
        - 1: the block requires it
        - 2: the maximum interval of epochs without blocks is reached for the forward ones (calculate offset).
        */
        if (block == BlockType.FULL_BLOCK || block == BlockType.FORWARD_BLOCK
            || this.maxEpoch > eFs + this.maximumIntervalLengthWithoutBlocks
        ) {
            this.forwardChains.push([this.maxEpoch, await TreeSSKG.genSSKG(this.maximumIntervalLengthWithoutBlocks)]);
        }
        /* Create a new backward chain if either:
        - 1: the block requires it
        - 2: the maximum interval of epochs without blocks for the backwards ones is reached (calculate offset).
         */
        if (block == BlockType.FULL_BLOCK || block == BlockType.BACKWARD_BLOCK
            || this.maxEpoch > eBs + this.maximumIntervalLengthWithoutBlocks
        ) {
            // Shorten the current chain to used keys
            this.getBSeeds({left: 0, right: this.maxEpoch});
            // move to new backward chain
            this.backwardChains.push([this.maxEpoch, await TreeSSKG.genSSKG(this.maximumIntervalLengthWithoutBlocks), this.maximumIntervalLengthWithoutBlocks]);
        }
    }

    public getInterval(interval: EpochInterval): DoubleChainsInterval {
        if (interval.left < 0 || interval.right > this.maxEpoch || interval.left > interval.right) {
            throw new Error("Precondition failed, the interval should be within bounds and left <= right should hold.");
        }
        const forwardChainsInterval = this.getFSeeds(interval);
        const backwardChainsInterval = this.getBSeeds(interval);
        return { forwardChainsInterval, backwardChainsInterval, epochs: interval };
    }

    public createExtension(interval: EpochInterval): DoubleChainsInterval {
        if (interval.left < 0 || interval.right > this.maxEpoch || interval.left > interval.right) {
            throw new Error("Precondition failed, the interval should be within bounds and left <= right should hold.");
        }
        const extension = this.getInterval(interval);
        // Reuse the old forward chain if it can derive the key at l.
        // if ()

        return extension;
    }
    
    processExtension(interval: DoubleChainsInterval, extension: DoubleChainsInterval): DoubleChainsInterval {
        if (interval.epochs.right + 1 != extension.epochs.left) {
            throw new Error("An interval can be extended ")
        }
        interval.forwardChainsInterval.slice = interval.forwardChainsInterval.slice.concat(extension.forwardChainsInterval.slice);
        const [e, ] = interval.backwardChainsInterval.slice[interval.backwardChainsInterval.slice.length - 1];
        const [e1, ] = extension.backwardChainsInterval.slice[0];
        if (e == e1) {
            interval.backwardChainsInterval.slice = interval.backwardChainsInterval.slice.slice(0, -1);
        }
        interval.backwardChainsInterval.slice = interval.backwardChainsInterval.slice.concat(extension.backwardChainsInterval.slice);
        interval.epochs.right = extension.epochs.right;
        return interval;
    }
    
    public async getKey(epoch: number, interval: DoubleChainsInterval): Promise<CryptoKey>;
    public async getKey(epoch: number): Promise<CryptoKey>;
    public async getKey(epoch: number, interval?: DoubleChainsInterval): Promise<CryptoKey> {
        if (interval == null) {
            // This should return the key for the last element.
            interval = this.getInterval({ left: 0, right: this.maxEpoch });
        }
        if (epoch < interval.epochs.left || epoch > interval.epochs.right) {
            throw new Error('Epoch is out of bound.');
        }
        const forwardChains = this.getFSeeds({left: epoch, right: epoch}, interval.forwardChainsInterval);
        if (forwardChains.slice.length != 1) { 
            throw new Error('Internal error');
        }
        const backwardChains = this.getBSeeds({left: epoch, right: epoch}, interval.backwardChainsInterval);
        if (backwardChains.slice.length != 1) {
            throw new Error('Internal error');
        }
        const [ , fs ] = forwardChains.slice[0];
        const fk = await fs.getKey();
        const [ , bs ] = backwardChains.slice[0];
        const bk = await bs.getKey();
        // How to combine the fk and bk? Do I export them in bits?
        throw new Error("To be finshed");
    }

    private getFSeeds(interval: EpochInterval, forwardChains?: ChainsInterval<ForwardChain>): ChainsInterval<ForwardChain> {
        if (forwardChains == null) {
            forwardChains = { 
                interval: [0, this.forwardChains.length - 1],
                // Don't need to slice here, we do it in the end.
                slice: this.forwardChains
            };
        }
        const lastIndex = forwardChains.interval[1];
        // When applying binary search, we need to use the original sequence, as indexes are referring to it and not the slice.
        const i = KaPPA.binarySearch(this.forwardChains, forwardChains.interval[0], lastIndex, interval.left);
        const j = KaPPA.binarySearch(this.forwardChains, i, lastIndex, interval.right);
        const [ei, sskgi] = this.forwardChains[i];
        sskgi.superseek(interval.left - ei);
        return { interval: [i, j], slice: this.forwardChains.slice(i, j) };
    }

    private getBSeeds(interval: EpochInterval, backwardChains?: ChainsInterval<BackwardChain>): ChainsInterval<BackwardChain> {
        if (backwardChains == null) {
            backwardChains = { 
                interval: [0, this.backwardChains.length - 1],
                // Don't need to slice here, we do it in the end.
                slice: this.backwardChains
            };
        }
        const lastIndex = backwardChains.interval[1];
        const i = KaPPA.binarySearch(this.backwardChains, backwardChains.interval[0], lastIndex, interval.left);
        const j = KaPPA.binarySearch(this.backwardChains, i, lastIndex, interval.right);
        const bj = this.backwardChains[j];
        const [ej, sskgj, nj] = bj;
        const shortenedNj = interval.right - ej + 1;
        sskgj.superseek(nj - shortenedNj);
        bj[2] = shortenedNj;
        return { interval: [i, j], slice: this.backwardChains.slice(i, j) };
    }

    private static binarySearch<T extends unknown[]>(arr: Array<[Epoch, ...T]>, l: number, r: number, x: Epoch): number {
        while (l <= r) {
            const mid = l + (r - l) / 2;
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
        return -1;
    }
}