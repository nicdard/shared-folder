import { string2ArrayBuffer, subtle } from "./commonCrypto";

// HMAC is a double-prf: When Messages are Keys: Is HMAC a dual-PRF?

type State = [CryptoKey, number];

/**
 * Implements the Seekable Sequential Key Generator with the binary tree construction.
 * Papers: https://eprint.iacr.org/2014/479.pdf https://eprint.iacr.org/2013/397.pdf
 * Reference implementation: https://github.com/oreparaz/sskg/blob/4ccfa13b9e5f/sskg.go
 */
export class TreeSSKG {

    private stack: Array<State>;
    private totalNumberOfEpochs: number;

    private constructor(totalNumberOfEpochs: number) {
        this.stack = [];
        this.totalNumberOfEpochs = totalNumberOfEpochs;
    }

    // GenSSK
    public static async genSSKG(totalNumberOfEpochs: number): Promise<TreeSSKG> {
        // We could also just directly use the key from this call...
        const seed = await subtle.generateKey({
            name: "HMAC",
            hash: "SHA-256"
        }, true, ["sign"]);
        const seedRaw = await subtle.exportKey("raw", seed);
        const hkdfSeed = await subtle.importKey("raw", seedRaw, "HKDF", false, ["deriveKey", "deriveBits"]);
        // ...but in this way we bound the seed label to the root element.
        const s = await TreeSSKG.prf(hkdfSeed, "seed");
        const h = Math.floor(Math.log2(totalNumberOfEpochs + 1));
        const sskg = new TreeSSKG(totalNumberOfEpochs);
        sskg.stack.push([s, h]);
        return sskg;
    }

    // GetKey
    public async getKey(): Promise<CryptoKey> {
        const [s, ] = this.stack.at(-1);
        const k = TreeSSKG.prf(s, "key");
        return k;
    }

    // Evolve
    public async evolve() {
        const [s, h] = this.stack.pop();
        if (h > 1) {
            this.stack.push([await TreeSSKG.prf(s, "right"), h - 1]);
            this.stack.push([await TreeSSKG.prf(s, "left"), h - 1]);
        }
    }

    // Seek: doesn't support being called after evolve or another seek operation was already performed.
    private async seek(offset: number) {
        let steps = offset;
        const [s, h] = this.stack.pop();
        let currentHeight = h;
        let currentSecret = s;
        while (steps > 0) {
            --currentHeight;
            const pow = 1 << currentHeight;
            if (steps < pow) {
                this.stack.push([await TreeSSKG.prf(currentSecret, "right"), currentHeight]);
                currentSecret = await TreeSSKG.prf(currentSecret, "left");
                --steps;
            } else {
                currentSecret = await TreeSSKG.prf(currentSecret, "right");
                steps -= pow;
            }
        }
        this.stack.push([currentSecret, currentHeight]);
    }

    // Superseek works even after other seek or evolve invocations.
    public async superseek(offset: number) {
        
        const [s, h] = this.stack.pop();
        let currentHeight = h;
        let currentSecret = s;
        let steps = offset;
        for (; steps >= ((1 << h) - 1); steps -= ((1 << h) - 1)) {
            const [s, h] = this.stack.pop();
            currentHeight = h;
            currentSecret = s;
        }

        while (steps > 0) {
            --currentHeight;
            if (currentHeight <= 0) {
                throw new Error("Seeking exceeds total number of epochs!");
            } 
            
            const pow = 1 << currentHeight;
            if (steps < pow) {
                this.stack.push([await TreeSSKG.prf(currentSecret, "right"), currentHeight]);
                currentSecret = await TreeSSKG.prf(currentSecret, "left");
                --steps;
            } else {
                currentSecret = await TreeSSKG.prf(currentSecret, "right");
                steps -= pow;
            }
        }
        this.stack.push([currentSecret, currentHeight]);
    }


    /**
     * @param s a {@link CryptoKey}.
     * @param label a label that is used in HKDF.
     * @returns performs an HKDF (which internally uses HMAC, thus being a double-PRF).
     */
    private static async prf(s: CryptoKey, label: string): Promise<CryptoKey> {
        const hmacKey = await subtle.deriveKey({
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(),
            info: string2ArrayBuffer(label),
        }, s, {
            name: "HMAC",
            hash: "SHA-256",
        }, true, ["sign", "verify"]);
        const hmacKeyRaw = await subtle.exportKey("raw", hmacKey);
        const hkdfKey = await subtle.importKey("raw", hmacKeyRaw, "HKDF", false, ["deriveKey", "deriveBits"]);
        return hkdfKey;
    }

    /**
     * @returns a new copy of the current {@link TreeSSKG}
     */
    public clone(): TreeSSKG {
        const clone = new TreeSSKG(this.totalNumberOfEpochs);
        clone.stack = this.stack.slice();
        return clone;
    }
}
