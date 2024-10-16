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
import {
  HMAC_PARAMS,
  getHkdfParams,
  string2ArrayBuffer,
  subtle,
} from '../commonCrypto';
import { decodeObject, encodeObject } from '../marshaller';
import { SSKG } from './sskg';

// HMAC is a double-prf: When Messages are Keys: Is HMAC a dual-PRF? https://eprint.iacr.org/2023/861.pdf
type State = [ArrayBuffer, number];

/**
 * Used in serialization and deserialization.
 */
interface TreeSSKGData {
  readonly name: string;
  readonly totalNumberOfEpochs: number;
  readonly stack: Array<State>;
}

/**
 * Implements the Seekable Sequential Key Generator with the binary tree construction.
 * Papers: https://eprint.iacr.org/2014/479.pdf https://eprint.iacr.org/2013/397.pdf
 * Reference implementation: https://github.com/oreparaz/sskg/blob/4ccfa13b9e5f/sskg.go
 */
export class TreeSSKG implements SSKG {
  private stack: Array<State>;
  private readonly totalNumberOfEpochs: number;
  public readonly name: string;

  private constructor(totalNumberOfEpochs: number, name: string) {
    this.name = name;
    this.stack = [];
    this.totalNumberOfEpochs = totalNumberOfEpochs;
  }

  // GenSSK
  public static async genSSKG(
    totalNumberOfEpochs: number,
    name = 'sskg'
  ): Promise<TreeSSKG> {
    // We could also just directly use the key from this call...
    const seed = await TreeSSKG.generateSeed();
    // ...but in this way we bound the seed label to the root element.
    const s = await TreeSSKG.prf(seed, 'seed');
    const h = Math.ceil(Math.log2(totalNumberOfEpochs + 1));
    const sskg = new TreeSSKG(totalNumberOfEpochs, name);
    sskg.stack.push([s, h]);
    return sskg;
  }

  // GetKey
  public async getKey(): Promise<CryptoKey> {
    const kRaw = await this.getRawKey();
    const k = subtle.importKey('raw', kRaw, 'HKDF', false, [
      'deriveKey',
      'deriveBits',
    ]);
    return k;
  }

  public async getRawKey(): Promise<ArrayBuffer> {
    const [s] = this.stack.at(-1);
    const kRaw = await TreeSSKG.prf(s, 'key');
    return kRaw;
  }

  // Evolve
  public async next() {
    const [s, h] = this.stack.pop();
    if (h > 1) {
      this.stack.push([await TreeSSKG.prf(s, 'right'), h - 1]);
      this.stack.push([await TreeSSKG.prf(s, 'left'), h - 1]);
    }
  }

  // Seek: doesn't support being called after evolve or another seek operation was already performed.
  public async seek(offset: number) {
    let steps = offset;
    const [s, h] = this.stack.pop();
    let currentHeight = h;
    let currentSecret = s;
    while (steps > 0) {
      --currentHeight;

      if (currentHeight <= 0) {
        throw new Error('Seeking exceeds total number of epochs!');
      }

      const pow = Math.pow(2, currentHeight);
      if (steps < pow) {
        this.stack.push([
          await TreeSSKG.prf(currentSecret, 'right'),
          currentHeight,
        ]);
        currentSecret = await TreeSSKG.prf(currentSecret, 'left');
        --steps;
      } else {
        currentSecret = await TreeSSKG.prf(currentSecret, 'right');
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
    for (; steps >= Math.pow(2, currentHeight) - 1; ) {
      steps -= Math.pow(2, currentHeight) - 1;
      const [s, h] = this.stack.pop();
      currentHeight = h;
      currentSecret = s;
    }

    while (steps > 0) {
      --currentHeight;
      if (currentHeight <= 0) {
        throw new Error('Seeking exceeds total number of epochs!');
      }

      const pow = Math.pow(2, currentHeight);
      if (steps < pow) {
        this.stack.push([
          await TreeSSKG.prf(currentSecret, 'right'),
          currentHeight,
        ]);
        currentSecret = await TreeSSKG.prf(currentSecret, 'left');
        --steps;
      } else {
        currentSecret = await TreeSSKG.prf(currentSecret, 'right');
        steps -= pow;
      }
    }
    this.stack.push([currentSecret, currentHeight]);
  }

  /**
   * @param s a {@link ArrayBuffer} containing an exported {@link CryptoKey} in {@code raw} format.
   * @param label a label that is used in HKDF.
   * @returns performs an HKDF (which internally uses HMAC, thus being a double-PRF).
   */
  private static async prf(
    s: ArrayBuffer,
    label: string
  ): Promise<ArrayBuffer> {
    const hkdfKey = await subtle.importKey('raw', s, 'HKDF', false, [
      'deriveKey',
      'deriveBits',
    ]);
    const hmacKey = await subtle.deriveKey(
      getHkdfParams(string2ArrayBuffer(label), new Uint8Array()),
      hkdfKey,
      HMAC_PARAMS,
      true,
      ['sign', 'verify']
    );
    const hmacKeyRaw = await subtle.exportKey('raw', hmacKey);
    return hmacKeyRaw;
  }

  /**
   * @returns a random HMAC {@link CryptoKey} exported in {@code raw} format to seed the SSKG.
   */
  private static async generateSeed(): Promise<ArrayBuffer> {
    const seed = await subtle.generateKey(HMAC_PARAMS, true, ['sign']);
    return subtle.exportKey('raw', seed);
  }

  /**
   * @param cloneName optional name to assign to the clone.
   * @returns a new copy of the current {@link TreeSSKG}
   */
  public clone(cloneName?: string): TreeSSKG {
    const clone = new TreeSSKG(
      this.totalNumberOfEpochs,
      cloneName ?? this.name
    );
    clone.stack = this.stack.slice();
    return clone;
  }

  /**
   * @returns {@link Buffer} containing the serialized form of this instance using CBOR.
   * @see TreeSSKGData
   */
  public async serialize(): Promise<Buffer> {
    const data: TreeSSKGData = {
      name: this.name,
      stack: this.stack,
      totalNumberOfEpochs: this.totalNumberOfEpochs,
    };
    const sskg = await encodeObject(data);
    return sskg;
  }

  /**
   *
   * @param buffer a buffer containing the CBOR serailized {@link TreeSSKGData}.
   * @returns deserialized {@link TreeSSKG}.
   */
  public static async deserialize(buffer: Buffer): Promise<TreeSSKG> {
    const treeSSKGData = await decodeObject<TreeSSKGData>(buffer);
    const treeSSKG = new TreeSSKG(
      treeSSKGData.totalNumberOfEpochs,
      treeSSKGData.name
    );
    treeSSKG.stack = treeSSKGData.stack;
    return treeSSKG;
  }
}
