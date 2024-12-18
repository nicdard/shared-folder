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
import { SSKG } from '../sskg/sskg';

/**
 * The Double Key Progression Scheme.
 * The global state `st` as described in the paper is going to be stored in the class instance.
 * Some functions are static in the code (so not visible here) so that non-admins can use them without instantiating a DKR, see {@link KaPPA}.
 */
export interface DKR {
  progress(block: BlockType): Promise<void>;
  getInterval(interval: EpochInterval): Promise<DoubleChainsInterval>;
  createExtension(interval: EpochInterval): Promise<DoubleChainsInterval>;
  processExtension(extension: DoubleChainsInterval): Promise<void>;
  getKey(epoch: Epoch): Promise<CryptoKey>;
  getMaxEpoch(): Epoch;
  serialize(): Promise<Buffer>;
}

/**
 * The type of an epoch should be a total order.
 */
export type Epoch = number;

/**
 * An Interval defined by two {@link Epoch}.
 *
 */
export interface EpochInterval {
  left: Epoch;
  right: Epoch;
}

/**
 * A forward chain is stored using the {@link Epoch} in which it starts
 * and the {@link SSKG} generiting the sequence of secrets.
 */
export type ForwardChain = [Epoch, SSKG];

/**
 * A bacward chain is stored as a {@link ForwardChain} with the additional
 * maximum number of elements that it can generate.
 */
export type BackwardChain = [Epoch, SSKG, number];

/**
 * This is the type of the `int` object in the paper pseudocode.
 * It collects: the epochs this interval refers to, and the elements from the chains
 * to compute the keys in within these epochs.
 */
export interface DoubleChainsInterval {
  epochs: EpochInterval;
  forwardChainsInterval: Array<ForwardChain>;
  backwardChainsInterval: Array<BackwardChain>;
}

export enum BlockType {
  /**
   * Epsilon (no block)
   */
  EMPTY,
  /**
   * {@code <-block} prevents the forward derivation of keys, i.e., that keys for epochs larger or equal
   * than {@code e} are independent from any earlier interval {@code [l, r] for r < e}.
   */
  FORWARD_BLOCK,
  /**
   * {@code >-block} prevents the backward derivation of keys, i.e., that keys for epochs smaller than
   * {@code e} are independent from any interval {@code [l, r] after the block (l >= e)}.
   */
  BACKWARD_BLOCK,
  /**
   * {@code ||-block} blocks the key derivation from both sides, i.e., setting both {@link FORWARD_BLOCK}
   * and {@link BACKWARD_BLOCK} simultaneously.
   */
  FULL_BLOCK,
}
