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
/**
 * Seekable Sequential Key Generator.
 * Papers: https://eprint.iacr.org/2014/479.pdf https://eprint.iacr.org/2013/397.pdf
 *
 * We implement the tree-based construction from the paper.
 * Another possible solution is to use an hash chain and a list (or possibly a SkipList) and eventually emulate seek or superseek.
 */
export interface SSKG {
  readonly name: string;
  getKey(): Promise<CryptoKey>;
  getRawKey(): Promise<ArrayBuffer>;
  next(): Promise<void>;
  seek(offset: number): Promise<void>;
  superseek(offset: number): Promise<void>;
  clone(cloneName?: string): SSKG;
  serialize(): Promise<Buffer>;
}
