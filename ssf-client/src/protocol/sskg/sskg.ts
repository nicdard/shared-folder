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
