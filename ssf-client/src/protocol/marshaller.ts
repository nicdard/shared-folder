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
import { Decoder, Encoder } from 'cbor';
import { BufferLike } from 'cbor/types/lib/decoder';

/**
 * @param encoded the CBOR encoded content to decode in {@type T}
 * @returns the decoded {@link T} object.
 */
export async function decodeObject<T>(encoded: BufferLike): Promise<T> {
  const decoded: T = (await Decoder.decodeFirst(encoded, {
    preventDuplicateKeys: false,
    extendedResults: false,
  })) as T;
  return decoded;
}

/**
 * @param object the object to encode
 * @returns CBOR encoding of the metadata object
 */
export async function encodeObject<T extends object>(
  object: T
): Promise<Buffer> {
  /* TODO: when server supports stream api, use stream: https://nodejs.org/api/stream.html
    const encoder = new Encoder({ canonical: true, detectLoops: false });
    encoder.pushAny(metadata);
    */
  const encoded = await Encoder.encodeAsync(object, {
    canonical: true,
    detectLoops: false,
  });
  return encoded;
}
