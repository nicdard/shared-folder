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
