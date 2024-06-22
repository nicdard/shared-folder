import { Metadata, decodeMetadata, encodeMetadata } from '../baseline';

test('Encoding and decoding of a non-empty Metadata works', async () => {
    const metadata: Metadata = {
        folderKeysByUser: {
            "user1@test.com": { cipher: new TextEncoder().encode("KEncryptedForUser1"), iv: new TextEncoder().encode("iv1")},
            "user2@test.com": { cipher: new TextEncoder().encode("KEncryptedForUser2"), iv: new TextEncoder().encode("iv2")},
        },
        fileMetadatas: {}
    }
    const encodedMetadata = await encodeMetadata(metadata);
    const decodedMetadata = await decodeMetadata(new Uint8Array(encodedMetadata));
    expect(decodedMetadata).toEqual(metadata);
});

test('')