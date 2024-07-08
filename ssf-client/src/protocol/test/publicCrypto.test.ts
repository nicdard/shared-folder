import { generateEphemeralKeyPair, string2ArrayBuffer } from "../commonCrypto";
import { pkeDec, pkeEnc } from "../publicCrypto";

it('pkeDec(sk, pkeEnc(pk, msg)) = msg', async () => {
    const msg = new Uint8Array(string2ArrayBuffer("TESTMESSAGE"));
    const a = await generateEphemeralKeyPair();
    const encrypted = await pkeEnc(a.publicKey, msg);
    const decrypted = await pkeDec(a, encrypted);
    const decryptedUint8Array = new Uint8Array(decrypted);
    expect(decryptedUint8Array).toStrictEqual(msg);
});