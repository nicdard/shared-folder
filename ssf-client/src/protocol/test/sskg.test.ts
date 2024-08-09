import { subtle } from "crypto";
import { deriveAesGcmKey, string2ArrayBuffer } from "../commonCrypto";
import { TreeSSKG } from "../sskg";

it("A SSKG returns HKDF keys", async () => {
    const sskg = await TreeSSKG.genSSKG(16);
    const key = await sskg.getKey();
    expect(key.algorithm.name).toEqual("HKDF");
    expect(key.usages).toStrictEqual(["deriveKey", "deriveBits"]);
});

it("Seeking by n an SSKG equals to calling evolve n times (randomized over n)", async () => {
    const p = Math.random();
    let offset = Math.ceil(14 * p) + 1;
    console.log("N: ", offset);
    const sskg = await TreeSSKG.genSSKG(16);
    const sskgClone = sskg.clone();
    await sskgClone.superseek(offset);
    while (offset--) {
        await sskg.evolve();
    }
    await checkSSKGKeyEquality(sskg, sskgClone);
});

it("Seeking multiple times corresponds to evolving each offset", async () => {
    const sskg = await TreeSSKG.genSSKG(256);
    const sskgClone = sskg.clone();
    for (let i = 1; i < 15; ++i) {
        const p = Math.random();
        let offset = Math.ceil(14 * p) + 1;
        console.log("N: ", offset);

        await sskgClone.superseek(offset);
        while (offset--) {
            await sskg.evolve();
        }
        await checkSSKGKeyEquality(sskg, sskgClone);
    }
});



/**
 * The {@link TreeSSKG} getKey operation returns an HKDF key.
 * Those keys cannot be extracted and thus compared.
 * Therefore we generate an AES key from the HKDF key and compare that one, given the same salt and label.
 */
async function checkSSKGKeyEquality(sskg: TreeSSKG, sskgClone: TreeSSKG) {
    const hkdfKey = await sskg.getKey();
    const hkdfKeyClone = await sskgClone.getKey();
    const salt = new Uint8Array();
    const label = string2ArrayBuffer("test");
    const aesKey = await deriveAesGcmKey({ k: hkdfKey, salt, label});
    const aesKeyClone = await deriveAesGcmKey({ k: hkdfKeyClone, salt, label});
    const rawAesKey = await subtle.exportKey("raw", aesKey);
    const rawAesKeyClone = await subtle.exportKey("raw", aesKeyClone);
    console.log(rawAesKey, rawAesKeyClone);
    expect(rawAesKey).toStrictEqual(rawAesKeyClone);
}

