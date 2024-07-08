import { generateIV, string2ArrayBuffer, subtle } from "./commonCrypto";
import { CtxtKem, kemKdfDecap, kemKdfEncap } from "./kemKdf";

/**
 * The result of a symmetric key encryption, where we have key encapsulation (KEM).
 */
export interface PkeEncryptResult {
    ctxt: ArrayBuffer,
    cKem: CtxtKem,
    iv: Uint8Array,
}

/**
 * Adding this label to have cryptographic assurance of what is the usage of the key
 * derived during KDF.
 */
const KEY_LABEL = string2ArrayBuffer("PKE");

/**
 * We construct a ephimeral async key, perform DH using the pk in input with the
 * ephimeral sk and then generate an AES_GCM key. We use the AES_GCM key to encrypt 
 * the msg in input to return the ctxt.
 * @param pk the public key to perform DH
 * @param msg the message to encrypt
 * @returns the ciphertext together with teh key encapsulation parameters, as {@link PkeEncryptResult}.
 */
export async function pkeEnc(pk: CryptoKey, msg: ArrayBufferLike): Promise<PkeEncryptResult> {
    // (K_kem, C_kem) <- Kem.Encap(pk, "PKE")
    const { k, c } = await kemKdfEncap(pk, KEY_LABEL);

    // C_msg <- AES_GCM.Enc(K_kem, msg)
    const iv = generateIV();
    const ctxt = await subtle.encrypt({ name: k.algorithm.name, iv }, k, msg);
    // return (C_msg, C_kem, iv)
    return { ctxt, cKem: c, iv };
}

/**
 * The reverse operation of {@link pkeEnc}
 * @param keyPair the asymmetric key
 * @param encResult the result of {@link pkeEnc}, thus being the ciphertext and the encapsulation paramaters
 * @returns the {@link ArrayBufferLike} containing the decrypted value. You need to convert it using the right typed array to be able to check the contents.
 */
export async function pkeDec(keyPair: CryptoKeyPair, encResult: PkeEncryptResult): Promise<ArrayBufferLike> {
    // K_kem <- KEM.Decap(sk, C_kem)
    const kKem = await kemKdfDecap(keyPair, encResult.cKem, KEY_LABEL);
    // msg <- AES_GCM.Dec(K_kem, C_msg)
    return subtle.decrypt( { name: kKem.algorithm.name, iv: encResult.iv }, kKem, encResult.ctxt);
}

