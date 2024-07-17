import {
  appendBuffers,
  deriveAesGcmKey,
  deriveHKDFKeyWithDH,
  generateEphemeralKeyPair,
  generateSalt,
  subtle,
} from './commonCrypto';

/**
 * The ciphertext result of a KEM operation.
 */
export interface CtxtKem {
  pe: CryptoKey;
  salt: ArrayBufferLike;
}

/**
 * The result of a KEM + KDF operation.
 */
interface KemKdfEncapResult {
  // The derived and encapsulated key
  k: CryptoKey;
  c: CtxtKem;
}

/**
 * Performs a KEM (Key encapsulation mechanism) and a KDF (key derivation function).
 * @param pk a public {@link CryptoKey}
 * @param keyLabel the label to apply to the KEM key with KDF.
 * @returns the encapsulated symmetric key (for AES).
 */
export async function kemKdfEncap(
  pk: CryptoKey,
  keyLabel: ArrayBufferLike
): Promise<KemKdfEncapResult> {
  if (pk.type !== 'public') {
    throw new Error('The key is not public');
  }
  // (se, pe) <-$ ECDH.Kg()
  const { privateKey: se, publicKey: pe } = await generateEphemeralKeyPair();
  // k' <- "derive"_HKDF(pk, se) = apply DH(pk, se)
  const k = await deriveHKDFKeyWithDH({ publicKey: pk, privateKey: se });
  // Generate a random salt of 8 bytes
  const salt = generateSalt(64);

  // K <- KDF_aes-gcm(k', label = pe||pk||keyLabel)
  // Calculate label.
  const label = await calculateKemKdfLabel(pk, pe, keyLabel);
  // derive the key
  const kKem = await deriveAesGcmKey({ k, salt, label });

  // C_kem <- (pe, salt)
  return {
    k: kKem,
    c: {
      pe,
      salt,
    },
  };
}

/**
 * @param cryptoKeyPair the asymmetric key pair
 * @param c the {@link CtxtKem}
 * @param keyLabel the label used in the KDF
 * @returns the decapsulated key
 */
export async function kemKdfDecap(
  { privateKey: sk, publicKey: pk }: CryptoKeyPair,
  c: CtxtKem,
  keyLabel: ArrayBufferLike
): Promise<CryptoKey> {
  // (pe, salt) <- C_kem
  const { pe, salt } = c;
  // k1 <- "derive"_HKDF(sk, pe) = DH(sk, pe) = DH(pk, se)
  const k = await deriveHKDFKeyWithDH({ publicKey: pe, privateKey: sk });
  // k_KEM <- KDF_aes-gcm(k1, pe || pk || keyLabel, salt)
  const label = await calculateKemKdfLabel(pk, pe, keyLabel);
  const kKem = await deriveAesGcmKey({ k, salt, label });
  return kKem;
}

async function calculateKemKdfLabel(
  pk: CryptoKey,
  pe: CryptoKey,
  keyLabel: ArrayBufferLike
) {
  const rawPk = await subtle.exportKey('raw', pk);
  const rawPe = await subtle.exportKey('raw', pe);
  return appendBuffers(rawPe, rawPk, keyLabel);
}
