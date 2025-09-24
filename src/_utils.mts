/**
 * This file contains code from the noble-ciphers project:
 *
 * Copyright (c) 2022 Paul Miller (https://paulmillr.com)
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * License: MIT
 */
import { abytes, createView, isLE, setBigUint64, type Cipher, type CipherParams } from "@noble/ciphers/utils";

export const u64BitLengths = (ad_nbits: bigint, ct_nbits: bigint) => {
    const num = new Uint8Array(16);
    const view = createView(num);
    setBigUint64(view, 0, ad_nbits, true);
    setBigUint64(view, 8, ct_nbits, true);
    return num;
};

export type AegisCipher = Cipher & {
    encryptDetached(plaintext: Uint8Array): [Uint8Array, Uint8Array],
    decryptDetached(ciphertext: Uint8Array, tag: Uint8Array): Uint8Array,
};

export interface AegisCipherOptions {
    tagLength?: number,
};

export type AegisCipherCons = (key: Uint8Array, nonce: Uint8Array, AAD?:Uint8Array, options?: AegisCipherOptions) => AegisCipher;
/**
 * Wraps a cipher: validates args, ensures encrypt() can only be called once.
 * @__NO_SIDE_EFFECTS__
 */
export const wrapAegisCipher = <C extends AegisCipherCons, P extends CipherParams>(
  params: P,
  constructor: C
): C & P => {
  function wrappedCipher(key: Uint8Array, nonce: Uint8Array, AAD?:Uint8Array, options?: AegisCipherOptions): AegisCipher {
    // Validate key
    abytes(key);

    // Big-Endian hardware is rare. Just in case someone still decides to run ciphers:
    if (!isLE) throw new Error('Non little-endian hardware is not yet supported');

    // Validate nonce if nonceLength is present
    if (params.nonceLength !== undefined) {
      if (!nonce) throw new Error('nonce / iv required');
      else abytes(nonce, params.nonceLength);
    }

    const tagLength = options?.tagLength ?? params.tagLength ?? 0;
    if (![16, 32].includes(tagLength)) throw new Error("invalid tag length, 16 or 32 expected");

    // Validate AAD if present
    if (AAD != null) {
      abytes(AAD);
    }

    const cipher = constructor(key, nonce, AAD, options);
    // Create wrapped cipher with validation and single-use encryption
    let called = false;
    const wrCipher = {
      encrypt(data: Uint8Array) {
        if (called) throw new Error('cannot encrypt() twice with same key + nonce');
        called = true;
        abytes(data);
        return (cipher as AegisCipher).encrypt(data);
      },
      encryptDetached(data: Uint8Array) {
        if (called) throw new Error('cannot encrypt() twice with same key + nonce');
        called = true;
        abytes(data);
        return (cipher as AegisCipher).encryptDetached(data);
      },
      decrypt(data: Uint8Array) {
        abytes(data);
        return (cipher as AegisCipher).decrypt(data);
      },
      decryptDetached(data: Uint8Array, tag: Uint8Array) {
        abytes(data); abytes(tag);
        return (cipher as AegisCipher).decryptDetached(data, tag);
      },
    };

    Object.assign(wrCipher, params, { tagLength });
    return wrCipher;
  }
  return wrappedCipher as C & P;
};
