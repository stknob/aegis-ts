import { isAligned32, concatBytes, copyBytes, u8, u32, clean } from "@noble/ciphers/utils";
import { aegis_decrypt_detached, aegis_encrypt_detached, type AegisState, C0, C1, set128, xor128, xor256 } from "./_aegis.mjs";
import { u64BitLengths, wrapAegisCipher, type AegisCipher, type AegisCipherOptions } from "./_utils.mjs";
import { AESRound } from "./_aes.mjs";

export type Aegis128LBlocks = [
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
];

const DUMMY_BLOCKS: Aegis128LBlocks = [
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
];


/**
 * Aegis128L state update function with single 256bit input block, extracted for testability
 * @param blocks
 * @param msg
 * @returns
 */
export function aegis128l_update1(blocks: Aegis128LBlocks, msg: Uint32Array, tmp: Uint32Array): Aegis128LBlocks {
    return aegis128l_update2(blocks, msg.subarray(0, 4), msg.subarray(4, 8), tmp);
}

/**
 * Aegis128L state update function with two 128bit input blocks, extracted for testability
 * @param blocks
 * @param msg
 * @returns
 */
export function aegis128l_update2(blocks: Aegis128LBlocks, m0: Uint32Array, m1: Uint32Array, tmp: Uint32Array): Aegis128LBlocks {
    const sm0 = AESRound(blocks[7], xor128(blocks[0], m0, tmp));
    const sm1 = AESRound(blocks[0], blocks[1]);
    const sm2 = AESRound(blocks[1], blocks[2]);
    const sm3 = AESRound(blocks[2], blocks[3]);
    const sm4 = AESRound(blocks[3], xor128(blocks[4], m1, tmp));
    const sm5 = AESRound(blocks[4], blocks[5]);
    const sm6 = AESRound(blocks[5], blocks[6]);
    const sm7 = AESRound(blocks[6], blocks[7]);

    set128(blocks[0], sm0);
    set128(blocks[1], sm1);
    set128(blocks[2], sm2);
    set128(blocks[3], sm3);
    set128(blocks[4], sm4);
    set128(blocks[5], sm5);
    set128(blocks[6], sm6);
    set128(blocks[7], sm7);
    return blocks;
}


class Aegis128LState implements AegisState {
    #blocks: Aegis128LBlocks = DUMMY_BLOCKS;
    #tmpBlock32 = new Uint32Array(8);   // Scratch buffer for generic operations e.g. xor128 and ZeroPad()
    #tmpBlock8  = u8(this.#tmpBlock32); // Uint8Array view into generic scratch buffer for ZeroPad()
    #sBlock32 = new Uint32Array(8);     // Scratch buffer for aegis128l_updateX
    #zBlock32 = new Uint32Array(8);     // Scratch buffer for genZ

    get blockSize(): number {
        return 32;
    }

    init(key: Uint8Array, nonce: Uint8Array): this {
        const toClean = [];
        if (!isAligned32(key)) toClean.push((key = copyBytes(key)));
        if (!isAligned32(nonce)) toClean.push((nonce = copyBytes(nonce)));

        const k = u32(key);
        const n = u32(nonce);

        this.#blocks = [
            xor128(k,  n, new Uint32Array(4)),
            Uint32Array.from(C1),
            Uint32Array.from(C0),
            Uint32Array.from(C1),
            xor128(k,  n, new Uint32Array(4)),
            xor128(k, C0, new Uint32Array(4)),
            xor128(k, C1, new Uint32Array(4)),
            xor128(k, C0, new Uint32Array(4)),
        ];

        for (let i = 0; i < 10; i++) {
            aegis128l_update2(this.#blocks, n, k, this.#sBlock32);
        }

        clean(...toClean);
        return this;
    }

    /**
     * Absorbs a full 256bit input block into the Aegis128L state
     * @param ai
     */
    absorb(ai: Uint32Array) {
        aegis128l_update1(this.#blocks, ai, this.#sBlock32);
    }

    absorbPartial(ai: Uint8Array) {
        this.#tmpBlock8.fill(0).set(ai);
        aegis128l_update1(this.#blocks, this.#tmpBlock32, this.#sBlock32);
    }

    /**
     * Generate Z0, Z1 as a single 256bit block
     * @param blocks
     * @param out
     * @returns
     */
    #genZ(blocks: Aegis128LBlocks, out: Uint32Array): Uint32Array {
        // z0 = S6 ^ S1 ^ (S2 & S3)
        out[0] = (blocks[6][0] ^ blocks[1][0] ^ (blocks[2][0] & blocks[3][0]));
        out[1] = (blocks[6][1] ^ blocks[1][1] ^ (blocks[2][1] & blocks[3][1]));
        out[2] = (blocks[6][2] ^ blocks[1][2] ^ (blocks[2][2] & blocks[3][2]));
        out[3] = (blocks[6][3] ^ blocks[1][3] ^ (blocks[2][3] & blocks[3][3]));
        // z1 = S2 ^ S5 ^ (S6 & S7)
        out[4] = (blocks[2][0] ^ blocks[5][0] ^ (blocks[6][0] & blocks[7][0]));
        out[5] = (blocks[2][1] ^ blocks[5][1] ^ (blocks[6][1] & blocks[7][1]));
        out[6] = (blocks[2][2] ^ blocks[5][2] ^ (blocks[6][2] & blocks[7][2]));
        out[7] = (blocks[2][3] ^ blocks[5][3] ^ (blocks[6][3] & blocks[7][3]));
        return out;
    }

    encBlock(xi: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#blocks, this.#zBlock32);
        aegis128l_update1(this.#blocks, xi, this.#sBlock32); // Update(t0, t1)
        xor256(xi, z, out); // ci = t0 ^ z0 || t1 ^ z1
        return out;
    }

    encPartial(xi: Uint8Array, out: Uint8Array): Uint8Array {
        this.#tmpBlock8.fill(0).set(xi);    // ZeroPad(xi, 128)
        this.encBlock(this.#tmpBlock32, this.#tmpBlock32);
        out.set(this.#tmpBlock8.subarray(0, xi.length));
        return out;
    }

    decBlock(ci: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#blocks, this.#zBlock32);
        xor256(ci, z, out); // xi = t0 ^ z0 || t1 ^ z1
        aegis128l_update1(this.#blocks, out, this.#sBlock32);    // Update(t0, t1)
        return out;
    }

    decPartial(ci: Uint8Array, out: Uint8Array): Uint8Array {
        const z = this.#genZ(this.#blocks, this.#zBlock32);
        this.#tmpBlock8.fill(0).set(ci);  // ZeroPad(ci, 256)
        xor256(this.#tmpBlock32, z, this.#tmpBlock32);

        out.set(this.#tmpBlock8.subarray(0, ci.length));    // xn = Truncate(out, |cn|)
        this.#tmpBlock8.fill(0).set(out);  // ZeroPad(xn, 256)
        aegis128l_update1(this.#blocks, this.#tmpBlock32, this.#sBlock32);
        return out;
    }

    finalize(ad_len: number, msg_len: number, tag_len: number): Uint8Array {
        // LE64(ad_len_bits) || LE64(msg_len_bits)
        const tmp = u64BitLengths(BigInt(ad_len) << 3n, BigInt(msg_len) << 3n);
        this.#tmpBlock32.set(new Uint32Array(tmp.buffer, tmp.byteOffset, tmp.byteLength >>> 2));

        // t = S2 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))
        xor128(this.#tmpBlock32, this.#blocks[2], this.#tmpBlock32);

        for (let i = 0; i < 7; i++) {
            aegis128l_update2(this.#blocks, this.#tmpBlock32, this.#tmpBlock32, this.#sBlock32);
        }

        clean(this.#tmpBlock32, this.#sBlock32, this.#zBlock32);

        const tag = new Uint8Array(tag_len);
        const tag32 = u32(tag);
        if (tag.length === 16) {
            // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
            tag32[0] = this.#blocks[0][0] ^ this.#blocks[1][0] ^ this.#blocks[2][0] ^ this.#blocks[3][0] ^ this.#blocks[4][0] ^ this.#blocks[5][0] ^ this.#blocks[6][0];
            tag32[1] = this.#blocks[0][1] ^ this.#blocks[1][1] ^ this.#blocks[2][1] ^ this.#blocks[3][1] ^ this.#blocks[4][1] ^ this.#blocks[5][1] ^ this.#blocks[6][1];
            tag32[2] = this.#blocks[0][2] ^ this.#blocks[1][2] ^ this.#blocks[2][2] ^ this.#blocks[3][2] ^ this.#blocks[4][2] ^ this.#blocks[5][2] ^ this.#blocks[6][2];
            tag32[3] = this.#blocks[0][3] ^ this.#blocks[1][3] ^ this.#blocks[2][3] ^ this.#blocks[3][3] ^ this.#blocks[4][3] ^ this.#blocks[5][3] ^ this.#blocks[6][3];
        } else {
            // tag = (S0 ^ S1 ^ S2 ^ S3) || (S4 ^ S5 ^ S6 ^ S7)
            tag32[0] = this.#blocks[0][0] ^ this.#blocks[1][0] ^ this.#blocks[2][0] ^ this.#blocks[3][0];
            tag32[1] = this.#blocks[0][1] ^ this.#blocks[1][1] ^ this.#blocks[2][1] ^ this.#blocks[3][1];
            tag32[2] = this.#blocks[0][2] ^ this.#blocks[1][2] ^ this.#blocks[2][2] ^ this.#blocks[3][2];
            tag32[3] = this.#blocks[0][3] ^ this.#blocks[1][3] ^ this.#blocks[2][3] ^ this.#blocks[3][3];

            tag32[4] = this.#blocks[4][0] ^ this.#blocks[5][0] ^ this.#blocks[6][0] ^ this.#blocks[7][0];
            tag32[5] = this.#blocks[4][1] ^ this.#blocks[5][1] ^ this.#blocks[6][1] ^ this.#blocks[7][1];
            tag32[6] = this.#blocks[4][2] ^ this.#blocks[5][2] ^ this.#blocks[6][2] ^ this.#blocks[7][2];
            tag32[7] = this.#blocks[4][3] ^ this.#blocks[5][3] ^ this.#blocks[6][3] ^ this.#blocks[7][3];
        }

        return tag;
    }
}

export const aegis128l: ((key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array, options?: AegisCipherOptions) => AegisCipher) & {
    nonceLength: number,
    tagLength: number,
    blockSize: number,
    varSizeNonce: boolean,
} = /* @__PURE__ */ wrapAegisCipher(
    { nonceLength: 16, tagLength: 32, blockSize: 32, varSizeNonce: false },
    function (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array, options?: AegisCipherOptions): AegisCipher {
        const tagLength = options?.tagLength || 32;
        if (![16, 32].includes(tagLength)) throw new Error("Invalid tag length, 16 or 32 bytes expected");
        const state = new Aegis128LState().init(key, nonce);
        return {
            encrypt(plaintext: Uint8Array): Uint8Array {
                const [ct, tag] = aegis_encrypt_detached(state, plaintext, AAD, tagLength);
                return concatBytes(ct, tag);
            },
            encryptDetached(plaintext: Uint8Array): [Uint8Array, Uint8Array] {
                return aegis_encrypt_detached(state, plaintext, AAD, tagLength);
            },
            decrypt(ciphertext: Uint8Array): Uint8Array {
                return aegis_decrypt_detached(state, ciphertext.subarray(0, -tagLength), ciphertext.subarray(-tagLength), AAD);
            },
            decryptDetached(ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
                return aegis_decrypt_detached(state, ciphertext, tag, AAD);
            }
        };
    }
);
