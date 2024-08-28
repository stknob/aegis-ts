import { isAligned32, concatBytes, copyBytes, wrapCipher, clean, u32, u8 } from "@noble/ciphers/utils";
import { aegis_decrypt_detached, aegis_encrypt_detached, type AegisCipher, type AegisCipherOptions, type AegisState, C0, C1, set128, xor128 } from "./_aegis.mjs";
import { u64BitLengths } from "./_utils.mjs";
import { AESRound } from "./_aes.mjs";

export type Aegis256Blocks = [
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
    Uint32Array, Uint32Array
];

const DUMMY_BLOCKS: Aegis256Blocks = [
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
    Uint32Array.of(0, 0, 0, 0),
];

/**
 * Aegis256 state update function, extracted for testability
 * @param blocks
 * @param msg
 * @returns
 */
export function aegis256_update(blocks: Aegis256Blocks, msg: Uint32Array, tmp: Uint32Array): Aegis256Blocks {
    const sm0 = AESRound(blocks[5], xor128(blocks[0], msg, tmp));
    const sm1 = AESRound(blocks[0], blocks[1]);
    const sm2 = AESRound(blocks[1], blocks[2]);
    const sm3 = AESRound(blocks[2], blocks[3]);
    const sm4 = AESRound(blocks[3], blocks[4]);
    const sm5 = AESRound(blocks[4], blocks[5]);

    set128(blocks[0], sm0);
    set128(blocks[1], sm1);
    set128(blocks[2], sm2);
    set128(blocks[3], sm3);
    set128(blocks[4], sm4);
    set128(blocks[5], sm5);
    return blocks;
}

class Aegis256State implements AegisState {
    #blocks: Aegis256Blocks = DUMMY_BLOCKS;
    #tmpBlock32 = new Uint32Array(4);   // Scratch buffer for generic operations e.g. xor128 and ZeroPad()
    #tmpBlock8  = u8(this.#tmpBlock32); // Uint8Array view into generic scratch buffer for ZeroPad()
    #sBlock32 = new Uint32Array(4);     // Scratch buffer for aegis256_update
    #zBlock32 = new Uint32Array(4);     // Scratch buffer for genZ

    get blockSize(): number {
        return 16;
    }

    /**
     * Splits a 256bit input block into two 128bit ones
     * @param inp
     * @returns
     */
    #split128(inp: Uint8Array): Array<Uint32Array> {
        return [
            new Uint32Array(inp.buffer,  0, 4),
            new Uint32Array(inp.buffer, 16, 4),
        ];
    }

    init(key: Uint8Array, nonce: Uint8Array): this {
        if (key.length != 32) throw new Error("Invalid key size, expected 32 bytes");
        else if (nonce.length != 32) throw new Error("Invalid nonce size, expected 32 bytes");

        const toClean = [];
        if (!isAligned32(key)) toClean.push((key = copyBytes(key)));
        const [k0, k1] = this.#split128(key);

        if (!isAligned32(nonce)) toClean.push((nonce = copyBytes(nonce)));
        const [n0, n1] = this.#split128(nonce);

        this.#blocks = [
            xor128(k0, n0, new Uint32Array(4)),
            xor128(k1, n1, new Uint32Array(4)),
            Uint32Array.from(C1),
            Uint32Array.from(C0),
            xor128(k0, C0, new Uint32Array(4)),
            xor128(k1, C1, new Uint32Array(4)),
        ];

        for (let i = 0; i < 4; i++) {
            aegis256_update(this.#blocks, k0, this.#sBlock32);
            aegis256_update(this.#blocks, k1, this.#sBlock32);
            aegis256_update(this.#blocks, xor128(k0, n0, this.#sBlock32), this.#sBlock32);
            aegis256_update(this.#blocks, xor128(k1, n1, this.#sBlock32), this.#sBlock32);
        }

        clean(...toClean);
        return this;
    }

    /**
     * Absorbs a full 128bit input block into the Aegis256 state
     * @param ai
     */
    absorb(ai: Uint32Array) {
        aegis256_update(this.#blocks, ai, this.#sBlock32);
    }

    absorbPartial(ai: Uint8Array) {
        this.#tmpBlock8.fill(0).set(ai);    // ZeroPad(ai, 128)
        aegis256_update(this.#blocks, this.#tmpBlock32, this.#sBlock32);
    }

    #genZ(blocks: Aegis256Blocks, out: Uint32Array): Uint32Array {
        out[0] = (blocks[1][0] ^ blocks[4][0] ^ blocks[5][0] ^ (blocks[2][0] & blocks[3][0]));
        out[1] = (blocks[1][1] ^ blocks[4][1] ^ blocks[5][1] ^ (blocks[2][1] & blocks[3][1]));
        out[2] = (blocks[1][2] ^ blocks[4][2] ^ blocks[5][2] ^ (blocks[2][2] & blocks[3][2]));
        out[3] = (blocks[1][3] ^ blocks[4][3] ^ blocks[5][3] ^ (blocks[2][3] & blocks[3][3]));
        return out;
    }

    encBlock(xi: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#blocks, this.#zBlock32);
        aegis256_update(this.#blocks, xi, this.#sBlock32);
        xor128(xi, z, out);
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
        xor128(ci, z, out);
        aegis256_update(this.#blocks, out, this.#sBlock32);
        return out;
    }

    decPartial(ci: Uint8Array, out: Uint8Array): Uint8Array {
        const z = this.#genZ(this.#blocks, this.#zBlock32);
        this.#tmpBlock8.fill(0).set(ci);  // ZeroPad(ci, 128)
        xor128(this.#tmpBlock32, z, this.#tmpBlock32);

        out.set(this.#tmpBlock8.subarray(0, ci.length));    // xn = Truncate(out, |cn|)
        this.#tmpBlock8.fill(0).set(out);  // ZeroPad(xn, 128)
        aegis256_update(this.#blocks, this.#tmpBlock32, this.#sBlock32);
        return out;
    }

    finalize(ad_len: number, msg_len: number, tag_len: number): Uint8Array {
        // LE64(ad_len_bits) || LE64(msg_len_bits)
        const tmp = u64BitLengths(BigInt(ad_len) << 3n, BigInt(msg_len) << 3n);
        this.#tmpBlock32.set(new Uint32Array(tmp.buffer, tmp.byteOffset, tmp.byteLength >>> 2));

        // t = S3 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))
        xor128(this.#tmpBlock32, this.#blocks[3], this.#tmpBlock32);

        for (let i = 0; i < 7; i++) {
            aegis256_update(this.#blocks, this.#tmpBlock32, this.#sBlock32);
        }

        clean(this.#tmpBlock32, this.#sBlock32, this.#zBlock32);

        const tag = new Uint8Array(tag_len);
        const tag32 = u32(tag);
        if (tag.length === 16) {
            // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
            tag32[0] = this.#blocks[0][0] ^ this.#blocks[1][0] ^ this.#blocks[2][0] ^ this.#blocks[3][0] ^ this.#blocks[4][0] ^ this.#blocks[5][0];
            tag32[1] = this.#blocks[0][1] ^ this.#blocks[1][1] ^ this.#blocks[2][1] ^ this.#blocks[3][1] ^ this.#blocks[4][1] ^ this.#blocks[5][1];
            tag32[2] = this.#blocks[0][2] ^ this.#blocks[1][2] ^ this.#blocks[2][2] ^ this.#blocks[3][2] ^ this.#blocks[4][2] ^ this.#blocks[5][2];
            tag32[3] = this.#blocks[0][3] ^ this.#blocks[1][3] ^ this.#blocks[2][3] ^ this.#blocks[3][3] ^ this.#blocks[4][3] ^ this.#blocks[5][3];
        } else {
            // tag = (S0 ^ S1 ^ S2) || (S3 ^ S4 ^ S5)
            tag32[0] = this.#blocks[0][0] ^ this.#blocks[1][0] ^ this.#blocks[2][0];
            tag32[1] = this.#blocks[0][1] ^ this.#blocks[1][1] ^ this.#blocks[2][1];
            tag32[2] = this.#blocks[0][2] ^ this.#blocks[1][2] ^ this.#blocks[2][2];
            tag32[3] = this.#blocks[0][3] ^ this.#blocks[1][3] ^ this.#blocks[2][3];

            tag32[4] = this.#blocks[3][0] ^ this.#blocks[4][0] ^ this.#blocks[5][0];
            tag32[5] = this.#blocks[3][1] ^ this.#blocks[4][1] ^ this.#blocks[5][1];
            tag32[6] = this.#blocks[3][2] ^ this.#blocks[4][2] ^ this.#blocks[5][2];
            tag32[7] = this.#blocks[3][3] ^ this.#blocks[4][3] ^ this.#blocks[5][3];
        }

        return tag;
    }
}

export const aegis256 = /* @__PURE__ */ wrapCipher({
    nonceLength: 32,
    tagLength: 32,
    blockSize: 16,
}, (key: Uint8Array, nonce: Uint8Array, options?: AegisCipherOptions): AegisCipher => {
    const tagLength = options?.tagLength || 32;
    if (![16, 32].includes(tagLength)) throw new Error("Invalid tag length, 16 or 32 bytes expected");
    const state = new Aegis256State().init(key, nonce);
    return {
        encrypt(pt: Uint8Array, aad?: Uint8Array): Uint8Array {
            const [ct, tag] = aegis_encrypt_detached(state, pt, aad, tagLength);
            return concatBytes(ct, tag);
        },
        encrypt_detached(pt: Uint8Array, aad?: Uint8Array): [Uint8Array, Uint8Array] {
            return aegis_encrypt_detached(state, pt, aad, tagLength);
        },
        decrypt(ct: Uint8Array, aad?: Uint8Array): Uint8Array {
            return aegis_decrypt_detached(state, ct.subarray(0, -tagLength), ct.subarray(-tagLength), aad);
        },
        decrypt_detached(ct: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Uint8Array {
            return aegis_decrypt_detached(state, ct, tag, aad);
        }
    };
});
