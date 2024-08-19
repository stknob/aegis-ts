
import { isAligned32, concatBytes, copyBytes, equalBytes, wrapCipher } from "@noble/ciphers/utils";
import { clean, u32, u8, u64BitLengths } from "./_utils.mjs";
import { aegis128l_update1, aegis128l_update2, Aegis128LBlocks, aegis256_update, Aegis256Blocks, xor128, xor256 } from "./_aegis.mjs";

// C0: 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
const C0 = Uint32Array.of(0x02010100, 0x0d080503, 0x59372215, 0x6279e990);
// C1: 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
const C1 = Uint32Array.of(0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573);

export class AegisInvalidTagError extends Error {
    constructor() { super("Aegis decryption failed") }
    get name() { return this.constructor.name; }
}

interface AegisState {
    blockSize: number;

    init(key: Uint8Array, nonce: Uint8Array): this;
    absorb(ai: Uint32Array);
    absorbPartial(ai: Uint8Array);
    encBlock(xi: Uint32Array, out: Uint32Array): Uint32Array;
    encPartial(xi: Uint8Array, out: Uint8Array): Uint8Array;
    decBlock(ci: Uint32Array, out: Uint32Array): Uint32Array;
    decPartial(ci: Uint8Array, out: Uint8Array): Uint8Array;
    finalize(ad_len: number, msg_len: number, tag_len: number): Uint8Array;
}

class Aegis128LState implements AegisState {
    #blocks: Aegis128LBlocks;
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
        const tmp = BigUint64Array.of(BigInt(ad_len) << 3n, BigInt(msg_len) << 3n);
        this.#tmpBlock32.set(new Uint32Array(tmp.buffer, tmp.byteOffset, tmp.byteLength >>> 2), 0);

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

class Aegis256State implements AegisState {
    #blocks: Aegis256Blocks;
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

const aegis_encrypt_detached = (state: AegisState, pt: Uint8Array, ad?: Uint8Array, tag_len: number = 32): [Uint8Array, Uint8Array] => {
    const toClean = [];
    if (!isAligned32(pt)) toClean.push((pt = copyBytes(pt)));
    const src32 = u32(pt);

    const ct = new Uint8Array(pt.length);
    const dst32 = u32(ct);

    const blockSizeU8  = state.blockSize;
    const blockSizeU32 = blockSizeU8 >> 2;

    const ad_len = ad?.length || 0;
    if (ad_len) {
        if (!isAligned32(ad)) toClean.push((ad = copyBytes(ad)));
        const ad32 = u32(ad);

        let ad_pos = 0;
        const ad_blocks = Math.floor(ad_len / blockSizeU8);
        for (let i = 0, off = 0; i < ad_blocks; i++) {
            const block = ad32.subarray(off, off + blockSizeU32)
            state.absorb(block);
            ad_pos += blockSizeU8; off += blockSizeU32;
        }
        if (ad_pos < ad_len) {
            state.absorbPartial(ad.subarray(ad_pos, ad_len));
        }
    }

    let pt_pos = 0;
    const pt_len    = pt.length;
    const pt_blocks = Math.floor(pt_len / blockSizeU8);
    for (let i = 0, off = 0; i < pt_blocks; i++) {
        state.encBlock(src32.subarray(off, off + blockSizeU32), dst32.subarray(off, off + blockSizeU32));
        pt_pos += blockSizeU8; off += blockSizeU32;
    }
    if (pt_pos < pt_len) {
        state.encPartial(pt.subarray(pt_pos, pt_len), ct.subarray(pt_pos));
    }

    const tag = state.finalize(ad_len, pt_len, tag_len);
    clean(...toClean);
    return [ct, tag];
}

const aegis_decrypt_detached = (state: AegisState, ct: Uint8Array, tag: Uint8Array, ad?: Uint8Array): Uint8Array => {
    const toClean = [];
    if (!isAligned32(ct)) toClean.push((ct = copyBytes(ct)));
    const src32 = u32(ct);

    const blockSizeU8  = state.blockSize;
    const blockSizeU32 = blockSizeU8 >> 2;

    const msg = new Uint8Array(ct.length);
    const dst32 = u32(msg);

    const ad_len = ad?.length;
    if (ad_len) {
        if (!isAligned32(ad)) toClean.push((ad = copyBytes(ad)));
        const ad32  = u32(ad);

        let ad_pos = 0;
        const ad_blocks = Math.floor(ad_len / blockSizeU8);
        for (let i = 0, off = 0; i < ad_blocks; i++) {
            const block = ad32.subarray(off, off + blockSizeU32)
            state.absorb(block);
            ad_pos += blockSizeU8; off += blockSizeU32;
        }
        if (ad_pos < ad_len) {
            state.absorbPartial(ad.subarray(ad_pos, ad_len));
        }
    }

    let ct_pos = 0;
    const ct_len    = ct.length;
    const ct_blocks = Math.floor(ct_len / blockSizeU8);
    for (let i = 0, off = 0; i < ct_blocks; i++) {
        state.decBlock(src32.subarray(off, off + blockSizeU32), dst32.subarray(off, off + blockSizeU32));
        ct_pos += blockSizeU8; off += blockSizeU32;
    }
    if (ct_pos < ct_len) {
        state.decPartial(ct.subarray(ct_pos, ct_len), msg.subarray(ct_pos));
    }

    const calculatedTag = state.finalize(ad_len, ct_len, tag.length);
    if (!equalBytes(tag, calculatedTag)) {
        clean(dst32, ...toClean); // Wipe plaintext
        throw new AegisInvalidTagError();
    }

    clean(...toClean);
    return msg;
}

export type AegisCipher = {
    encrypt(plaintext: Uint8Array, ad?: Uint8Array): Uint8Array
    decrypt(ciphertext: Uint8Array, ad?: Uint8Array): Uint8Array,
    encrypt_detached(plaintext: Uint8Array, ad?: Uint8Array): [Uint8Array, Uint8Array],
    decrypt_detached(ciphertext: Uint8Array, tag: Uint8Array, ad?: Uint8Array): Uint8Array,
};

export interface AegisOptions {
    tagLength?: number,
};

export const aegis128l = /* @__PURE__ */ wrapCipher({
    nonceLength: 16,
    tagLength: 32,
    blockSize: 32,
}, (key: Uint8Array, nonce: Uint8Array, options?: AegisOptions): AegisCipher => {
    const tagLength = options?.tagLength || 32;
    if (![16, 32].includes(tagLength)) throw new Error("Invalid tag length, 16 or 32 bytes expected");
    const state = new Aegis128LState().init(key, nonce);
    return {
        encrypt(pt: Uint8Array, aad?: Uint8Array): Uint8Array {
            const [ct, tag] = this.encrypt_detached(pt, aad);
            return concatBytes(ct, tag);
        },
        encrypt_detached(pt: Uint8Array, aad?: Uint8Array): [Uint8Array, Uint8Array] {
            return aegis_encrypt_detached(state, pt, aad, tagLength)
        },
        decrypt(ct: Uint8Array, aad?: Uint8Array): Uint8Array {
            return this.decrypt_detached(ct.subarray(0, -tagLength), ct.subarray(-tagLength), aad);
        },
        decrypt_detached(ct: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Uint8Array {
            return aegis_decrypt_detached(state, ct, tag, aad);
        }
    };
});

export const aegis256 = /* @__PURE__ */ wrapCipher({
    nonceLength: 32,
    tagLength: 32,
    blockSize: 16,
}, (key: Uint8Array, nonce: Uint8Array, options?: AegisOptions): AegisCipher => {
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
