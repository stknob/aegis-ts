
import { equalBytes } from "@noble/ciphers/utils";
import { clean, u32, u8 } from "./_utils.mjs";
import { aegis128l_update1, aegis128l_update2, Aegis128LState, aegis256_update, Aegis256State, xor128, xor256 } from "./_aegis.mjs";

const C0 = new Uint32Array(Uint8Array.of(0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62).buffer);
const C1 = new Uint32Array(Uint8Array.of(0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd).buffer);
export class AegisInvalidTagError extends Error {
    constructor() { super("Aegis decryption failed") }
    get name() { return this.constructor.name; }
}

export class Aegis256 {
    #state: Aegis256State;
    #tmpBlock32 = new Uint32Array(4);   // Scratch buffer for generic operations e.g. xor128 and ZeroPad()
    #tmpBlock8  = u8(this.#tmpBlock32); // Uint8Array view into generic scratch buffer for ZeroPad()
    #sBlock32 = new Uint32Array(4);     // Scratch buffer for aegis256_update
    #zBlock32 = new Uint32Array(4);     // Scratch buffer for genZ

    constructor(key: Uint8Array, nonce: Uint8Array) {
        this.#init(key, nonce);
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

    #init(key: Uint8Array, nonce: Uint8Array) {
        const [k0, k1] = this.#split128(key);
        const [n0, n1] = this.#split128(nonce);

        this.#state = [
            xor128(k0, n0, new Uint32Array(4)),
            xor128(k1, n1, new Uint32Array(4)),
            Uint32Array.from(C1),
            Uint32Array.from(C0),
            xor128(k0, C0, new Uint32Array(4)),
            xor128(k1, C1, new Uint32Array(4)),
        ];

        for (let i = 0; i < 4; i++) {
            aegis256_update(this.#state, k0, this.#sBlock32);
            aegis256_update(this.#state, k1, this.#sBlock32);
            aegis256_update(this.#state, xor128(k0, n0, this.#tmpBlock32), this.#sBlock32);
            aegis256_update(this.#state, xor128(k1, n1, this.#tmpBlock32), this.#sBlock32);
        }
    }

    /**
     * Absorbs a full 128bit input block into the Aegis256 state
     * @param ai
     */
    #absorb(ai: Uint32Array) {
        aegis256_update(this.#state, ai, this.#sBlock32);
    }

    #genZ(state: Aegis256State, out: Uint32Array): Uint32Array {
        out[0] = (state[1][0] ^ state[4][0] ^ state[5][0] ^ (state[2][0] & state[3][0]));
        out[1] = (state[1][1] ^ state[4][1] ^ state[5][1] ^ (state[2][1] & state[3][1]));
        out[2] = (state[1][2] ^ state[4][2] ^ state[5][2] ^ (state[2][2] & state[3][2]));
        out[3] = (state[1][3] ^ state[4][3] ^ state[5][3] ^ (state[2][3] & state[3][3]));
        return out;
    }

    #encBlock(xi: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#state, this.#zBlock32);
        aegis256_update(this.#state, xi, this.#sBlock32);
        xor128(xi, z, out);
        return out;
    }

    #decBlock(ci: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#state, this.#zBlock32);
        xor128(ci, z, out);
        aegis256_update(this.#state, out, this.#sBlock32);
        return out;
    }

    #decPartial(ci: Uint8Array, out: Uint8Array): Uint8Array {
        const z = this.#genZ(this.#state, this.#zBlock32);
        this.#tmpBlock8.fill(0).set(ci);  // ZeroPad(ci, 128)
        xor128(this.#tmpBlock32, z, this.#tmpBlock32);

        out.set(this.#tmpBlock8.subarray(0, ci.length));    // xn = Truncate(out, |cn|)
        this.#tmpBlock8.fill(0).set(out);  // ZeroPad(xn, 128)
        aegis256_update(this.#state, this.#tmpBlock32, this.#sBlock32);
        return out;
    }

    #finalize(ad_len: number, msg_len: number, tag: Uint8Array): Uint8Array {
        // LE64(ad_len_bits) || LE64(msg_len_bits)
        const tmp = BigUint64Array.of(BigInt(ad_len) << 3n, BigInt(msg_len) << 3n);
        this.#tmpBlock32.set(new Uint32Array(tmp.buffer, tmp.byteOffset, tmp.byteLength >>> 2));

        // t = S3 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))
        xor128(this.#tmpBlock32, this.#state[3], this.#tmpBlock32);

        for (let i = 0; i < 7; i++) {
            aegis256_update(this.#state, this.#tmpBlock32, this.#sBlock32);
        }

        clean(this.#tmpBlock32, this.#sBlock32, this.#zBlock32);

        const tag32 = u32(tag);
        if (tag.length === 16) {
            // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
            tag32[0] = this.#state[0][0] ^ this.#state[1][0] ^ this.#state[2][0] ^ this.#state[3][0] ^ this.#state[4][0] ^ this.#state[5][0];
            tag32[1] = this.#state[0][1] ^ this.#state[1][1] ^ this.#state[2][1] ^ this.#state[3][1] ^ this.#state[4][1] ^ this.#state[5][1];
            tag32[2] = this.#state[0][2] ^ this.#state[1][2] ^ this.#state[2][2] ^ this.#state[3][2] ^ this.#state[4][2] ^ this.#state[5][2];
            tag32[3] = this.#state[0][3] ^ this.#state[1][3] ^ this.#state[2][3] ^ this.#state[3][3] ^ this.#state[4][3] ^ this.#state[5][3];
        } else {
            // tag = (S0 ^ S1 ^ S2) || (S3 ^ S4 ^ S5)
            tag32[0] = this.#state[0][0] ^ this.#state[1][0] ^ this.#state[2][0];
            tag32[1] = this.#state[0][1] ^ this.#state[1][1] ^ this.#state[2][1];
            tag32[2] = this.#state[0][2] ^ this.#state[1][2] ^ this.#state[2][2];
            tag32[3] = this.#state[0][3] ^ this.#state[1][3] ^ this.#state[2][3];

            tag32[4] = this.#state[3][0] ^ this.#state[4][0] ^ this.#state[5][0];
            tag32[5] = this.#state[3][1] ^ this.#state[4][1] ^ this.#state[5][1];
            tag32[6] = this.#state[3][2] ^ this.#state[4][2] ^ this.#state[5][2];
            tag32[7] = this.#state[3][3] ^ this.#state[4][3] ^ this.#state[5][3];
        }

        clean(...this.#state);
        return tag;
    }

    static encrypt(key: Uint8Array, nonce: Uint8Array, msg: Uint8Array, ad: Uint8Array, tag_len: number = 32): [Uint8Array, Uint8Array] {
        if (tag_len != 16 && tag_len != 32) throw new Error("Invalid tag length: 16 or 32 bytes expected");
        else if (nonce.length != 32) throw new Error("Invalid nonce length: 32 byte expected");

        const prf = new this(key, nonce);
        const ct  = new Uint8Array(msg.length);
        const tag = new Uint8Array(tag_len);

        const ad32  = u32(ad);
        const src32 = u32(msg);
        const dst32 = u32(ct);

        let ad_pos = 0;
        const ad_len    = ad.length;
        const ad_blocks = ad_len >>> 4;
        for (let i = 0, off = 0; i < ad_blocks; i++) {
            const block = ad32.subarray(off, off + 4)
            prf.#absorb(block);
            ad_pos += 16; off += 4;
        }
        if (ad_pos < ad_len) {
            prf.#tmpBlock8.fill(0).set(ad.subarray(ad_pos, ad_len));  // ZeroPad(ad, 128)
            prf.#absorb(prf.#tmpBlock32);
        }

        let msg_pos = 0;
        const msg_len    = msg.length;
        const msg_blocks = msg_len >>> 4;
        for (let i = 0, off = 0; i < msg_blocks; i++) {
            prf.#encBlock(src32.subarray(off, off + 4), dst32.subarray(off, off + 4));
            msg_pos += 16; off += 4;
        }
        if (msg_pos < msg_len) {
            prf.#tmpBlock8.fill(0).set(msg.subarray(msg_pos, msg_len));  // ZeroPad(msg, 128)
            prf.#encBlock(prf.#tmpBlock32, prf.#tmpBlock32);
            ct.set(prf.#tmpBlock8.subarray(0, msg_len - msg_pos), msg_pos);
        }

        prf.#finalize(ad_len, msg_len, tag);
        return [ct, tag];
    }

    static decrypt(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, ad: Uint8Array, tag: Uint8Array): Uint8Array {
        if (tag.length != 16 && tag.length != 32) throw new Error("Invalid tag length: 16 or 32 bytes expected");
        else if (nonce.length != 32) throw new Error("Invalid nonce length: 32 byte expected");

        const prf = new this(key, nonce);
        const msg = new Uint8Array(ct.length);

        const ad32  = u32(ad);
        const src32 = u32(ct);
        const dst32 = u32(msg);

        let ad_pos = 0;
        const ad_len    = ad.length;
        const ad_blocks = ad_len >>> 4;
        for (let i = 0, off = 0; i < ad_blocks; i++) {
            const block = ad32.subarray(off, off + 4)
            prf.#absorb(block);
            ad_pos += 16; off += 4;
        }
        if (ad_pos < ad_len) {
            prf.#tmpBlock8.fill(0).set(ad.subarray(ad_pos, ad_len));  // ZeroPad(ad, 128)
            prf.#absorb(prf.#tmpBlock32);
        }

        let ct_pos = 0;
        const ct_len    = ct.length;
        const ct_blocks = ct_len >>> 4;
        for (let i = 0, off = 0; i < ct_blocks; i++) {
            prf.#decBlock(src32.subarray(off, off + 4), dst32.subarray(off, off + 4));
            ct_pos += 16; off += 4;
        }
        if (ct_pos < ct_len) {
            prf.#decPartial(ct.subarray(ct_pos, ct_len), msg.subarray(ct_pos));
        }

        const calculatedTag = prf.#finalize(ad_len, ct_len, new Uint8Array(tag.length));
        if (!equalBytes(tag, calculatedTag)) {
            clean(dst32); // Wipe plaintext
            throw new AegisInvalidTagError();
        }

        return msg;
    }
}



export class Aegis128L {
    #state: Aegis128LState;
    #tmpBlock32 = new Uint32Array(8);   // Scratch buffer for generic operations e.g. xor128 and ZeroPad()
    #tmpBlock8  = u8(this.#tmpBlock32); // Uint8Array view into generic scratch buffer for ZeroPad()
    #sBlock32 = new Uint32Array(8);     // Scratch buffer for aegis128l_updateX
    #zBlock32 = new Uint32Array(8);     // Scratch buffer for genZ

    constructor(key: Uint8Array, nonce: Uint8Array) {
        this.#init(key, nonce);
    }

    #init(key: Uint8Array, nonce: Uint8Array) {
        const k = u32(key);
        const n = u32(nonce);

        this.#state = [
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
            aegis128l_update2(this.#state, n, k, this.#sBlock32);
        }
    }

    /**
     * Absorbs a full 256bit input block into the Aegis128L state
     * @param ai
     */
    #absorb(ai: Uint32Array) {
        aegis128l_update1(this.#state, ai, this.#sBlock32);
    }

    /**
     * Generate Z0, Z1 as a single 256bit block
     * @param state
     * @param out
     * @returns
     */
    #genZ(state: Aegis128LState, out: Uint32Array): Uint32Array {
        // z0 = S6 ^ S1 ^ (S2 & S3)
        out[0] = (state[6][0] ^ state[1][0] ^ (state[2][0] & state[3][0]));
        out[1] = (state[6][1] ^ state[1][1] ^ (state[2][1] & state[3][1]));
        out[2] = (state[6][2] ^ state[1][2] ^ (state[2][2] & state[3][2]));
        out[3] = (state[6][3] ^ state[1][3] ^ (state[2][3] & state[3][3]));
        // z1 = S2 ^ S5 ^ (S6 & S7)
        out[4] = (state[2][0] ^ state[5][0] ^ (state[6][0] & state[7][0]));
        out[5] = (state[2][1] ^ state[5][1] ^ (state[6][1] & state[7][1]));
        out[6] = (state[2][2] ^ state[5][2] ^ (state[6][2] & state[7][2]));
        out[7] = (state[2][3] ^ state[5][3] ^ (state[6][3] & state[7][3]));
        return out;
    }

    #encBlock(xi: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#state, this.#zBlock32);
        aegis128l_update1(this.#state, xi, this.#sBlock32); // Update(t0, t1)
        xor256(xi, z, out); // ci = t0 ^ z0 || t1 ^ z1
        return out;
    }

    #decBlock(ci: Uint32Array, out: Uint32Array): Uint32Array {
        const z = this.#genZ(this.#state, this.#zBlock32);
        xor256(ci, z, out); // xi = t0 ^ z0 || t1 ^ z1
        aegis128l_update1(this.#state, out, this.#sBlock32);    // Update(t0, t1)
        return out;
    }

    #decPartial(ci: Uint8Array, out: Uint8Array): Uint8Array {
        const z = this.#genZ(this.#state, this.#zBlock32);
        this.#tmpBlock8.fill(0).set(ci);  // ZeroPad(ci, 256)
        xor256(this.#tmpBlock32, z, this.#tmpBlock32);

        out.set(this.#tmpBlock8.subarray(0, ci.length));    // xn = Truncate(out, |cn|)
        this.#tmpBlock8.fill(0).set(out);  // ZeroPad(xn, 256)
        aegis128l_update1(this.#state, this.#tmpBlock32, this.#sBlock32);
        return out;
    }

    #finalize(ad_len: number, msg_len: number, tag: Uint8Array): Uint8Array {
        // LE64(ad_len_bits) || LE64(msg_len_bits)
        const tmp = BigUint64Array.of(BigInt(ad_len) << 3n, BigInt(msg_len) << 3n);
        this.#tmpBlock32.set(new Uint32Array(tmp.buffer, tmp.byteOffset, tmp.byteLength >>> 2), 0);

        // t = S2 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))
        xor128(this.#tmpBlock32, this.#state[2], this.#tmpBlock32);

        for (let i = 0; i < 7; i++) {
            aegis128l_update2(this.#state, this.#tmpBlock32, this.#tmpBlock32, this.#sBlock32);
        }

        clean(this.#tmpBlock32, this.#sBlock32, this.#zBlock32);

        const tag32 = u32(tag);
        if (tag.length === 16) {
            // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
            tag32[0] = this.#state[0][0] ^ this.#state[1][0] ^ this.#state[2][0] ^ this.#state[3][0] ^ this.#state[4][0] ^ this.#state[5][0] ^ this.#state[6][0];
            tag32[1] = this.#state[0][1] ^ this.#state[1][1] ^ this.#state[2][1] ^ this.#state[3][1] ^ this.#state[4][1] ^ this.#state[5][1] ^ this.#state[6][1];
            tag32[2] = this.#state[0][2] ^ this.#state[1][2] ^ this.#state[2][2] ^ this.#state[3][2] ^ this.#state[4][2] ^ this.#state[5][2] ^ this.#state[6][2];
            tag32[3] = this.#state[0][3] ^ this.#state[1][3] ^ this.#state[2][3] ^ this.#state[3][3] ^ this.#state[4][3] ^ this.#state[5][3] ^ this.#state[6][3];
        } else {
            // tag = (S0 ^ S1 ^ S2 ^ S3) || (S4 ^ S5 ^ S6 ^ S7)
            tag32[0] = this.#state[0][0] ^ this.#state[1][0] ^ this.#state[2][0] ^ this.#state[3][0];
            tag32[1] = this.#state[0][1] ^ this.#state[1][1] ^ this.#state[2][1] ^ this.#state[3][1];
            tag32[2] = this.#state[0][2] ^ this.#state[1][2] ^ this.#state[2][2] ^ this.#state[3][2];
            tag32[3] = this.#state[0][3] ^ this.#state[1][3] ^ this.#state[2][3] ^ this.#state[3][3];

            tag32[4] = this.#state[4][0] ^ this.#state[5][0] ^ this.#state[6][0] ^ this.#state[7][0];
            tag32[5] = this.#state[4][1] ^ this.#state[5][1] ^ this.#state[6][1] ^ this.#state[7][1];
            tag32[6] = this.#state[4][2] ^ this.#state[5][2] ^ this.#state[6][2] ^ this.#state[7][2];
            tag32[7] = this.#state[4][3] ^ this.#state[5][3] ^ this.#state[6][3] ^ this.#state[7][3];
        }

        clean(...this.#state);
        return tag;
    }

    static encrypt(key: Uint8Array, nonce: Uint8Array, msg: Uint8Array, ad: Uint8Array, tag_len: number = 32): [Uint8Array, Uint8Array] {
        if (tag_len != 16 && tag_len != 32) throw new Error("Invalid tag length: 16 or 32 bytes expected");
        else if (nonce.length != 16) throw new Error("Invalid nonce length: 16 byte expected");

        const prf = new this(key, nonce);
        const ct  = new Uint8Array(msg.length);
        const tag = new Uint8Array(tag_len);

        const ad32  = u32(ad);
        const src32 = u32(msg);
        const dst32 = u32(ct);

        let ad_pos = 0;
        const ad_len    = ad.length;
        const ad_blocks = ad_len >>> 5;
        for (let i = 0, off = 0; i < ad_blocks; i++) {
            const block = ad32.subarray(off, off + 8)
            prf.#absorb(block);
            ad_pos += 32; off += 8;
        }
        if (ad_pos < ad_len) {
            prf.#tmpBlock8.fill(0).set(ad.subarray(ad_pos, ad_len));  // ZeroPad(ad, 256)
            prf.#absorb(prf.#tmpBlock32);
        }

        let msg_pos = 0;
        const msg_len    = msg.length;
        const msg_blocks = msg_len >>> 5;
        for (let i = 0, off = 0; i < msg_blocks; i++) {
            prf.#encBlock(src32.subarray(off, off + 8), dst32.subarray(off, off + 8));
            msg_pos += 32; off += 8;
        }
        if (msg_pos < msg_len) {
            prf.#tmpBlock8.fill(0).set(msg.subarray(msg_pos, msg_len));  // ZeroPad(msg, 128)
            prf.#encBlock(prf.#tmpBlock32, prf.#tmpBlock32);
            ct.set(prf.#tmpBlock8.subarray(0, msg_len - msg_pos), msg_pos);
        }

        prf.#finalize(ad_len, msg_len, tag);
        return [ct, tag];
    }

    static decrypt(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, ad: Uint8Array, tag: Uint8Array): Uint8Array {
        if (tag.length != 16 && tag.length != 32) throw new Error("Invalid tag length: 16 or 32 bytes expected");
        else if (nonce.length != 16) throw new Error("Invalid nonce length: 16 byte expected");

        const prf = new this(key, nonce);
        const msg = new Uint8Array(ct.length);

        const ad32  = u32(ad);
        const src32 = u32(ct);
        const dst32 = u32(msg);

        let ad_pos = 0;
        const ad_len    = ad.length;
        const ad_blocks = ad_len >>> 5;
        for (let i = 0, off = 0; i < ad_blocks; i++) {
            const block = ad32.subarray(off, off + 8)
            prf.#absorb(block);
            ad_pos += 32; off += 8;
        }
        if (ad_pos < ad_len) {
            prf.#tmpBlock8.fill(0).set(ad.subarray(ad_pos, ad_len));  // ZeroPad(ad, 128)
            prf.#absorb(prf.#tmpBlock32);
        }

        let ct_pos = 0;
        const ct_len    = ct.length;
        const ct_blocks = ct_len >>> 5;
        for (let i = 0, off = 0; i < ct_blocks; i++) {
            prf.#decBlock(src32.subarray(off, off + 8), dst32.subarray(off, off + 8));
            ct_pos += 32; off += 8;
        }
        if (ct_pos < ct_len) {
            prf.#decPartial(ct.subarray(ct_pos, ct_len), msg.subarray(ct_pos));
        }

        const calculatedTag = prf.#finalize(ad_len, ct_len, new Uint8Array(tag.length));
        if (!equalBytes(tag, calculatedTag)) {
            clean(dst32); // Wipe plaintext
            throw new AegisInvalidTagError();
        }

        return msg;
    }
}
