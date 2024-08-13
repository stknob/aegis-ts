
import { bytesToHex, equalBytes, hexToBytes, TypedArray } from "@noble/ciphers/utils";

const C0 = new Uint32Array(Uint8Array.of(0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62).buffer);
const C1 = new Uint32Array(Uint8Array.of(0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd).buffer);

const u32 = (arr: Uint8Array) => new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >>> 2);
const  u8 = (arr: Uint32Array) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);

const clean = (...arrays: TypedArray[]) => {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
};

const POLY = 0x11b; // 1 + x + x**3 + x**4 + x**8

// TODO: remove multiplication, binary ops only
function mul2(n: number) {
    return (n << 1) ^ (POLY & -(n >> 7));
}
  
function mul(a: number, b: number) {
    let res = 0;
    for (; b > 0; b >>= 1) {
        // Montgomery ladder
        res ^= a & -(b & 1); // if (b&1) res ^=a (but const-time).
        a = mul2(a); // a = 2*a
    }
    return res;
}
  
// AES S-box is generated using finite field inversion,
// an affine transform, and xor of a constant 0x63.
const sbox = /* @__PURE__ */ (() => {
    const t = new Uint8Array(256);
    for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x)) t[i] = x;
    const box = new Uint8Array(256);
    box[0] = 0x63; // first elm
    for (let i = 0; i < 255; i++) {
        let x = t[255 - i];
        x |= x << 8;
        box[t[i]] = (x ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63) & 0xff;
    }
    clean(t);
    return box;
})();
  
const rotl32_8 = (n: number) => (n << 8) | (n >>> 24);
  
// T-table is optimization suggested in 5.2 of original proposal (missed from FIPS-197). Changes:
// - LE instead of BE
// - bigger tables: T0 and T1 are merged into T01 table and T2 & T3 into T23;
//   so index is u16, instead of u8. This speeds up things, unexpectedly
function genTtable(sbox: Uint8Array, fn: (n: number) => number) {
    if (sbox.length !== 256) throw new Error('Wrong sbox length');
    const T0 = new Uint32Array(256).map((_, j) => fn(sbox[j]));
    const T1 = T0.map(rotl32_8);
    const T2 = T1.map(rotl32_8);
    const T3 = T2.map(rotl32_8);
    const T01 = new Uint32Array(256 * 256);
    const T23 = new Uint32Array(256 * 256);
    for (let i = 0; i < 256; i++) {
        for (let j = 0; j < 256; j++) {
            const idx = i * 256 + j;
            T01[idx] = T0[i] ^ T1[j];
            T23[idx] = T2[i] ^ T3[j];
        }
    }
    return { T01, T23 };
}
  
const tableEncoding = /* @__PURE__ */ genTtable(
    sbox,
    (s: number) => (mul(s, 3) << 24) | (s << 16) | (s << 8) | mul(s, 2)
);

function apply0123(
    T01: Uint32Array,
    T23: Uint32Array,
    s0: number,
    s1: number,
    s2: number,
    s3: number
) {
    return (
        T01[((s0 << 8) & 0xff00) | ((s1 >>> 8) & 0xff)] ^
        T23[((s2 >>> 8) & 0xff00) | ((s3 >>> 24) & 0xff)]
    );
}

type AESRoundResult = { t0: number, t1: number, t2: number, t3: number };

/**
 * AES round function
 * @param inp 
 * @param rk 
 * @returns 
 */
function AESRound(inp: Uint32Array, rk: Uint32Array): AESRoundResult {
    const { T01, T23 } = tableEncoding;
    const [s0, s1, s2, s3] = inp;

    const t0 = rk[0] ^ apply0123(T01, T23, s0, s1, s2, s3);
    const t1 = rk[1] ^ apply0123(T01, T23, s1, s2, s3, s0);
    const t2 = rk[2] ^ apply0123(T01, T23, s2, s3, s0, s1);
    const t3 = rk[3] ^ apply0123(T01, T23, s3, s0, s1, s2);
    return { t0, t1, t2, t3 };
}

type Aegis256State = [Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array];
class AegisDecryptionError extends Error {
    constructor() { super("Aegis decryption failed") }
    get name() { return this.constructor.name; }
}

function xor128(a: Uint32Array, b: Uint32Array, out: Uint32Array): Uint32Array {
    out[0] = a[0] ^ b[0];
    out[1] = a[1] ^ b[1];
    out[2] = a[2] ^ b[2];
    out[3] = a[3] ^ b[3];
    return out;
}

function set128(out: Uint32Array, inp: AESRoundResult): Uint32Array {
    out[0] = inp.t0;
    out[1] = inp.t1;
    out[2] = inp.t2;
    out[3] = inp.t3;
    return out;
}

/**
 * Aegis256 state update function, extracted for testability
 * @param state 
 * @param msg 
 * @returns 
 */
function aegis256_update(state: Aegis256State, msg: Uint32Array, tmp: Uint32Array): Aegis256State {
    const sm0 = AESRound(state[5], xor128(state[0], msg, tmp));
    const sm1 = AESRound(state[0], state[1]);
    const sm2 = AESRound(state[1], state[2]);
    const sm3 = AESRound(state[2], state[3]);
    const sm4 = AESRound(state[3], state[4]);
    const sm5 = AESRound(state[4], state[5]);

    set128(state[0], sm0);
    set128(state[1], sm1);
    set128(state[2], sm2);
    set128(state[3], sm3);
    set128(state[4], sm4);
    set128(state[5], sm5);
    return state;
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
            clean(dst32); // Wipe plaintext and state
            throw new AegisDecryptionError();
        }

        return msg;
    }
}


type Aegis128LState = [
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
];

function xor256(a: Uint32Array, b: Uint32Array, out: Uint32Array): Uint32Array {
    // first 128bit block
    out[0] = a[0] ^ b[0];
    out[1] = a[1] ^ b[1];
    out[2] = a[2] ^ b[2];
    out[3] = a[3] ^ b[3];
    // second 128bit block
    out[4] = a[4] ^ b[4];
    out[5] = a[5] ^ b[5];
    out[6] = a[6] ^ b[6];
    out[7] = a[7] ^ b[7];
    return out;
}


/**
 * Aegis128L state update function with single 256bit input block, extracted for testability
 * @param state 
 * @param msg 
 * @returns 
 */
function aegis128l_update1(state: Aegis128LState, msg: Uint32Array, tmp: Uint32Array): Aegis128LState {
    return aegis128l_update2(state, msg.subarray(0, 4), msg.subarray(4, 8), tmp);
}

/**
 * Aegis128L state update function with two 128bit input blocks, extracted for testability
 * @param state 
 * @param msg 
 * @returns 
 */
function aegis128l_update2(state: Aegis128LState, m0: Uint32Array, m1: Uint32Array, tmp: Uint32Array): Aegis128LState {
    const sm0 = AESRound(state[7], xor128(state[0], m0, tmp));
    const sm1 = AESRound(state[0], state[1]);
    const sm2 = AESRound(state[1], state[2]);
    const sm3 = AESRound(state[2], state[3]);
    const sm4 = AESRound(state[3], xor128(state[4], m1, tmp));
    const sm5 = AESRound(state[4], state[5]);
    const sm6 = AESRound(state[5], state[6]);
    const sm7 = AESRound(state[6], state[7]);

    set128(state[0], sm0);
    set128(state[1], sm1);
    set128(state[2], sm2);
    set128(state[3], sm3);
    set128(state[4], sm4);
    set128(state[5], sm5);
    set128(state[6], sm6);
    set128(state[7], sm7);
    return state;
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
            // const block = prf.#pack128(ad.subarray(ad_pos, ad_pos + 32), prf.#tmpBlock);
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
            clean(dst32); // Wipe plaintext and state
            throw new AegisDecryptionError();
        }

        return msg;
    }
}




(() => {
    const aesRoundIn = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const aesRoundRk = hexToBytes("101112131415161718191a1b1c1d1e1f");
    const aesRoundRs = hexToBytes("7a7b4e5638782546a8c0477a3b813f43");

    const result = AESRound(u32(aesRoundIn), u32(aesRoundRk));
    const aesRoundOut = u8(Uint32Array.of(result.t0, result.t1, result.t2, result.t3));
    console.log(bytesToHex(aesRoundOut), equalBytes(aesRoundOut, aesRoundRs));
})();


(() => {
    // Aegis256 update check
    const message = "b165617ed04ab738afb2612c6d18a1ec";
    const beforeState = [
        "1fa1207ed76c86f2c4bb40e8b395b43e",
        "b44c375e6c1e1978db64bcd12e9e332f",
        "0dab84bfa9f0226432ff630f233d4e5b",
        "d7ef65c9b93e8ee60c75161407b066e7",
        "a760bb3da073fbd92bdc24734b1f56fb",
        "a828a18d6a964497ac6e7e53c5f55c73",
    ];

    const afterState = [
        "e6bc643bae82dfa3d991b1b323839dcd",
        "648578232ba0f2f0a3677f617dc052c3",
        "ea788e0e572044a46059212dd007a789",
        "2f1498ae19b80da13fba698f088a8590",
        "a54c2ee95e8c2a2c3dae2ec743ae6b86",
        "a3240fceb68e32d5d114df1b5363ab67",
    ];

    const inp = beforeState.map((v) => u32(hexToBytes(v))) as Aegis256State;
    const out = afterState.map((v) => u32(hexToBytes(v))) as Aegis256State;
    const msg = u32(hexToBytes(message));
    const result = aegis256_update(inp, msg, new Uint32Array(4));
    console.log("Aegis256", result.map((v, i) => equalBytes(u8(v), u8(out[i])) ));
})();

(() => {
    // Aegis128L update check
    const message = "033e6975b94816879e42917650955aa0";
    const beforeState = [
        "9b7e60b24cc873ea894ecc07911049a3",
        "330be08f35300faa2ebf9a7b0d274658",
        "7bbd5bd2b049f7b9b515cf26fbe7756c",
        "c35a00f55ea86c3886ec5e928f87db18",
        "9ebccafce87cab446396c4334592c91f",
        "58d83e31f256371e60fc6bb257114601",
        "1639b56ea322c88568a176585bc915de",
        "640818ffb57dc0fbc2e72ae93457e39a",
    ];

    const afterState = [
        "596ab773e4433ca0127c73f60536769d",
        "790394041a3d26ab697bde865014652d",
        "38cf49e4b65248acd533041b64dd0611",
        "16d8e58748f437bfff1797f780337cee",
        "69761320f7dd738b281cc9f335ac2f5a",
        "a21746bb193a569e331e1aa985d0d729",
        "09d714e6fcf9177a8ed1cde7e3d259a6",
        "61279ba73167f0ab76f0a11bf203bdff",
    ];

    const inp = beforeState.map((v) => u32(hexToBytes(v))) as Aegis128LState;
    const out = afterState.map((v) => u32(hexToBytes(v))) as Aegis128LState;
    const msg = u32(hexToBytes(message));
    const result = aegis128l_update2(inp, msg, msg, new Uint32Array(8));
    console.log("Aegis128L", result.map((v, i) => equalBytes(u8(v), u8(out[i])) ));
})();


const AEGIS128L_TEST_VECTORS = [{
    // Aegis128L testvector #1
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     Uint8Array.from([]),
    msg:    hexToBytes("00000000000000000000000000000000"),
    ct:     hexToBytes("c1c0e58bd913006feba00f4b3cc3594e"),
    tag128: hexToBytes("abe0ece80c24868a226a35d16bdae37a"),
    tag256: hexToBytes("25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4"),
    valid:  true,
}, {
    // Aegis128L testvector #2
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     Uint8Array.from([]),
    msg:    Uint8Array.from([]),
    ct:     Uint8Array.from([]),
    tag128: hexToBytes("c2b879a67def9d74e6c14f708bbcc9b4"),
    tag256: hexToBytes("1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d"),
    valid:  true,
}, {
    // Aegis128L testvector #3
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    ct:     hexToBytes("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84"),
    tag128: hexToBytes("cc6f3372f6aa1bb82388d695c3962d9a"),
    tag256: hexToBytes("022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3"),
    valid:  true,
}, {
    // Aegis128L testvector #4
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    hexToBytes("000102030405060708090a0b0c0d"),
    ct:     hexToBytes("79d94593d8c2119d7e8fd9b8fc77"),
    tag128: hexToBytes("5c04b3dba849b2701effbe32c7f0fab7"),
    tag256: hexToBytes("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
    valid:  true,
}, {
    // Aegis128L testvector #5
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"),
    msg:    hexToBytes("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"),
    ct:     hexToBytes("b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10"),
    tag128: hexToBytes("7542a745733014f9474417b337399507"),
    tag256: hexToBytes("b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98"),
    valid:  true,
}, {
    // Aegis128L testvector #6
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("79d94593d8c2119d7e8fd9b8fc77"),
    tag128: hexToBytes("5c04b3dba849b2701effbe32c7f0fab7"),
    tag256: hexToBytes("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis128L testvector #7
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("79d94593d8c2119d7e8fd9b8fc78"),
    tag128: hexToBytes("5c04b3dba849b2701effbe32c7f0fab7"),
    tag256: hexToBytes("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis128L testvector #8
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("0001020304050608"),
    msg:    null,
    ct:     hexToBytes("79d94593d8c2119d7e8fd9b8fc77"),
    tag128: hexToBytes("5c04b3dba849b2701effbe32c7f0fab7"),
    tag256: hexToBytes("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis128L testvector #9
    key:    hexToBytes("10010000000000000000000000000000"),
    nonce:  hexToBytes("10000200000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("79d94593d8c2119d7e8fd9b8fc77"),
    tag128: hexToBytes("6c04b3dba849b2701effbe32c7f0fab8"),
    tag256: hexToBytes("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad"),
    decryptOnly: true,
    valid: false,
}];

const AEGIS256_TEST_VECTORS = [{
    // Aegis256 testvector #1
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     Uint8Array.from([]),
    msg:    hexToBytes("00000000000000000000000000000000"),
    ct:     hexToBytes("754fc3d8c973246dcc6d741412a4b236"),
    tag128: hexToBytes("3fe91994768b332ed7f570a19ec5896e"),
    tag256: hexToBytes("1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"),
    valid:  true,
}, {
    // Aegis256 testvector #2
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     Uint8Array.from([]),
    msg:    Uint8Array.from([]),
    ct:     Uint8Array.from([]),
    tag128: hexToBytes("e3def978a0f054afd1e761d7553afba3"),
    tag256: hexToBytes("6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"),
    valid:  true,
}, {
    // Aegis256 testvector #3
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    ct:     hexToBytes("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"),
    tag128: hexToBytes("8d86f91ee606e9ff26a01b64ccbdd91d"),
    tag256: hexToBytes("b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"),
    valid:  true,
}, {
    // Aegis256 testvector #4
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    hexToBytes("000102030405060708090a0b0c0d"),
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    valid:  true,
}, {
    // Aegis256 testvector #5
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"),
    msg:    hexToBytes("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"),
    ct:     hexToBytes("57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67"),
    tag128: hexToBytes("ab8a7d53fd0e98d727accca94925e128"),
    tag256: hexToBytes("a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734"),
    valid:  true,
}, {
    // Aegis256 testvector #6
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis256 testvector #7
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358459"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis256 testvector #8
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050608"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis256 testvector #9
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215653"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da"),
    decryptOnly: true,
    valid: false,
}];

function runAegisTestVectors(name, clazz, vectors) {
    for (const [idx, desc] of vectors.entries()) {
        if (!desc.decryptOnly) {
            const [ct, tag256] = clazz.encrypt(desc.key, desc.nonce, desc.msg, desc.ad, 32);
            const [__, tag128] = clazz.encrypt(desc.key, desc.nonce, desc.msg, desc.ad, 16);

            if (!equalBytes(desc.ct, ct)) throw new Error(`${name} testvector #${idx + 1} failed ciphertext validation: expected '${bytesToHex(desc.ct)}' got '${bytesToHex(ct)}'`);
            if (!equalBytes(desc.tag128, tag128)) throw new Error(`${name} testvector #${idx + 1} failed 128bit tag: expected '${bytesToHex(desc.tag128)}' got '${bytesToHex(tag128)}'`);
            if (!equalBytes(desc.tag256, tag256)) throw new Error(`${name} testvector #${idx + 1} failed 256bit tag: expected '${bytesToHex(desc.tag256)}' got '${bytesToHex(tag256)}'`);
        }

        try {
            const pt = clazz.decrypt(desc.key, desc.nonce, desc.ct, desc.ad, desc.tag256);
            const isValid = pt && desc.msg ? equalBytes(pt, desc.msg) : false;
            if (desc.valid && pt == null) throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 256bit tag: expected '${bytesToHex(desc.msg)}' got 'null'`);
            else if (desc.valid && !isValid) throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 256bit tag: expected '${bytesToHex(desc.msg)}' got '${bytesToHex(pt)}'`);
            else if (!desc.valid && isValid) throw new Error(`${name} testvector #${idx + 1} succeeded decryption w/ 256bit tag: expected 'rejected' got '${bytesToHex(pt)}'`);
        } catch (err) {
            if (err.name == "AegisDecryptionError") {
                if (desc.valid) throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 256bit tag: expected '${bytesToHex(desc.msg)}' got 'rejected'`, err);
            } else {
                throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 256bit tag: expected '${desc.valid ? bytesToHex(desc.msg) : 'rejected'}' got 'error'`, err);
            }
        }

        try {
            const pt = clazz.decrypt(desc.key, desc.nonce, desc.ct, desc.ad, desc.tag128);
            const isValid = pt && desc.msg ? equalBytes(pt, desc.msg) : false;
            if (desc.valid && pt == null) throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 128bit tag: expected '${bytesToHex(desc.msg)}' got 'null'`);
            else if (desc.valid && !isValid) throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 128bit tag: expected '${bytesToHex(desc.msg)}' got '${bytesToHex(pt)}'`);
            else if (!desc.valid && isValid) throw new Error(`${name} testvector #${idx + 1} succeeded decryption w/ 128bit tag: expected 'rejected' got '${bytesToHex(pt)}'`);
        } catch (err) {
            if (err.name == "AegisDecryptionError") {
                if (desc.valid) throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 128bit tag: expected '${bytesToHex(desc.msg)}' got 'rejected'`, err);
            } else {
                throw new Error(`${name} testvector #${idx + 1} failed decryption w/ 128bit tag: expected '${desc.valid ? bytesToHex(desc.msg) : 'rejected'}' got 'error'`, err);
            }
        }
    }
}

(() => {
    runAegisTestVectors("Aegis128L", Aegis128L, AEGIS128L_TEST_VECTORS);
    runAegisTestVectors("Aegis256",  Aegis256,  AEGIS256_TEST_VECTORS);
})();


const formatByteRate = (rate: number) => {
    const units = ["iB", "KiB", "MiB", "GiB", "TiB", "PiB"];
    const divisor = 1024;

    let magnitude = 0;
    while (rate >= divisor && magnitude < units.length) {
        rate /= divisor;
        magnitude++;
    }

    /* Limit to one digit */
    rate = Math.floor(rate * 10) / 10;
    return `${rate <= 0 ? "-" : rate} ${units[magnitude]}/s`;
};

console.log("\n--------------------------------------------------------------------------------------\n");

(() => {
    // Aegis128L benchmark
    const key   = hexToBytes("10010000000000000000000000000000");
    const nonce = hexToBytes("10000200000000000000000000000000");
    const msg   = new Uint8Array(64);
    const ad    = hexToBytes("0001020304050607");
    const [ct, tag] = Aegis128L.encrypt(key, nonce, msg, ad);

    const rounds = 1_000_000;
    const start = Date.now();
    for (let i = 0; i < rounds; i++) {
        const pt = Aegis128L.decrypt(key, nonce, ct, ad, tag);
        if (!equalBytes(msg, pt)) throw new Error("foobar");
    }
    const msec = Date.now() - start;

    const msec_per_op = msec / rounds;
    const ops_per_sec = 1000 / msec_per_op;
    console.log("Aegis128L@%d: %d ms => %s msec/op (%s ops/s) = %s",
        msg.length, msec, msec_per_op.toFixed(3), ops_per_sec.toFixed(2),
        formatByteRate(msg.length * ops_per_sec));
})();

(() => {
    // Aegis256 benchmark
    const key   = hexToBytes("1001000000000000000000000000000000000000000000000000000000000000");
    const nonce = hexToBytes("1000020000000000000000000000000000000000000000000000000000000000");
    const msg   = new Uint8Array(64);
    const ad    = hexToBytes("0001020304050607");
    const [ct, tag] = Aegis256.encrypt(key, nonce, msg, ad);

    const rounds = 1_000_000;
    const start = Date.now();
    for (let i = 0; i < rounds; i++) {
        const pt = Aegis256.decrypt(key, nonce, ct, ad, tag);
        if (!equalBytes(msg, pt)) throw new Error("foobar");
    }
    const msec = Date.now() - start;

    const msec_per_op = msec / rounds;
    const ops_per_sec = 1000 / msec_per_op;
    console.log("Aegis256@%d: %d ms => %s msec/op (%s ops/s) = %s",
        msg.length, msec, msec_per_op.toFixed(3), ops_per_sec.toFixed(2),
        formatByteRate(msg.length * ops_per_sec));
})();
