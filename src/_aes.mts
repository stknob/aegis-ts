/**
 * This file contains code from the noble-ciphers project:
 *
 * Copyright (c) 2022 Paul Miller (https://paulmillr.com)
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * License: MIT
 */
import { clean } from "@noble/ciphers/utils";

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

export type AESRoundResult = { t0: number, t1: number, t2: number, t3: number };

/**
 * AES round function
 * @param inp
 * @param rk
 * @returns
 */
export function AESRound(inp: Uint32Array, rk: Uint32Array): AESRoundResult {
    const { T01, T23 } = tableEncoding;

    const t0 = rk[0] ^ apply0123(T01, T23, inp[0], inp[1], inp[2], inp[3]);
    const t1 = rk[1] ^ apply0123(T01, T23, inp[1], inp[2], inp[3], inp[0]);
    const t2 = rk[2] ^ apply0123(T01, T23, inp[2], inp[3], inp[0], inp[1]);
    const t3 = rk[3] ^ apply0123(T01, T23, inp[3], inp[0], inp[1], inp[2]);
    return { t0, t1, t2, t3 };
}
