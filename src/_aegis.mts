import { AESRound, AESRoundResult } from "./_aes.mjs";

export type Aegis256Blocks = [
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
    Uint32Array, Uint32Array
];

export function xor128(a: Uint32Array, b: Uint32Array, out: Uint32Array): Uint32Array {
    out[0] = a[0] ^ b[0];
    out[1] = a[1] ^ b[1];
    out[2] = a[2] ^ b[2];
    out[3] = a[3] ^ b[3];
    return out;
}

export function set128(out: Uint32Array, inp: AESRoundResult): Uint32Array {
    out[0] = inp.t0;
    out[1] = inp.t1;
    out[2] = inp.t2;
    out[3] = inp.t3;
    return out;
}

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


export type Aegis128LBlocks = [
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
    Uint32Array, Uint32Array, Uint32Array, Uint32Array,
];

export function xor256(a: Uint32Array, b: Uint32Array, out: Uint32Array): Uint32Array {
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
