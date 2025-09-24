import { clean, copyBytes, equalBytes, isAligned32, u32, type Cipher } from "@noble/ciphers/utils";
import { type AESRoundResult } from "./_aes.mjs";

// C0: 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
export const C0 = Uint32Array.of(0x02010100, 0x0d080503, 0x59372215, 0x6279e990);
// C1: 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
export const C1 = Uint32Array.of(0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573);

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

export interface AegisState {
    blockSize: number;

    init(key: Uint8Array, nonce: Uint8Array): this;
    absorb(ai: Uint32Array): void;
    absorbPartial(ai: Uint8Array): void;
    encBlock(xi: Uint32Array, out: Uint32Array): Uint32Array;
    encPartial(xi: Uint8Array, out: Uint8Array): Uint8Array;
    decBlock(ci: Uint32Array, out: Uint32Array): Uint32Array;
    decPartial(ci: Uint8Array, out: Uint8Array): Uint8Array;
    finalize(ad_len: number, msg_len: number, tag_len: number): Uint8Array;
}

export class AegisInvalidTagError extends Error {
    constructor() { super("Aegis decryption failed") }
    override get name() { return this.constructor.name; }
}

export const aegis_encrypt_detached = (state: AegisState, pt: Uint8Array, ad?: Uint8Array, tag_len: number = 32): [Uint8Array, Uint8Array] => {
    const toClean = [];
    if (!isAligned32(pt)) toClean.push((pt = copyBytes(pt)));
    const src32 = u32(pt);

    const ct = new Uint8Array(pt.length);
    const dst32 = u32(ct);

    const blockSizeU8  = state.blockSize;
    const blockSizeU32 = blockSizeU8 >> 2;

    const ad_len = ad?.length || 0;
    if (ad && ad_len) {
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

export const aegis_decrypt_detached = (state: AegisState, ct: Uint8Array, tag: Uint8Array, ad?: Uint8Array): Uint8Array => {
    const toClean = [];
    if (!isAligned32(ct)) toClean.push((ct = copyBytes(ct)));
    const src32 = u32(ct);

    const blockSizeU8  = state.blockSize;
    const blockSizeU32 = blockSizeU8 >> 2;

    const msg = new Uint8Array(ct.length);
    const dst32 = u32(msg);

    const ad_len = ad?.length || 0;
    if (ad && ad_len) {
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
        clean(dst32, calculatedTag, ...toClean); // Wipe plaintext
        throw new AegisInvalidTagError();
    }

    clean(...toClean);
    return msg;
}
