/**
 * This file contains code from the noble-ciphers project:
 *
 * Copyright (c) 2022 Paul Miller (https://paulmillr.com)
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * License: MIT
 */
import { createView, setBigUint64, TypedArray } from "@noble/ciphers/utils";

export const u32 = (arr: Uint8Array) => new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >>> 2);
export const  u8 = (arr: Uint32Array) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);

export const u64BitLengths = (ad_nbits: bigint, ct_nbits: bigint) => {
    const num = new Uint8Array(16);
    const view = createView(num);
    setBigUint64(view, 0, ad_nbits, true);
    setBigUint64(view, 8, ct_nbits, true);
    return num;
};

export const clean = (...arrays: TypedArray[]) => {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
};
