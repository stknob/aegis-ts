/**
 * This file contains code from the noble-ciphers project:
 *
 * Copyright (c) 2022 Paul Miller (https://paulmillr.com)
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * License: MIT
 */
import { TypedArray } from "@noble/ciphers/utils";

export const u32 = (arr: Uint8Array) => new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >>> 2);
export const  u8 = (arr: Uint32Array) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);

export const u32_aligned = (arr: Uint8Array) => {
    // Handle unaligned blocks by copying instead of "casting"
    return (arr.byteOffset & 0x03)
        ? new Uint32Array(arr.slice(0).buffer, 0, arr.byteLength >>> 2)
        : new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >>> 2);
};

export const u32_aligned_at = (arr: Uint8Array, offset: number, length: number) => {
    // Handle unaligned blocks by copying instead of "casting"
    return ((arr.byteOffset + offset) & 0x3)
        ? new Uint32Array(arr.slice(offset, offset + length).buffer, 0, length >>> 2)
        : new Uint32Array(arr.buffer, arr.byteOffset + offset, length >>> 2);
};

export const clean = (...arrays: TypedArray[]) => {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
};
