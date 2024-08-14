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

export const clean = (...arrays: TypedArray[]) => {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
};
