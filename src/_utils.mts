/**
 * This file contains code from the noble-ciphers project:
 *
 * Copyright (c) 2022 Paul Miller (https://paulmillr.com)
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * License: MIT
 */
import { createView, setBigUint64 } from "@noble/ciphers/utils";

export const u64BitLengths = (ad_nbits: bigint, ct_nbits: bigint) => {
    const num = new Uint8Array(16);
    const view = createView(num);
    setBigUint64(view, 0, ad_nbits, true);
    setBigUint64(view, 8, ct_nbits, true);
    return num;
};
