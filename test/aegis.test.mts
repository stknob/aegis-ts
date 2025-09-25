import { hexToBytes, u32, u8 } from "@noble/ciphers/utils.js";
import assert from "node:assert";
import suite from "node:test";

import { AESRound } from "../src/_aes.mjs";

suite("aegis", async (s) => {
    await s.test("AESRound", () => {
        const inp = hexToBytes("000102030405060708090a0b0c0d0e0f");
        const rk  = hexToBytes("101112131415161718191a1b1c1d1e1f");
        const expected = hexToBytes("7a7b4e5638782546a8c0477a3b813f43");

        const result = AESRound(u32(inp), u32(rk));
        const actual = u8(Uint32Array.of(result.t0, result.t1, result.t2, result.t3));
        assert.deepStrictEqual(actual, expected);
    });
});
