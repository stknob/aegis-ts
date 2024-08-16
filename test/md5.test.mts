import { hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { MD5 } from "../src/md5.mjs";
import assert from "node:assert";
import suite from "node:test";

function runDigestTestVectors(name: string, clazz: any, vectors: any[]) {
    for (const [idx, desc] of vectors.entries()) {
        const res = clazz.digest(desc.msg);
        assert.deepStrictEqual(res, desc.res, `${name} testvector #${idx + 1} failed validation`);
    }
}

suite("md5", async (s) => {
    await s.test("md5 test vectors", () => {
        const MD5_TEST_VECTORS = [{
            msg: Uint8Array.from([]),
            res: hexToBytes("d41d8cd98f00b204e9800998ecf8427e"),
        }, {
            msg: utf8ToBytes("a"),
            res: hexToBytes("0cc175b9c0f1b6a831c399e269772661"),
        }, {
            msg: utf8ToBytes("abc"),
            res: hexToBytes("900150983cd24fb0d6963f7d28e17f72"),
        }, {
            msg: utf8ToBytes("message digest"),
            res: hexToBytes("f96b697d7cb7938d525a2f31aaf161d0"),
        }, {
            msg: utf8ToBytes("abcdefghijklmnopqrstuvwxyz"),
            res: hexToBytes("c3fcd3d76192e4007dfb496cca67e13b"),
        }, {
            msg: utf8ToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            res: hexToBytes("d174ab98d277d9f5a5611c2c9f419d9f"),
        }, {
            msg: utf8ToBytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            res: hexToBytes("57edf4a22be3c955ac49da2e2107b67a"),
        }];

        runDigestTestVectors("md5", MD5, MD5_TEST_VECTORS);
    });
});
