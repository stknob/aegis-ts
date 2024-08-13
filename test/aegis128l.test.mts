import { hexToBytes } from "@noble/ciphers/utils";
import suite from "node:test";

import { Aegis128L } from "../src/index.mjs";
import { runAegisTestVectors } from "./common.mjs";


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
    nonce:  hexToBytes("10000100000000000000000000000000"),
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

suite("aegis128l", async (s) => {
    await s.test("aegis128l test vectors", () => {
        runAegisTestVectors("aegis128l", Aegis128L, AEGIS128L_TEST_VECTORS);
    });
});
