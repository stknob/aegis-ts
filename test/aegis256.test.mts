import { hexToBytes } from "@noble/ciphers/utils";
import suite from "node:test";

import { Aegis256 } from "../src/index.mjs";
import { runAegisTestVectors } from "./common.mjs";

const AEGIS256_TEST_VECTORS = [{
    // Aegis256 testvector #1
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     Uint8Array.from([]),
    msg:    hexToBytes("00000000000000000000000000000000"),
    ct:     hexToBytes("754fc3d8c973246dcc6d741412a4b236"),
    tag128: hexToBytes("3fe91994768b332ed7f570a19ec5896e"),
    tag256: hexToBytes("1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"),
    valid:  true,
}, {
    // Aegis256 testvector #2
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     Uint8Array.from([]),
    msg:    Uint8Array.from([]),
    ct:     Uint8Array.from([]),
    tag128: hexToBytes("e3def978a0f054afd1e761d7553afba3"),
    tag256: hexToBytes("6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"),
    valid:  true,
}, {
    // Aegis256 testvector #3
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    ct:     hexToBytes("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"),
    tag128: hexToBytes("8d86f91ee606e9ff26a01b64ccbdd91d"),
    tag256: hexToBytes("b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"),
    valid:  true,
}, {
    // Aegis256 testvector #4
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    hexToBytes("000102030405060708090a0b0c0d"),
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    valid:  true,
}, {
    // Aegis256 testvector #5
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"),
    msg:    hexToBytes("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"),
    ct:     hexToBytes("57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67"),
    tag128: hexToBytes("ab8a7d53fd0e98d727accca94925e128"),
    tag256: hexToBytes("a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734"),
    valid:  true,
}, {
    // Aegis256 testvector #6
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis256 testvector #7
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358459"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis256 testvector #8
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050608"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215652"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
    decryptOnly: true,
    valid: false,
}, {
    // Aegis256 testvector #9
    key:    hexToBytes("1001000000000000000000000000000000000000000000000000000000000000"),
    nonce:  hexToBytes("1000020000000000000000000000000000000000000000000000000000000000"),
    ad:     hexToBytes("0001020304050607"),
    msg:    null,
    ct:     hexToBytes("f373079ed84b2709faee37358458"),
    tag128: hexToBytes("c60b9c2d33ceb058f96e6dd03c215653"),
    tag256: hexToBytes("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da"),
    decryptOnly: true,
    valid: false,
}];

suite("aegis256", async (s) => {
    await s.test("aegis256 test vectors", () => {
        runAegisTestVectors("aegis256", Aegis256, AEGIS256_TEST_VECTORS);
    });
});
