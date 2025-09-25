import { bytesToHex, hexToBytes, u32, u8 } from "@noble/ciphers/utils.js";
import assert from "node:assert";
import suite from "node:test";

import { aegis256, aegis256_update, Aegis256Blocks } from "../src/aegis256.mjs";
import { AegisTestVectorDesc, runAegisTestVectors } from "./common.mjs";

suite("aegis256", async (s) => {
    await s.test("aegis256 update", () => {
        const message = "b165617ed04ab738afb2612c6d18a1ec";
        const beforeState = [
            "1fa1207ed76c86f2c4bb40e8b395b43e",
            "b44c375e6c1e1978db64bcd12e9e332f",
            "0dab84bfa9f0226432ff630f233d4e5b",
            "d7ef65c9b93e8ee60c75161407b066e7",
            "a760bb3da073fbd92bdc24734b1f56fb",
            "a828a18d6a964497ac6e7e53c5f55c73",
        ];

        const afterState = [
            "e6bc643bae82dfa3d991b1b323839dcd",
            "648578232ba0f2f0a3677f617dc052c3",
            "ea788e0e572044a46059212dd007a789",
            "2f1498ae19b80da13fba698f088a8590",
            "a54c2ee95e8c2a2c3dae2ec743ae6b86",
            "a3240fceb68e32d5d114df1b5363ab67",
        ];

        const msg = u32(hexToBytes(message));
        const inp = beforeState.map((v) => u32(hexToBytes(v))) as Aegis256Blocks;
        const out = aegis256_update(inp, msg, new Uint32Array(5)).map((v) => bytesToHex(u8(v)));

        assert.deepStrictEqual(afterState, out);
    });

    await s.test("aegis256 test vectors", () => {
        const AEGIS256_TEST_VECTORS: AegisTestVectorDesc[] = [{
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

        runAegisTestVectors("aegis256", aegis256, AEGIS256_TEST_VECTORS);
    });

    await s.test("misaligned parameters", () => {
        const key =    hexToBytes("0F1001000000000000000000000000000000000000000000000000000000000000").subarray(1);
        const nonce =  hexToBytes("0F1000020000000000000000000000000000000000000000000000000000000000").subarray(1);
        const ad =     hexToBytes("0F0001020304050607").subarray(1);
        const msg =    hexToBytes("0F000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").subarray(1);
        const ct =     hexToBytes("0Ff373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711").subarray(1);
        const tag128 = hexToBytes("0F8d86f91ee606e9ff26a01b64ccbdd91d").subarray(1);
        const tag256 = hexToBytes("0Fb7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a").subarray(1);

        assert.doesNotThrow(() => {
            const [actual_ct, actual_tag] = aegis256(key, nonce, ad).encryptDetached(msg);
            assert.deepStrictEqual(actual_ct, ct, "ciphertext does not match expected");
            assert.deepStrictEqual(actual_tag, tag256, "encryption tag does not match expected");
            const actual_msg256 = aegis256(key, nonce, ad).decryptDetached(ct, tag256);
            assert.deepStrictEqual(actual_msg256, msg, "plaintext does not match expected");
            const actual_msg128 = aegis256(key, nonce, ad).decryptDetached(ct, tag128);
            assert.deepStrictEqual(actual_msg128, msg, "plaintext does not match expected");
        }, RangeError);
    });
});
