import assert from "node:assert";
import { AegisInvalidTagError } from "../src/index.mjs";

export function runAegisTestVectors(name, clazz, vectors) {
    for (const [idx, desc] of vectors.entries()) {
        if (!desc.decryptOnly) {
            const [ct, tag256] = clazz.encrypt(desc.key, desc.nonce, desc.msg, desc.ad, 32);
            const [__, tag128] = clazz.encrypt(desc.key, desc.nonce, desc.msg, desc.ad, 16);

            assert.deepStrictEqual(ct, desc.ct, `${name} testvector #${idx + 1} failed ciphertext validation`);
            assert.deepStrictEqual(tag128, desc.tag128, `${name} testvector #${idx + 1} failed 128bit tag`);
            assert.deepStrictEqual(tag256, desc.tag256, `${name} testvector #${idx + 1} failed 256bit tag`);
        }

        // Decryption w/ 128bit tag
        if (desc.valid) {
            let pt = null;
            assert.doesNotThrow(() => { pt = clazz.decrypt(desc.key, desc.nonce, desc.ct, desc.ad, desc.tag128); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ 128bit tag`);
        } else {
            let pt = null;
            assert.throws(() => { pt = clazz.decrypt(desc.key, desc.nonce, desc.ct, desc.ad, desc.tag128); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }

        // Decryption w/ 256bit tag
        if (desc.valid) {
            let pt = null;
            assert.doesNotThrow(() => { pt = clazz.decrypt(desc.key, desc.nonce, desc.ct, desc.ad, desc.tag256); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ 256bit tag`);
        } else {
            let pt = null;
            assert.throws(() => { pt = clazz.decrypt(desc.key, desc.nonce, desc.ct, desc.ad, desc.tag256); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }
    }
}
