import assert from "node:assert";
import { AegisInvalidTagError } from "../src/_aegis.mjs";
import { type AegisCipher, type AegisCipherOptions } from "../src/_utils.mts";
import { concatBytes } from "@noble/ciphers/utils";

export interface AegisTestVectorDesc {
    key: Uint8Array,
    msg: Uint8Array|null,
    ad: Uint8Array,
    ct: Uint8Array,
    nonce: Uint8Array,
    tag128: Uint8Array,
    tag256: Uint8Array,
    decryptOnly?: boolean,
    valid: boolean,
}

const EMPTY_BUF = Uint8Array.from([]);

export function runAegisTestVectors(name: string, cipher: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array, options?: AegisCipherOptions) => AegisCipher, vectors: AegisTestVectorDesc[]) {
    for (const [idx, desc] of vectors.entries()) {
        if (!desc.decryptOnly) {
            const [ct256, tag256] = cipher(desc.key, desc.nonce, desc.ad, { tagLength: 32 }).encryptDetached(desc.msg || EMPTY_BUF);
            const [ct128, tag128] = cipher(desc.key, desc.nonce, desc.ad, { tagLength: 16 }).encryptDetached(desc.msg || EMPTY_BUF);

            assert.deepStrictEqual(ct128, desc.ct, `${name} testvector #${idx + 1} failed detached ciphertext validation`);
            assert.deepStrictEqual(ct256, desc.ct, `${name} testvector #${idx + 1} failed detached ciphertext validation`);
            assert.deepStrictEqual(tag128, desc.tag128, `${name} testvector #${idx + 1} failed detached 128bit tag`);
            assert.deepStrictEqual(tag256, desc.tag256, `${name} testvector #${idx + 1} failed detached 256bit tag`);

            const ctt256 = cipher(desc.key, desc.nonce, desc.ad, { tagLength: 32 }).encrypt(desc.msg || EMPTY_BUF);
            const ctt128 = cipher(desc.key, desc.nonce, desc.ad, { tagLength: 16 }).encrypt(desc.msg || EMPTY_BUF);

            assert.deepStrictEqual(ctt128.subarray(0, desc.ct.length), desc.ct, `${name} testvector #${idx + 1} failed ciphertext validation`);
            assert.deepStrictEqual(ctt256.subarray(0, desc.ct.length), desc.ct, `${name} testvector #${idx + 1} failed ciphertext validation`);
            assert.deepStrictEqual(ctt128.subarray(-desc.tag128.length), desc.tag128, `${name} testvector #${idx + 1} failed 128bit tag`);
            assert.deepStrictEqual(ctt256.subarray(-desc.tag256.length), desc.tag256, `${name} testvector #${idx + 1} failed 256bit tag`);
        }

        // Detached decryption w/ 128bit tag
        if (desc.valid) {
            let pt: Uint8Array|null = null;
            assert.doesNotThrow(() => { pt = cipher(desc.key, desc.nonce, desc.ad).decryptDetached(desc.ct, desc.tag128); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ detached 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ detached 128bit tag`);
        } else {
            let pt: Uint8Array|null = null;
            assert.throws(() => { pt = cipher(desc.key, desc.nonce, desc.ad).decryptDetached(desc.ct, desc.tag128); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ detached 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }

        // Detached decryption w/ 256bit tag
        if (desc.valid) {
            let pt: Uint8Array|null = null;
            assert.doesNotThrow(() => { pt = cipher(desc.key, desc.nonce, desc.ad).decryptDetached(desc.ct, desc.tag256); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ detached 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ detached 256bit tag`);
        } else {
            let pt: Uint8Array|null = null;
            assert.throws(() => { pt = cipher(desc.key, desc.nonce, desc.ad).decryptDetached(desc.ct, desc.tag256); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ detached 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }

        // Decryption w/ 128bit tag
        if (desc.valid) {
            let pt: Uint8Array|null = null;
            assert.doesNotThrow(() => { pt = cipher(desc.key, desc.nonce, desc.ad, { tagLength: desc.tag128.length }).decrypt(concatBytes(desc.ct, desc.tag128)); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ 128bit tag`);
        } else {
            let pt: Uint8Array|null = null;
            assert.throws(() => { pt = cipher(desc.key, desc.nonce, desc.ad, { tagLength: desc.tag128.length }).decrypt(concatBytes(desc.ct, desc.tag128)); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }

        // Decryption w/ 256bit tag
        if (desc.valid) {
            let pt: Uint8Array|null = null;
            assert.doesNotThrow(() => { pt = cipher(desc.key, desc.nonce, desc.ad, { tagLength: desc.tag256.length }).decrypt(concatBytes(desc.ct, desc.tag256)); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ 256bit tag`);
        } else {
            let pt: Uint8Array|null = null;
            assert.throws(() => { pt = cipher(desc.key, desc.nonce, desc.ad, { tagLength: desc.tag256.length }).decrypt(concatBytes(desc.ct, desc.tag256)); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }
    }
}
