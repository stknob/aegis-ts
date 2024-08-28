import assert from "node:assert";
import { AegisInvalidTagError, type AegisCipher, type AegisCipherOptions } from "../src/_aegis.mjs";

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

export function runAegisTestVectors(name: string, cipher: (key: Uint8Array, nonce: Uint8Array, options?: AegisCipherOptions) => AegisCipher, vectors: AegisTestVectorDesc[]) {
    for (const [idx, desc] of vectors.entries()) {
        if (!desc.decryptOnly) {
            const [ct, tag256] = cipher(desc.key, desc.nonce, { tagLength: 32 }).encrypt_detached(desc.msg || EMPTY_BUF, desc.ad);
            const [__, tag128] = cipher(desc.key, desc.nonce, { tagLength: 16 }).encrypt_detached(desc.msg || EMPTY_BUF, desc.ad);

            assert.deepStrictEqual(ct, desc.ct, `${name} testvector #${idx + 1} failed ciphertext validation`);
            assert.deepStrictEqual(tag128, desc.tag128, `${name} testvector #${idx + 1} failed 128bit tag`);
            assert.deepStrictEqual(tag256, desc.tag256, `${name} testvector #${idx + 1} failed 256bit tag`);
        }

        // Decryption w/ 128bit tag
        if (desc.valid) {
            let pt: Uint8Array|null = null;
            assert.doesNotThrow(() => { pt = cipher(desc.key, desc.nonce).decrypt_detached(desc.ct, desc.tag128, desc.ad); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ 128bit tag`);
        } else {
            let pt: Uint8Array|null = null;
            assert.throws(() => { pt = cipher(desc.key, desc.nonce).decrypt_detached(desc.ct, desc.tag128, desc.ad); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ 128bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }

        // Decryption w/ 256bit tag
        if (desc.valid) {
            let pt: Uint8Array|null = null;
            assert.doesNotThrow(() => { pt = cipher(desc.key, desc.nonce).decrypt_detached(desc.ct, desc.tag256, desc.ad); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} failed decryption w/ 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg, `${name} testvector #${idx + 1} failed decryption w/ 256bit tag`);
        } else {
            let pt: Uint8Array|null = null;
            assert.throws(() => { pt = cipher(desc.key, desc.nonce).decrypt_detached(desc.ct, desc.tag256, desc.ad); }, AegisInvalidTagError,
                `${name} testvector #${idx + 1} succeeded decryption w/ 256bit tag`);
            assert.deepStrictEqual(pt, desc.msg);
        }
    }
}
