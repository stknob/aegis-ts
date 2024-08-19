import * as bench from 'micro-bmark';
import { aegis128l, aegis256 } from '../src/index.mjs';
import { MD5 } from '../src/md5.mjs';

const PARAMS = [
    [16, 1_000_000],
    [64, 1_000_000],
    [128, 100_000],
    [256, 100_000],
    [512, 100_000],
    [1024, 100_000],
    [1024*1024, 100],
];

await bench.run(null, async () => {
    for (const [size, samples] of PARAMS) {
        const msg = new Uint8Array(size);
        await bench.mark(`md5  @ ${size}`, samples, () => {
            MD5.digest(msg);
        });
    }
});

await bench.run(null, async () => {
    const key   = new Uint8Array(16);
    const nonce = new Uint8Array(16);
    const ad    = new Uint8Array(16);

    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis128l(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        await bench.mark(`aegis128l @ ${size}`, samples, () => {
            aegis128l(key, nonce).decrypt_detached(ct, tag, ad);
        });
    }
});

await bench.run(null, async () => {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(32);
    const ad    = new Uint8Array(16);

    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis256(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        await bench.mark(`aegis256 @ ${size}`, samples, () => {
            aegis256(key, nonce).decrypt_detached(ct, tag, ad);
        });
    }
});


await bench.run(null, async () => {
    const key   = new Uint8Array(16);
    const nonce = new Uint8Array(16);
    const ad    = new Uint8Array(16);

    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis128l(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        const ct_unaligned = new Uint8Array(ct.length + 1).subarray(1); ct_unaligned.set(ct);
        const nonce_unaligned = new Uint8Array(nonce.length + 1).subarray(1); nonce_unaligned.set(nonce);
        await bench.mark(`aegis128l misaligned nonce + ct @ ${size}`, samples, () => {
            aegis128l(key, nonce).decrypt_detached(ct, tag, ad);
        });
    }
});


await bench.run(null, async () => {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(32);
    const ad    = new Uint8Array(16);

    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis256(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        const ct_unaligned = new Uint8Array(ct.length + 1).subarray(1); ct_unaligned.set(ct);
        const nonce_unaligned = new Uint8Array(nonce.length + 1).subarray(1); nonce_unaligned.set(nonce);
        await bench.mark(`aegis256 misaligned nonce + ct @ ${size}`, samples, () => {
            aegis256(key, nonce).decrypt_detached(ct, tag, ad);
        });
    }
});
