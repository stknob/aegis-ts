import bench from 'micro-bmark';
import { aegis128l } from '../src/aegis128l.mjs';
import { aegis256 } from '../src/aegis256.mjs';

const PARAMS = [
    [16, 1_000_000],
    [64, 1_000_000],
    [128, 100_000],
    [256, 100_000],
    [512, 100_000],
    [1024, 100_000],
    [1024*1024, 500],
];

async function bench_aegis128l() {
    const key   = new Uint8Array(16);
    const nonce = new Uint8Array(16);
    const ad    = new Uint8Array(16);

    console.log("--------------------------------");
    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis128l(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        await bench(`aegis128l @ ${size}`, samples, () => aegis128l(key, nonce).decrypt_detached(ct, tag, ad));
    }
};

async function bench_aegis256() {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(32);
    const ad    = new Uint8Array(16);

    console.log("--------------------------------");
    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis256(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        await bench(`aegis256 @ ${size}`, samples, () => aegis256(key, nonce).decrypt_detached(ct, tag, ad));
    }
}


async function bench_aegis128l_misaligned() {
    const key   = new Uint8Array(16);
    const nonce = new Uint8Array(16);
    const ad    = new Uint8Array(16);

    console.log("--------------------------------");
    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis128l(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        const ct_unaligned = new Uint8Array(ct.length + 1).subarray(1); ct_unaligned.set(ct);
        const nonce_unaligned = new Uint8Array(nonce.length + 1).subarray(1); nonce_unaligned.set(nonce);
        await bench(`aegis128l misaligned nonce + ct @ ${size}`, samples, () => aegis128l(key, nonce).decrypt_detached(ct, tag, ad));
    }
}


async function bench_aegis256_misaligned() {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(32);
    const ad    = new Uint8Array(16);

    console.log("--------------------------------");
    for (const [size, samples] of PARAMS) {
        const [ct, tag] = aegis256(key, nonce).encrypt_detached(new Uint8Array(size), ad);
        const ct_unaligned = new Uint8Array(ct.length + 1).subarray(1); ct_unaligned.set(ct);
        const nonce_unaligned = new Uint8Array(nonce.length + 1).subarray(1); nonce_unaligned.set(nonce);
        await bench(`aegis256 misaligned nonce + ct @ ${size}`, samples, () => aegis256(key, nonce).decrypt_detached(ct, tag, ad));
    }
}

(async () => {
    await bench_aegis128l();
    await bench_aegis256();
    await bench_aegis128l_misaligned();
    await bench_aegis256_misaligned();
})();
