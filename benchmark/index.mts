import * as bench from 'micro-bmark';
import { Aegis128L, Aegis256 } from '../src/index.mjs';

const PARAMS = [
    [16, 1_000_000],
    [64, 1_000_000],
    [128, 100_000],
    [256, 100_000],
    [512, 100_000],
    [1024, 100_000],
    [1024*1024, 1_000],
];

(async () => {
    const key   = new Uint8Array(16);
    const nonce = new Uint8Array(16);
    const ad    = Uint8Array.from([]);

    for (const [size, samples] of PARAMS) {
        const [ct, tag] = Aegis128L.encrypt(key, nonce, new Uint8Array(size), ad, 32);
        await bench.mark(`aegis128l @ ${size}`, samples, () => {
            Aegis128L.decrypt(key, nonce, ct, ad, tag);
        });
    }
})();

(async () => {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(32);
    const ad    = Uint8Array.from([]);

    for (const [size, samples] of PARAMS) {
        const [ct, tag] = Aegis256.encrypt(key, nonce, new Uint8Array(size), ad, 32);
        await bench.mark(`aegis256  @ ${size}`, samples, () => {
            Aegis256.decrypt(key, nonce, ct, ad, tag);
        });
    }
})();
