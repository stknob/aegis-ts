## TypeScript implementation of Aegis128L and Aegis256

Using utility and low-level AES function from Paul Miller's [noble-ciphers](https://github.com/paulmillr/noble-ciphers).

Passes all testvectors from the current [draft spec 13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-13).

Use at your own risk!

### Example

```javascript
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { aegis256 } from "aegis-ts/aegis256.js";

const key = randomBytes(32);
const nonce = randomBytes(32);
const plaintext = utf8ToBytes("Hello World");

const ciphertext = aegis256(key, nonce).encrypt(plaintext);
const plaintext_ = aegis256(key, nonce).decrypt(ciphertext);   // Use bytesToUtf8 to convert result back to text
```

### Benchmarks

En-/Decryption Benchmarks of Aegis128L and Aegis256 on a Rizen 7 3700X, Firefox Nightly 133.0a1 (2024-10-03).

Notes:
  - Source: custom benchmark suite based on benchmark.js and glue code for a number of implementations
  - Plain- / Ciphertext sizes: 16 bytes, 1 KiB, 1 MiB
  - Non-official aegis-js Aegis256 implementation
  - libsodium-js and wasmCrypto-rs use Webassmbly, the latter being a thin wasm-bindgen wrapper for RustCrypto

#### Aegis128L

```
Encryption:

*** Running suite Aegis128L/16/encrypt...
aegis-js x 62,131 ops/sec ±2.06% (58 runs sampled)
aegis-ts x 50,570 ops/sec ±1.52% (61 runs sampled)
libsodium-js x 305,238 ops/sec ±1.08% (62 runs sampled)
wasmCrypto-rs x 496,064 ops/sec ±0.43% (64 runs sampled)
==> Aegis128L/16/encrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis128L/1024/encrypt...
aegis-js x 16,944 ops/sec ±0.85% (64 runs sampled)
aegis-ts x 12,450 ops/sec ±1.57% (60 runs sampled)
libsodium-js x 107,975 ops/sec ±1.31% (62 runs sampled)
wasmCrypto-rs x 179,445 ops/sec ±2.12% (64 runs sampled)
==> Aegis128L/1024/encrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis128L/1048576/encrypt...
aegis-js x 23.93 ops/sec ±0.91% (43 runs sampled)
aegis-ts x 16.78 ops/sec ±1.24% (32 runs sampled)
libsodium-js x 183 ops/sec ±1.25% (60 runs sampled)
wasmCrypto-rs x 310 ops/sec ±1.22% (62 runs sampled)
==> Aegis128L/1048576/encrypt: Fastest is wasmCrypto-rs

Decryption:

*** Running suite Aegis128L/16/decrypt...
aegis-js x 64,970 ops/sec ±1.63% (63 runs sampled)
aegis-ts x 52,414 ops/sec ±0.91% (65 runs sampled)
libsodium-js x 305,176 ops/sec ±0.56% (65 runs sampled)
wasmCrypto-rs x 513,980 ops/sec ±0.39% (67 runs sampled)
==> Aegis128L/16/decrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis128L/1024/decrypt...
aegis-js x 24,367 ops/sec ±1.23% (65 runs sampled)
aegis-ts x 16,313 ops/sec ±1.02% (63 runs sampled)
libsodium-js x 114,087 ops/sec ±1.50% (57 runs sampled)
wasmCrypto-rs x 192,124 ops/sec ±1.53% (64 runs sampled)
==> Aegis128L/1024/decrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis128L/1048576/decrypt...
aegis-js x 38.77 ops/sec ±0.85% (52 runs sampled)
aegis-ts x 23.04 ops/sec ±1.25% (42 runs sampled)
libsodium-js x 181 ops/sec ±1.49% (59 runs sampled)
wasmCrypto-rs x 327 ops/sec ±1.49% (63 runs sampled)
==> Aegis128L/1048576/decrypt: Fastest is wasmCrypto-rs
```

#### Aegis256

```
Encryption:

*** Running suite Aegis256/16/encrypt...
aegis-js x 67,816 ops/sec ±1.44% (62 runs sampled)
aegis-ts x 71,340 ops/sec ±1.24% (62 runs sampled)
libsodium-js x 319,330 ops/sec ±0.63% (63 runs sampled)
wasmCrypto-rs x 483,330 ops/sec ±0.52% (66 runs sampled)
==> Aegis256/16/encrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis256/1024/encrypt...
aegis-js x 15,246 ops/sec ±1.23% (63 runs sampled)
aegis-ts x 13,216 ops/sec ±1.17% (59 runs sampled)
libsodium-js x 89,147 ops/sec ±1.42% (63 runs sampled)
wasmCrypto-rs x 141,559 ops/sec ±2.38% (64 runs sampled)
==> Aegis256/1024/encrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis256/1048576/encrypt...
aegis-js x 19.92 ops/sec ±0.52% (37 runs sampled)
aegis-ts x 16.48 ops/sec ±1.36% (32 runs sampled)
libsodium-js x 134 ops/sec ±1.02% (58 runs sampled)
wasmCrypto-rs x 221 ops/sec ±1.21% (58 runs sampled)
==> Aegis256/1048576/encrypt: Fastest is wasmCrypto-rs

Decryption:

*** Running suite Aegis256/16/decrypt...
aegis-js x 67,675 ops/sec ±1.26% (63 runs sampled)
aegis-ts x 74,035 ops/sec ±1.31% (62 runs sampled)
libsodium-js x 315,484 ops/sec ±0.64% (64 runs sampled)
wasmCrypto-rs x 505,080 ops/sec ±0.27% (67 runs sampled)
==> Aegis256/16/decrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis256/1024/decrypt...
aegis-js x 20,492 ops/sec ±0.83% (64 runs sampled)
aegis-ts x 17,313 ops/sec ±1.08% (63 runs sampled)
libsodium-js x 92,460 ops/sec ±1.66% (65 runs sampled)
wasmCrypto-rs x 153,225 ops/sec ±1.43% (55 runs sampled)
==> Aegis256/1024/decrypt: Fastest is wasmCrypto-rs

*** Running suite Aegis256/1048576/decrypt...
aegis-js x 29.28 ops/sec ±0.45% (40 runs sampled)
aegis-ts x 23.21 ops/sec ±1.03% (42 runs sampled)
libsodium-js x 133 ops/sec ±1.10% (58 runs sampled)
wasmCrypto-rs x 233 ops/sec ±1.17% (61 runs sampled)
==> Aegis256/1048576/decrypt: Fastest is wasmCrypto-rs
```
