## TypeScript implementation of Aegis128L and Aegis256

Using utility and low-level AES function from Paul Miller's [noble-ciphers](https://github.com/paulmillr/noble-ciphers).

Passes all testvectors from the current [draft spec 11](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-11).

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
