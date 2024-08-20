import { clean, copyBytes, isAligned32, u32, u8 } from "@noble/ciphers/utils";

// M5 Constants in LE
const MD5_REG_CONSTS = Uint32Array.from([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
]);

// const MD5_ROUND_CONSTS = Uint32Array.from([
//     // round 1
//     0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
//     0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
//     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
//     0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
//     // round 2
//     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
//     0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
//     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
//     0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
//     // round 3
//     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
//     0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
//     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
//     0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
//     // round 4
//     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
//     0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
//     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
//     0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
// ]);

const MD5_ROUND_CONSTS = (() => {
    const t = new Uint32Array(64);
    for (let i = 0; i < t.length; i++)
        t[i] = 4294967296 * Math.abs(Math.sin((i + 1)));
    return t;
})();

// const MD5_BITMASK = 0xffff_ffff;
const MD5_PADDING = Uint8Array.from([
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

// function rol32x(x: number, n: number): number {
//     return ((x << n) & MD5_BITMASK) | ((x & MD5_BITMASK) >>> (32 - n));
// }

function rol32(x: number, n: number): number {
    return (x << n) | (x >>> (32 - n));
}

export class MD5 {
    #state = new Uint32Array(4);
    #count = new Uint32Array(2);
    #buf   = new Uint8Array(64);

    constructor() {
        this.init();
    }

    #f(x: number, y: number, z: number): number {
        return ((x & y) | (~x & z));
    }

    #g(x: number, y: number, z: number): number {
        return ((x & z) | (y & ~z));
    }

    #h(x: number, y: number, z: number): number {
        return (x ^ y ^ z);
    }

    #i(x: number, y: number, z: number): number {
        return (y ^ (x | ~z));
    }

    #round1(a: number, b: number, c: number, d: number, x: number, s: number, i: number) {
        this.#state[a] = this.#state[b] + rol32((this.#state[a] + this.#f(this.#state[b], this.#state[c], this.#state[d]) + x + MD5_ROUND_CONSTS[i]), s);
    }

    #round2(a: number, b: number, c: number, d: number, x: number, s: number, i: number) {
        this.#state[a] = this.#state[b] + rol32((this.#state[a] + this.#g(this.#state[b], this.#state[c], this.#state[d]) + x + MD5_ROUND_CONSTS[i]), s);
    }

    #round3(a: number, b: number, c: number, d: number, x: number, s: number, i: number) {
        this.#state[a] = this.#state[b] + rol32((this.#state[a] + this.#h(this.#state[b], this.#state[c], this.#state[d]) + x + MD5_ROUND_CONSTS[i]), s);
    }

    #round4(a: number, b: number, c: number, d: number, x: number, s: number, i: number) {
        this.#state[a] = this.#state[b] + rol32((this.#state[a] + this.#i(this.#state[b], this.#state[c], this.#state[d]) + x + MD5_ROUND_CONSTS[i]), s);
    }

    #transform(block: Uint8Array) {
        const toClean = [];
        if (!isAligned32(block)) toClean.push((block = copyBytes(block)));

        const [a, b, c, d] = this.#state;
        const x = u32(block);

        // TODO: convert round functions calls into pass-by-value instead of state array indexes
        // let [a, b, c, d] = this.#state;
        // a = this.#round1(a, b, c, d, x[ 0], 7, 0);
        // ...
        // this.#state[0] += a;

        // round #1
        this.#round1(0, 1, 2, 3, x[ 0],  7,  0);   // [ABCD  0  7  1]
        this.#round1(3, 0, 1, 2, x[ 1], 12,  1);   // [DABC  1 12  2]
        this.#round1(2, 3, 0, 1, x[ 2], 17,  2);   // [CDAB  2 17  3]
        this.#round1(1, 2, 3, 0, x[ 3], 22,  3);   // [BCDA  3 22  4]

        this.#round1(0, 1, 2, 3, x[ 4],  7,  4);   // [ABCD  4  7  5]
        this.#round1(3, 0, 1, 2, x[ 5], 12,  5);   // [DABC  5 12  6]
        this.#round1(2, 3, 0, 1, x[ 6], 17,  6);   // [CDAB  6 17  7]
        this.#round1(1, 2, 3, 0, x[ 7], 22,  7);   // [BCDA  7 22  8]

        this.#round1(0, 1, 2, 3, x[ 8],  7,  8);   // [ABCD  8  7  9]
        this.#round1(3, 0, 1, 2, x[ 9], 12,  9);   // [DABC  9 12 10]
        this.#round1(2, 3, 0, 1, x[10], 17, 10);   // [CDAB 10 17 11]
        this.#round1(1, 2, 3, 0, x[11], 22, 11);   // [BCDA 11 22 12]

        this.#round1(0, 1, 2, 3, x[12],  7, 12);   // [ABCD 12  7 13]
        this.#round1(3, 0, 1, 2, x[13], 12, 13);   // [DABC 13 12 14]
        this.#round1(2, 3, 0, 1, x[14], 17, 14);   // [CDAB 14 17 15]]
        this.#round1(1, 2, 3, 0, x[15], 22, 15);   // [BCDA 15 22 16]

        // round #2
        this.#round2(0, 1, 2, 3, x[ 1],  5, 16);   // [ABCD  1  5 17]
        this.#round2(3, 0, 1, 2, x[ 6],  9, 17);   // [DABC  6  9 18]
        this.#round2(2, 3, 0, 1, x[11], 14, 18);   // [CDAB 11 14 19]
        this.#round2(1, 2, 3, 0, x[ 0], 20, 19);   // [BCDA  0 20 20]

        this.#round2(0, 1, 2, 3, x[ 5],  5, 20);   // [ABCD  5  5 21]
        this.#round2(3, 0, 1, 2, x[10],  9, 21);   // [DABC 10  9 22]
        this.#round2(2, 3, 0, 1, x[15], 14, 22);   // [CDAB 15 14 23]
        this.#round2(1, 2, 3, 0, x[ 4], 20, 23);   // [BCDA  4 20 24]

        this.#round2(0, 1, 2, 3, x[ 9],  5, 24);   // [ABCD  9  5 25]
        this.#round2(3, 0, 1, 2, x[14],  9, 25);   // [DABC 14  9 26]
        this.#round2(2, 3, 0, 1, x[ 3], 14, 26);   // [CDAB  3 14 27]
        this.#round2(1, 2, 3, 0, x[ 8], 20, 27);   // [BCDA  8 20 28]

        this.#round2(0, 1, 2, 3, x[13],  5, 28);   // [ABCD 13  5 29]
        this.#round2(3, 0, 1, 2, x[ 2],  9, 29);   // [DABC  2  9 30]
        this.#round2(2, 3, 0, 1, x[ 7], 14, 30);   // [CDAB  7 14 31]
        this.#round2(1, 2, 3, 0, x[12], 20, 31);   // [BCDA 12 20 32]

        // round #3
        this.#round3(0, 1, 2, 3, x[ 5],  4, 32);   // [ABCD  5  4 33]
        this.#round3(3, 0, 1, 2, x[ 8], 11, 33);   // [DABC  8 11 34]
        this.#round3(2, 3, 0, 1, x[11], 16, 34);   // [CDAB 11 16 35]
        this.#round3(1, 2, 3, 0, x[14], 23, 35);   // [BCDA 14 23 36]

        this.#round3(0, 1, 2, 3, x[ 1],  4, 36);   // [ABCD  1  4 37]
        this.#round3(3, 0, 1, 2, x[ 4], 11, 37);   // [DABC  4 11 38]
        this.#round3(2, 3, 0, 1, x[ 7], 16, 38);   // [CDAB  7 16 39]
        this.#round3(1, 2, 3, 0, x[10], 23, 39);   // [BCDA 10 23 40]

        this.#round3(0, 1, 2, 3, x[13],  4, 40);   // [ABCD 13  4 41]
        this.#round3(3, 0, 1, 2, x[ 0], 11, 41);   // [DABC  0 11 42]
        this.#round3(2, 3, 0, 1, x[ 3], 16, 42);   // [CDAB  3 16 43]
        this.#round3(1, 2, 3, 0, x[ 6], 23, 43);   // [BCDA  6 23 44]

        this.#round3(0, 1, 2, 3, x[ 9],  4, 44);   // [ABCD  9  4 45]
        this.#round3(3, 0, 1, 2, x[12], 11, 45);   // [DABC 12 11 46]
        this.#round3(2, 3, 0, 1, x[15], 16, 46);   // [CDAB 15 16 47]
        this.#round3(1, 2, 3, 0, x[ 2], 23, 47);   // [BCDA  2 23 48]

        // round #4
        this.#round4(0, 1, 2, 3, x[ 0],  6, 48);   // [ABCD  0  6 49]
        this.#round4(3, 0, 1, 2, x[ 7], 10, 49);   // [DABC  7 10 40]
        this.#round4(2, 3, 0, 1, x[14], 15, 50);   // [CDAB 14 15 51]
        this.#round4(1, 2, 3, 0, x[ 5], 21, 51);   // [BCDA  5 21 52]

        this.#round4(0, 1, 2, 3, x[12],  6, 52);   // [ABCD 12  6 53]
        this.#round4(3, 0, 1, 2, x[ 3], 10, 53);   // [DABC  3 10 54]
        this.#round4(2, 3, 0, 1, x[10], 15, 54);   // [CDAB 10 15 55]
        this.#round4(1, 2, 3, 0, x[ 1], 21, 55);   // [BCDA  1 21 56]

        this.#round4(0, 1, 2, 3, x[ 8],  6, 56);   // [ABCD  8  6 57]
        this.#round4(3, 0, 1, 2, x[15], 10, 57);   // [DABC 15 10 58]
        this.#round4(2, 3, 0, 1, x[ 6], 15, 58);   // [CDAB  6 15 59]
        this.#round4(1, 2, 3, 0, x[13], 21, 59);   // [BCDA 13 21 60]

        this.#round4(0, 1, 2, 3, x[ 4],  6, 60);   // [ABCD  4  6 61]
        this.#round4(3, 0, 1, 2, x[11], 10, 61);   // [DABC 11 10 62]
        this.#round4(2, 3, 0, 1, x[ 2], 15, 62);   // [CDAB  2 15 63]
        this.#round4(1, 2, 3, 0, x[ 9], 21, 63);   // [BCDA  9 21 64]

        this.#state[0] += a;
        this.#state[1] += b;
        this.#state[2] += c;
        this.#state[3] += d;

        clean(x, ...toClean);
    }

    init(): this {
        this.#state.set(MD5_REG_CONSTS);
        clean(this.#count, this.#buf);
        return this;
    }

    update(msg: Uint8Array): this {
        // Get number of partial block bytes in buffer
        let index = (this.#count[0] >>> 3) & 0x3f;

        // Update 64bit bits counter
        const msgbits = msg.length << 3;
        this.#count[0] += msgbits;
        this.#count[1] += msg.length >>> 29;
        if (this.#count[0] < msgbits)
            this.#count[1]++;

        let partlen = 64 - index;
        let msg_off = 0;

        if (msg.length >= partlen) {
            this.#buf.set(msg.subarray(0, partlen), index);
            this.#transform(this.#buf);
            msg_off += partlen;
            index = 0;

            const nblocks = (msg.length - msg_off) >>> 6;
            for (let i = 0; i < nblocks; i++) {
                this.#transform(msg.subarray(msg_off, msg_off + 64));
                msg_off += 64;
            }
        }

        // Copy leftover bytes into buffer
        if (msg_off < msg.length) {
            this.#buf.set(msg.subarray(msg_off), index);
        }

        return this;
    }

    finish(): Uint8Array {
        const bits = new Uint8Array(8);
        bits.set(u8(this.#count));  // Encode (bits, context->count, 8);

        // Get number of partial block bytes in buffer
        const index  = (this.#count[0] >>> 3) & 0x3f;
        const padlen = (index < 56) ? (56 - index) : (120 - index);
        if (padlen) this.update(MD5_PADDING.subarray(0, padlen));

        this.update(bits);

        return u8(this.#state);
    }

    static digest(msg: Uint8Array): Uint8Array {
        return new this().update(msg).finish();
    }
}
