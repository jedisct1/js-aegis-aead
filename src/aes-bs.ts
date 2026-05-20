/**
 * Bitsliced AES implementation using 32-bit integers.
 * Processes 8 AES blocks simultaneously for constant-time operation.
 * Based on the barrel-shiftrows representation by Adomnicai and Peyrin.
 */

/**
 * Bitsliced representation of 8 AES blocks.
 * 32 uint32 words where each bit position corresponds to one of 8 blocks.
 */
export type AesBlocks = Uint32Array;

/**
 * A single AES block as 4 uint32 words (little-endian).
 */
export type AesBlock = Uint32Array;

/**
 * Creates a new bitsliced state for 8 AES blocks.
 */
export function createAesBlocks(): AesBlocks {
	return new Uint32Array(32);
}

/**
 * Creates a new AES block (4 uint32 words).
 */
export function createAesBlock(): AesBlock {
	return new Uint32Array(4);
}

/**
 * Swap-move operation used in pack/unpack transformations.
 * Swaps bits at positions n between a and b using a mask.
 */
function swapmove(
	st: Uint32Array,
	aIdx: number,
	bIdx: number,
	mask: number,
	n: number,
): void {
	const tmp = ((st[bIdx]! ^ (st[aIdx]! >>> n)) & mask) >>> 0;
	st[bIdx] = (st[bIdx]! ^ tmp) >>> 0;
	st[aIdx] = (st[aIdx]! ^ ((tmp << n) >>> 0)) >>> 0;
}

/**
 * 32-bit left rotation.
 */
function rotl32(x: number, b: number): number {
	return ((x << b) | (x >>> (32 - b))) >>> 0;
}

function sbox(st: Uint32Array, offset: number): void {
	const u0 = st[offset]!;
	const u1 = st[offset + 1]!;
	const u2 = st[offset + 2]!;
	const u3 = st[offset + 3]!;
	const u4 = st[offset + 4]!;
	const u5 = st[offset + 5]!;
	const u6 = st[offset + 6]!;
	const u7 = st[offset + 7]!;

	const z24 = u3 ^ u4;
	const q17 = u1 ^ u7;
	const q16 = u5 ^ q17;
	const q0 = z24 ^ q16;
	const q7 = z24 ^ u1 ^ u6;
	const q2 = u2 ^ q0;
	const q1 = q7 ^ q2;
	const q3 = u0 ^ q7;
	const q4 = u0 ^ q2;
	const q5 = u1 ^ q4;
	const q6 = u2 ^ u3;
	const q10 = q6 ^ q7;
	const q8 = u0 ^ q10;
	const q9 = q8 ^ q2;
	const q12 = z24 ^ q17;
	const q15 = u7 ^ q4;
	const m02 = u0 ^ u2;
	const m15 = u1 ^ u5;
	const q13 = m02 ^ m15;
	const q14 = m02 ^ u7;
	const q11 = u5;

	const t20 = q6 & q12;
	const t21 = q3 & q14;
	const t22 = q1 & q16;
	const t23 = q2 & q17;
	const x0 = (q3 | q14) ^ (q0 & q7) ^ (t20 ^ t22);
	const x1 = (q4 | q13) ^ (q10 & q11) ^ (t21 ^ t20);
	const x2 = (q2 | q17) ^ (q5 & q9) ^ (t21 ^ t22);
	const x3 = (q8 | q15) ^ t23 ^ (t21 ^ (q4 & q13));

	const a = x1 & ~x3;
	const b = x0 & ~x3;
	const c = x3 & ~x1;
	const d = x2 & ~x1;
	const e = x0 ^ a;
	const y0 = x3 ^ (x2 & ~e);
	const f = x1 ^ b;
	const y1 = c ^ (x2 & f);
	const g = x2 ^ c;
	const y2 = x1 ^ (x0 & ~g);
	const h = x3 ^ d;
	const y3 = a ^ (x0 & h);
	const y02 = y2 ^ y0;
	const y13 = y3 ^ y1;
	const y23 = y3 ^ y2;
	const y01 = y1 ^ y0;
	const y00 = y02 ^ y13;

	const a0 = y01 & q11;
	const a1 = y0 & q12;
	const a2 = y1 & q0;
	const a3 = y23 & q17;
	const a4 = y2 & q5;
	const a5 = y3 & q15;
	const a6 = y13 & q14;
	const a7 = y00 & q16;
	const a8 = y02 & q13;
	const a9 = y01 & q7;
	const a10 = y0 & q10;
	const a11 = y1 & q6;
	const a12 = y23 & q2;
	const a13 = y2 & q9;
	const a14 = y3 & q8;
	const a15 = y13 & q3;
	const a16 = y00 & q1;
	const a17 = y02 & q4;

	const r0 = a1 ^ a5;
	const r1 = a9 ^ a15;
	const r2 = a4 ^ r0;
	const r3 = a2 ^ a10;
	const r4 = a11 ^ a17;
	const r5 = a8 ^ r1;
	const r6 = a0 ^ a16;
	const r7 = a7 ^ a13;
	const r8 = a11 ^ a14;
	const r9 = r3 ^ r4;
	const r10 = r5 ^ r6;
	const r11 = r2 ^ r9;
	const r12 = a3 ^ r0;
	const r13 = r7 ^ r8;
	const r14 = r12 ^ r13;
	st[offset] = r10 ^ r14;
	const r15 = a6 ^ a10;
	const r16 = r15 ^ r2;
	st[offset + 1] = ~(r10 ^ r16);
	st[offset + 2] = ~(a2 ^ r2);
	const r17 = a12 ^ a13;
	const r18 = a15 ^ r17;
	st[offset + 3] = r18 ^ r11;
	const r19 = a1 ^ a14;
	const r20 = a17 ^ r3;
	const r21 = r7 ^ r19;
	const r22 = r5 ^ r20;
	st[offset + 4] = r21 ^ r22;
	const r23 = a9 ^ a12;
	st[offset + 5] = r8 ^ r23;
	st[offset + 6] = ~(r1 ^ r4);
	st[offset + 7] = ~(a16 ^ r11);
}

/**
 * Apply S-box to all 4 byte positions.
 */
function sboxes(st: AesBlocks): void {
	for (let i = 0; i < 4; i++) {
		sbox(st, 8 * i);
	}
}

/**
 * ShiftRows operation in bitsliced form.
 */
function shiftrows(st: AesBlocks): void {
	for (let i = 8; i < 16; i++) {
		st[i] = rotl32(st[i]!, 24);
	}
	for (let i = 16; i < 24; i++) {
		st[i] = rotl32(st[i]!, 16);
	}
	for (let i = 24; i < 32; i++) {
		st[i] = rotl32(st[i]!, 8);
	}
}

/**
 * MixColumns operation in bitsliced form.
 */
function mixcolumns(st: AesBlocks): void {
	const t2_0 = (st[0]! ^ st[8]!) >>> 0;
	const t2_1 = (st[8]! ^ st[16]!) >>> 0;
	const t2_2 = (st[16]! ^ st[24]!) >>> 0;
	const t2_3 = (st[24]! ^ st[0]!) >>> 0;

	let t0_0 = (st[7]! ^ st[15]!) >>> 0;
	let t0_1 = (st[15]! ^ st[23]!) >>> 0;
	let t0_2 = (st[23]! ^ st[31]!) >>> 0;
	let t0_3 = (st[31]! ^ st[7]!) >>> 0;

	let t = st[7]!;
	st[7] = (t2_0 ^ t0_2 ^ st[15]!) >>> 0;
	st[15] = (t2_1 ^ t0_2 ^ t) >>> 0;
	t = st[23]!;
	st[23] = (t2_2 ^ t0_0 ^ st[31]!) >>> 0;
	st[31] = (t2_3 ^ t0_0 ^ t) >>> 0;

	let t1_0 = (st[6]! ^ st[14]!) >>> 0;
	let t1_1 = (st[14]! ^ st[22]!) >>> 0;
	let t1_2 = (st[22]! ^ st[30]!) >>> 0;
	let t1_3 = (st[30]! ^ st[6]!) >>> 0;

	t = st[6]!;
	let t_bis = st[14]!;
	st[6] = (t0_0 ^ t2_0 ^ st[14]! ^ t1_2) >>> 0;
	st[14] = (t0_1 ^ t2_1 ^ t1_2 ^ t) >>> 0;
	t = st[22]!;
	st[22] = (t0_2 ^ t2_2 ^ t1_3 ^ t_bis) >>> 0;
	st[30] = (t0_3 ^ t2_3 ^ t1_0 ^ t) >>> 0;

	t0_0 = (st[5]! ^ st[13]!) >>> 0;
	t0_1 = (st[13]! ^ st[21]!) >>> 0;
	t0_2 = (st[21]! ^ st[29]!) >>> 0;
	t0_3 = (st[29]! ^ st[5]!) >>> 0;

	t = st[5]!;
	t_bis = st[13]!;
	st[5] = (t1_0 ^ t0_1 ^ st[29]!) >>> 0;
	st[13] = (t1_1 ^ t0_2 ^ t) >>> 0;
	t = st[21]!;
	st[21] = (t1_2 ^ t0_3 ^ t_bis) >>> 0;
	st[29] = (t1_3 ^ t0_0 ^ t) >>> 0;

	t1_0 = (st[4]! ^ st[12]!) >>> 0;
	t1_1 = (st[12]! ^ st[20]!) >>> 0;
	t1_2 = (st[20]! ^ st[28]!) >>> 0;
	t1_3 = (st[28]! ^ st[4]!) >>> 0;

	t = st[4]!;
	t_bis = st[12]!;
	st[4] = (t0_0 ^ t2_0 ^ t1_1 ^ st[28]!) >>> 0;
	st[12] = (t0_1 ^ t2_1 ^ t1_2 ^ t) >>> 0;
	t = st[20]!;
	st[20] = (t0_2 ^ t2_2 ^ t1_3 ^ t_bis) >>> 0;
	st[28] = (t0_3 ^ t2_3 ^ t1_0 ^ t) >>> 0;

	t0_0 = (st[3]! ^ st[11]!) >>> 0;
	t0_1 = (st[11]! ^ st[19]!) >>> 0;
	t0_2 = (st[19]! ^ st[27]!) >>> 0;
	t0_3 = (st[27]! ^ st[3]!) >>> 0;

	t = st[3]!;
	t_bis = st[11]!;
	st[3] = (t1_0 ^ t2_0 ^ t0_1 ^ st[27]!) >>> 0;
	st[11] = (t1_1 ^ t2_1 ^ t0_2 ^ t) >>> 0;
	t = st[19]!;
	st[19] = (t1_2 ^ t2_2 ^ t0_3 ^ t_bis) >>> 0;
	st[27] = (t1_3 ^ t2_3 ^ t0_0 ^ t) >>> 0;

	t1_0 = (st[2]! ^ st[10]!) >>> 0;
	t1_1 = (st[10]! ^ st[18]!) >>> 0;
	t1_2 = (st[18]! ^ st[26]!) >>> 0;
	t1_3 = (st[26]! ^ st[2]!) >>> 0;

	t = st[2]!;
	t_bis = st[10]!;
	st[2] = (t0_0 ^ t1_1 ^ st[26]!) >>> 0;
	st[10] = (t0_1 ^ t1_2 ^ t) >>> 0;
	t = st[18]!;
	st[18] = (t0_2 ^ t1_3 ^ t_bis) >>> 0;
	st[26] = (t0_3 ^ t1_0 ^ t) >>> 0;

	t0_0 = (st[1]! ^ st[9]!) >>> 0;
	t0_1 = (st[9]! ^ st[17]!) >>> 0;
	t0_2 = (st[17]! ^ st[25]!) >>> 0;
	t0_3 = (st[25]! ^ st[1]!) >>> 0;

	t = st[1]!;
	t_bis = st[9]!;
	st[1] = (t1_0 ^ t0_1 ^ st[25]!) >>> 0;
	st[9] = (t1_1 ^ t0_2 ^ t) >>> 0;
	t = st[17]!;
	st[17] = (t1_2 ^ t0_3 ^ t_bis) >>> 0;
	st[25] = (t1_3 ^ t0_0 ^ t) >>> 0;

	t = st[0]!;
	t_bis = st[8]!;
	st[0] = (t0_0 ^ t2_1 ^ st[24]!) >>> 0;
	st[8] = (t0_1 ^ t2_2 ^ t) >>> 0;
	t = st[16]!;
	st[16] = (t0_2 ^ t2_3 ^ t_bis) >>> 0;
	st[24] = (t0_3 ^ t2_0 ^ t) >>> 0;
}

/**
 * Complete AES round (SubBytes + ShiftRows + MixColumns).
 * Note: AddRoundKey is handled separately in AEGIS.
 */
export function aesRound(st: AesBlocks): void {
	sboxes(st);
	shiftrows(st);
	mixcolumns(st);
}

/**
 * Pack 8 AES blocks into bitsliced representation.
 */
export function pack(st: AesBlocks): void {
	for (let i = 0; i < 8; i++) {
		swapmove(st, i, i + 8, 0x00ff00ff, 8);
		swapmove(st, i + 16, i + 24, 0x00ff00ff, 8);
	}
	for (let i = 0; i < 16; i++) {
		swapmove(st, i, i + 16, 0x0000ffff, 16);
	}
	for (let i = 0; i < 32; i += 8) {
		swapmove(st, i + 1, i, 0x55555555, 1);
		swapmove(st, i + 3, i + 2, 0x55555555, 1);
		swapmove(st, i + 5, i + 4, 0x55555555, 1);
		swapmove(st, i + 7, i + 6, 0x55555555, 1);
		swapmove(st, i + 2, i, 0x33333333, 2);
		swapmove(st, i + 3, i + 1, 0x33333333, 2);
		swapmove(st, i + 6, i + 4, 0x33333333, 2);
		swapmove(st, i + 7, i + 5, 0x33333333, 2);
		swapmove(st, i + 4, i, 0x0f0f0f0f, 4);
		swapmove(st, i + 5, i + 1, 0x0f0f0f0f, 4);
		swapmove(st, i + 6, i + 2, 0x0f0f0f0f, 4);
		swapmove(st, i + 7, i + 3, 0x0f0f0f0f, 4);
	}
}

/**
 * Unpack bitsliced representation to 8 AES blocks.
 */
export function unpack(st: AesBlocks): void {
	for (let i = 0; i < 32; i += 8) {
		swapmove(st, i + 1, i, 0x55555555, 1);
		swapmove(st, i + 3, i + 2, 0x55555555, 1);
		swapmove(st, i + 5, i + 4, 0x55555555, 1);
		swapmove(st, i + 7, i + 6, 0x55555555, 1);
		swapmove(st, i + 2, i, 0x33333333, 2);
		swapmove(st, i + 3, i + 1, 0x33333333, 2);
		swapmove(st, i + 6, i + 4, 0x33333333, 2);
		swapmove(st, i + 7, i + 5, 0x33333333, 2);
		swapmove(st, i + 4, i, 0x0f0f0f0f, 4);
		swapmove(st, i + 5, i + 1, 0x0f0f0f0f, 4);
		swapmove(st, i + 6, i + 2, 0x0f0f0f0f, 4);
		swapmove(st, i + 7, i + 3, 0x0f0f0f0f, 4);
	}
	for (let i = 0; i < 16; i++) {
		swapmove(st, i, i + 16, 0x0000ffff, 16);
	}
	for (let i = 0; i < 8; i++) {
		swapmove(st, i, i + 8, 0x00ff00ff, 8);
		swapmove(st, i + 16, i + 24, 0x00ff00ff, 8);
	}
}

/**
 * Pack only blocks 0 and 4 (used for constant inputs in AEGIS-128L).
 */
export function pack04(st: AesBlocks): void {
	swapmove(st, 0, 0 + 8, 0x00ff00ff, 8);
	swapmove(st, 0 + 16, 0 + 24, 0x00ff00ff, 8);
	swapmove(st, 4, 4 + 8, 0x00ff00ff, 8);
	swapmove(st, 4 + 16, 4 + 24, 0x00ff00ff, 8);

	swapmove(st, 0, 0 + 16, 0x0000ffff, 16);
	swapmove(st, 4, 4 + 16, 0x0000ffff, 16);
	swapmove(st, 8, 8 + 16, 0x0000ffff, 16);
	swapmove(st, 12, 12 + 16, 0x0000ffff, 16);

	for (let i = 0; i < 32; i += 8) {
		swapmove(st, i + 1, i, 0x55555555, 1);
		swapmove(st, i + 5, i + 4, 0x55555555, 1);
		swapmove(st, i + 2, i, 0x33333333, 2);
		swapmove(st, i + 3, i + 1, 0x33333333, 2);
		swapmove(st, i + 6, i + 4, 0x33333333, 2);
		swapmove(st, i + 7, i + 5, 0x33333333, 2);
		swapmove(st, i + 4, i, 0x0f0f0f0f, 4);
		swapmove(st, i + 5, i + 1, 0x0f0f0f0f, 4);
		swapmove(st, i + 6, i + 2, 0x0f0f0f0f, 4);
		swapmove(st, i + 7, i + 3, 0x0f0f0f0f, 4);
	}
}

/**
 * Inverse of pack04: unpack only blocks 0 and 4.
 */
export function unpack04(st: AesBlocks): void {
	for (let i = 0; i < 32; i += 8) {
		swapmove(st, i + 7, i + 3, 0x0f0f0f0f, 4);
		swapmove(st, i + 6, i + 2, 0x0f0f0f0f, 4);
		swapmove(st, i + 5, i + 1, 0x0f0f0f0f, 4);
		swapmove(st, i + 4, i, 0x0f0f0f0f, 4);
		swapmove(st, i + 7, i + 5, 0x33333333, 2);
		swapmove(st, i + 6, i + 4, 0x33333333, 2);
		swapmove(st, i + 3, i + 1, 0x33333333, 2);
		swapmove(st, i + 2, i, 0x33333333, 2);
		swapmove(st, i + 5, i + 4, 0x55555555, 1);
		swapmove(st, i + 1, i, 0x55555555, 1);
	}

	swapmove(st, 12, 12 + 16, 0x0000ffff, 16);
	swapmove(st, 8, 8 + 16, 0x0000ffff, 16);
	swapmove(st, 4, 4 + 16, 0x0000ffff, 16);
	swapmove(st, 0, 0 + 16, 0x0000ffff, 16);

	swapmove(st, 4 + 16, 4 + 24, 0x00ff00ff, 8);
	swapmove(st, 4, 4 + 8, 0x00ff00ff, 8);
	swapmove(st, 0 + 16, 0 + 24, 0x00ff00ff, 8);
	swapmove(st, 0, 0 + 8, 0x00ff00ff, 8);
}

/**
 * Pack only block 0 (used for constant inputs in AEGIS-256).
 */
export function pack04_6(st: AesBlocks): void {
	swapmove(st, 0, 0 + 8, 0x00ff00ff, 8);
	swapmove(st, 0 + 16, 0 + 24, 0x00ff00ff, 8);

	swapmove(st, 0, 0 + 16, 0x0000ffff, 16);
	swapmove(st, 8, 8 + 16, 0x0000ffff, 16);

	for (let i = 0; i < 32; i += 8) {
		swapmove(st, i + 1, i, 0x55555555, 1);
		swapmove(st, i + 2, i, 0x33333333, 2);
		swapmove(st, i + 3, i + 1, 0x33333333, 2);
		swapmove(st, i + 4, i, 0x0f0f0f0f, 4);
		swapmove(st, i + 5, i + 1, 0x0f0f0f0f, 4);
		swapmove(st, i + 6, i + 2, 0x0f0f0f0f, 4);
		swapmove(st, i + 7, i + 3, 0x0f0f0f0f, 4);
	}
}

/**
 * Inverse of pack04_6: unpack only block 0.
 */
export function unpack04_6(st: AesBlocks): void {
	for (let i = 0; i < 32; i += 8) {
		swapmove(st, i + 7, i + 3, 0x0f0f0f0f, 4);
		swapmove(st, i + 6, i + 2, 0x0f0f0f0f, 4);
		swapmove(st, i + 5, i + 1, 0x0f0f0f0f, 4);
		swapmove(st, i + 4, i, 0x0f0f0f0f, 4);
		swapmove(st, i + 3, i + 1, 0x33333333, 2);
		swapmove(st, i + 2, i, 0x33333333, 2);
		swapmove(st, i + 1, i, 0x55555555, 1);
	}

	swapmove(st, 8, 8 + 16, 0x0000ffff, 16);
	swapmove(st, 0, 0 + 16, 0x0000ffff, 16);

	swapmove(st, 0 + 16, 0 + 24, 0x00ff00ff, 8);
	swapmove(st, 0, 0 + 8, 0x00ff00ff, 8);
}

/**
 * Computes the index into the bitsliced state array.
 * @param block - Block index (0-7)
 * @param word - Word index (0-3)
 */
export function wordIdx(block: number, word: number): number {
	return block + word * 8;
}

/**
 * Rotate all blocks right by 1 position (for AEGIS state rotation).
 * Performs (st[i] & 0xfefefefe) >> 1 | (st[i] & 0x01010101) << 7
 */
export function blocksRotr(st: AesBlocks): void {
	for (let i = 0; i < 32; i++) {
		st[i] =
			(((st[i]! & 0xfefefefe) >>> 1) | ((st[i]! & 0x01010101) << 7)) >>> 0;
	}
}

/**
 * Rotate within the bottom 6 lanes (for AEGIS-256, 6 blocks).
 */
export function blocksRotr6(st: AesBlocks): void {
	for (let i = 0; i < 32; i++) {
		st[i] =
			(((st[i]! & 0xf8f8f8f8) >>> 1) | ((st[i]! & 0x04040404) << 5)) >>> 0;
	}
}

/**
 * Put a single AES block into the bitsliced state at the given block position.
 */
export function blocksPut(st: AesBlocks, s: AesBlock, block: number): void {
	st[wordIdx(block, 0)] = s[0]!;
	st[wordIdx(block, 1)] = s[1]!;
	st[wordIdx(block, 2)] = s[2]!;
	st[wordIdx(block, 3)] = s[3]!;
}

/**
 * Load a 16-byte buffer into an AES block (4 uint32 little-endian).
 */
export function blockFromBytes(out: AesBlock, src: Uint8Array): void {
	const view = new DataView(src.buffer, src.byteOffset, src.byteLength);
	out[0] = view.getUint32(0, true);
	out[1] = view.getUint32(4, true);
	out[2] = view.getUint32(8, true);
	out[3] = view.getUint32(12, true);
}

/**
 * Store an AES block to a 16-byte buffer (little-endian).
 */
export function blockToBytes(out: Uint8Array, src: AesBlock): void {
	const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
	view.setUint32(0, src[0]!, true);
	view.setUint32(4, src[1]!, true);
	view.setUint32(8, src[2]!, true);
	view.setUint32(12, src[3]!, true);
}

/**
 * XOR two AES blocks: out = a ^ b
 */
export function blockXor(out: AesBlock, a: AesBlock, b: AesBlock): void {
	out[0] = (a[0]! ^ b[0]!) >>> 0;
	out[1] = (a[1]! ^ b[1]!) >>> 0;
	out[2] = (a[2]! ^ b[2]!) >>> 0;
	out[3] = (a[3]! ^ b[3]!) >>> 0;
}

/**
 * XOR two bitsliced states: a ^= b
 */
export function blocksXor(a: AesBlocks, b: AesBlocks): void {
	for (let i = 0; i < 32; i++) {
		a[i] = (a[i]! ^ b[i]!) >>> 0;
	}
}
