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

/**
 * S-box implementation using bitsliced logic gates.
 * Maximov & Ekdahl circuit.
 */
function sbox(st: Uint32Array, offset: number): void {
	let u0 = st[offset]!;
	let u1 = st[offset + 1]!;
	let u2 = st[offset + 2]!;
	let u3 = st[offset + 3]!;
	let u4 = st[offset + 4]!;
	let u5 = st[offset + 5]!;
	let u6 = st[offset + 6]!;
	let u7 = st[offset + 7]!;

	const z24 = (u3 ^ u4) >>> 0;
	const q17 = (u1 ^ u7) >>> 0;
	const q16 = (u5 ^ q17) >>> 0;
	const q0 = (z24 ^ q16) >>> 0;
	const q7 = (z24 ^ u1 ^ u6) >>> 0;
	const q2 = (u2 ^ q0) >>> 0;
	const q1 = (q7 ^ q2) >>> 0;
	const q3 = (u0 ^ q7) >>> 0;
	const q4 = (u0 ^ q2) >>> 0;
	const q5 = (u1 ^ q4) >>> 0;
	const q6 = (u2 ^ u3) >>> 0;
	const q10 = (q6 ^ q7) >>> 0;
	const q8 = (u0 ^ q10) >>> 0;
	const q9 = (q8 ^ q2) >>> 0;
	const q12 = (z24 ^ q17) >>> 0;
	const q15 = (u7 ^ q4) >>> 0;
	const q13 = (z24 ^ q15) >>> 0;
	const q14 = (q15 ^ q0) >>> 0;
	const q11 = u5;

	// NAND(x, y) = ~(x & y)
	// NOR(x, y) = ~(x | y)
	// XNOR(x, y) = ~(x ^ y)
	// MUX(s, x, y) = (x & s) | (y & ~s)
	const nand = (x: number, y: number) => ~(x & y) >>> 0;
	const nor = (x: number, y: number) => ~(x | y) >>> 0;
	const xnor = (x: number, y: number) => ~(x ^ y) >>> 0;
	const mux = (s: number, x: number, y: number) =>
		(((x & s) >>> 0) | ((y & ~s) >>> 0)) >>> 0;

	const t20 = nand(q6, q12);
	const t21 = nand(q3, q14);
	const t22 = nand(q1, q16);
	const x0 = (nor(q3, q14) ^ nand(q0, q7) ^ (t20 ^ t22)) >>> 0;
	const x1 = (nor(q4, q13) ^ nand(q10, q11) ^ (t21 ^ t20)) >>> 0;
	const x2 = (nor(q2, q17) ^ nand(q5, q9) ^ (t21 ^ t22)) >>> 0;
	const x3 = (nor(q8, q15) ^ nand(q2, q17) ^ (t21 ^ nand(q4, q13))) >>> 0;

	const t2 = xnor(nand(x0, x2), nor(x1, x3));
	const y0 = mux(x2, t2, x3);
	const y2 = mux(x0, t2, x1);
	const y1 = mux(t2, x3, mux(x1, x2, 0xffffffff));
	const y3 = mux(t2, x1, mux(x3, x0, 0xffffffff));
	const y02 = (y2 ^ y0) >>> 0;
	const y13 = (y3 ^ y1) >>> 0;
	const y23 = (y3 ^ y2) >>> 0;
	const y01 = (y1 ^ y0) >>> 0;
	const y00 = (y02 ^ y13) >>> 0;

	const n0 = nand(y01, q11);
	const n1 = nand(y0, q12);
	const n2 = nand(y1, q0);
	const n3 = nand(y23, q17);
	const n4 = nand(y2, q5);
	const n5 = nand(y3, q15);
	const n6 = nand(y13, q14);
	const n7 = nand(y00, q16);
	const n8 = nand(y02, q13);
	const n9 = nand(y01, q7);
	const n10 = nand(y0, q10);
	const n11 = nand(y1, q6);
	const n12 = nand(y23, q2);
	const n13 = nand(y2, q9);
	const n14 = nand(y3, q8);
	const n15 = nand(y13, q3);
	const n16 = nand(y00, q1);
	const n17 = nand(y02, q4);

	const h1 = (n4 ^ n1 ^ n5) >>> 0;
	u2 = xnor(n2, h1);
	const h2 = (n9 ^ n15) >>> 0;
	u6 = xnor(h2, (n11 ^ n17) >>> 0);
	const h4 = (n11 ^ n14) >>> 0;
	const h5 = (n9 ^ n12) >>> 0;
	u5 = (h4 ^ h5) >>> 0;
	const h7 = (u2 ^ u6) >>> 0;
	const h8 = (n10 ^ h7) >>> 0;
	u7 = xnor((n16 ^ h2) >>> 0, h8);
	const h9 = (n8 ^ h1) >>> 0;
	const h10 = (n13 ^ h8) >>> 0;
	u3 = (h5 ^ h10) >>> 0;
	const h13 = (h4 ^ n7 ^ h9 ^ h10) >>> 0;
	u4 = (n1 ^ h13) >>> 0;
	const h14 = xnor(n0, u7);
	u1 = xnor(n6, (h7 ^ h9 ^ h14) >>> 0);
	u0 = (h13 ^ n3 ^ n4 ^ h14) >>> 0;

	st[offset] = u0;
	st[offset + 1] = u1;
	st[offset + 2] = u2;
	st[offset + 3] = u3;
	st[offset + 4] = u4;
	st[offset + 5] = u5;
	st[offset + 6] = u6;
	st[offset + 7] = u7;
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
