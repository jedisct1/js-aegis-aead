const SBOX = new Uint8Array([
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
	0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
	0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
	0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
	0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
	0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
	0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
	0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
	0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
	0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
	0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
	0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
	0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
	0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
	0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
	0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
	0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
	0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

function mul2(x: number): number {
	return ((x << 1) ^ ((x >>> 7) * 0x1b)) & 0xff;
}

function mul3(x: number): number {
	return mul2(x) ^ x;
}

/**
 * Performs a single AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey).
 * Writes result to the provided output buffer.
 * @param input - 16-byte input block
 * @param roundKey - 16-byte round key
 * @param out - 16-byte output buffer
 */
export function aesRoundTo(
	input: ArrayLike<number>,
	roundKey: ArrayLike<number>,
	out: Uint8Array,
): void {
	const s0 = SBOX[input[0]!]!;
	const s1 = SBOX[input[5]!]!;
	const s2 = SBOX[input[10]!]!;
	const s3 = SBOX[input[15]!]!;
	const s4 = SBOX[input[4]!]!;
	const s5 = SBOX[input[9]!]!;
	const s6 = SBOX[input[14]!]!;
	const s7 = SBOX[input[3]!]!;
	const s8 = SBOX[input[8]!]!;
	const s9 = SBOX[input[13]!]!;
	const s10 = SBOX[input[2]!]!;
	const s11 = SBOX[input[7]!]!;
	const s12 = SBOX[input[12]!]!;
	const s13 = SBOX[input[1]!]!;
	const s14 = SBOX[input[6]!]!;
	const s15 = SBOX[input[11]!]!;

	out[0] = mul2(s0) ^ mul3(s1) ^ s2 ^ s3 ^ roundKey[0]!;
	out[1] = s0 ^ mul2(s1) ^ mul3(s2) ^ s3 ^ roundKey[1]!;
	out[2] = s0 ^ s1 ^ mul2(s2) ^ mul3(s3) ^ roundKey[2]!;
	out[3] = mul3(s0) ^ s1 ^ s2 ^ mul2(s3) ^ roundKey[3]!;
	out[4] = mul2(s4) ^ mul3(s5) ^ s6 ^ s7 ^ roundKey[4]!;
	out[5] = s4 ^ mul2(s5) ^ mul3(s6) ^ s7 ^ roundKey[5]!;
	out[6] = s4 ^ s5 ^ mul2(s6) ^ mul3(s7) ^ roundKey[6]!;
	out[7] = mul3(s4) ^ s5 ^ s6 ^ mul2(s7) ^ roundKey[7]!;
	out[8] = mul2(s8) ^ mul3(s9) ^ s10 ^ s11 ^ roundKey[8]!;
	out[9] = s8 ^ mul2(s9) ^ mul3(s10) ^ s11 ^ roundKey[9]!;
	out[10] = s8 ^ s9 ^ mul2(s10) ^ mul3(s11) ^ roundKey[10]!;
	out[11] = mul3(s8) ^ s9 ^ s10 ^ mul2(s11) ^ roundKey[11]!;
	out[12] = mul2(s12) ^ mul3(s13) ^ s14 ^ s15 ^ roundKey[12]!;
	out[13] = s12 ^ mul2(s13) ^ mul3(s14) ^ s15 ^ roundKey[13]!;
	out[14] = s12 ^ s13 ^ mul2(s14) ^ mul3(s15) ^ roundKey[14]!;
	out[15] = mul3(s12) ^ s13 ^ s14 ^ mul2(s15) ^ roundKey[15]!;
}

/**
 * Performs a single AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey).
 * @param input - 16-byte input block
 * @param roundKey - 16-byte round key
 * @returns 16-byte output block
 */
export function aesRound(
	input: ArrayLike<number>,
	roundKey: ArrayLike<number>,
): Uint8Array {
	const out = new Uint8Array(16);
	aesRoundTo(input, roundKey, out);
	return out;
}

/**
 * XORs two 16-byte blocks and writes result to destination.
 * @param a - First byte array
 * @param b - Second byte array
 * @param out - Output buffer
 */
export function xorBlocksTo(
	a: ArrayLike<number>,
	b: ArrayLike<number>,
	out: Uint8Array,
): void {
	out[0] = a[0]! ^ b[0]!;
	out[1] = a[1]! ^ b[1]!;
	out[2] = a[2]! ^ b[2]!;
	out[3] = a[3]! ^ b[3]!;
	out[4] = a[4]! ^ b[4]!;
	out[5] = a[5]! ^ b[5]!;
	out[6] = a[6]! ^ b[6]!;
	out[7] = a[7]! ^ b[7]!;
	out[8] = a[8]! ^ b[8]!;
	out[9] = a[9]! ^ b[9]!;
	out[10] = a[10]! ^ b[10]!;
	out[11] = a[11]! ^ b[11]!;
	out[12] = a[12]! ^ b[12]!;
	out[13] = a[13]! ^ b[13]!;
	out[14] = a[14]! ^ b[14]!;
	out[15] = a[15]! ^ b[15]!;
}

/**
 * XORs two byte arrays of equal length.
 * @param a - First byte array
 * @param b - Second byte array
 * @returns XOR result
 */
export function xorBlocks(
	a: ArrayLike<number>,
	b: ArrayLike<number>,
): Uint8Array {
	const result = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) {
		result[i] = a[i]! ^ b[i]!;
	}
	return result;
}

/**
 * ANDs two 16-byte blocks and writes result to destination.
 * @param a - First byte array
 * @param b - Second byte array
 * @param out - Output buffer
 */
export function andBlocksTo(
	a: ArrayLike<number>,
	b: ArrayLike<number>,
	out: Uint8Array,
): void {
	out[0] = a[0]! & b[0]!;
	out[1] = a[1]! & b[1]!;
	out[2] = a[2]! & b[2]!;
	out[3] = a[3]! & b[3]!;
	out[4] = a[4]! & b[4]!;
	out[5] = a[5]! & b[5]!;
	out[6] = a[6]! & b[6]!;
	out[7] = a[7]! & b[7]!;
	out[8] = a[8]! & b[8]!;
	out[9] = a[9]! & b[9]!;
	out[10] = a[10]! & b[10]!;
	out[11] = a[11]! & b[11]!;
	out[12] = a[12]! & b[12]!;
	out[13] = a[13]! & b[13]!;
	out[14] = a[14]! & b[14]!;
	out[15] = a[15]! & b[15]!;
}

/**
 * ANDs two byte arrays of equal length.
 * @param a - First byte array
 * @param b - Second byte array
 * @returns AND result
 */
export function andBlocks(
	a: ArrayLike<number>,
	b: ArrayLike<number>,
): Uint8Array {
	const result = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) {
		result[i] = a[i]! & b[i]!;
	}
	return result;
}

/**
 * Pads data with zeros to a multiple of the block size.
 * @param data - Input data
 * @param blockSizeBytes - Block size in bytes
 * @returns Padded data (or empty array if data is empty)
 */
export function zeroPad(
	data: ArrayLike<number>,
	blockSizeBytes: number,
): Uint8Array {
	if (data.length === 0) return new Uint8Array(0);
	const paddedLen = Math.ceil(data.length / blockSizeBytes) * blockSizeBytes;
	if (paddedLen === data.length) return new Uint8Array(data);
	const padded = new Uint8Array(paddedLen);
	padded.set(data);
	return padded;
}

/**
 * Concatenates multiple byte arrays into a single Uint8Array.
 * @param arrays - Byte arrays to concatenate
 * @returns Concatenated result
 */
export function concatBytes(...arrays: ArrayLike<number>[]): Uint8Array {
	const totalLen = arrays.reduce((sum, arr) => sum + arr.length, 0);
	const result = new Uint8Array(totalLen);
	let offset = 0;
	for (const arr of arrays) {
		result.set(arr, offset);
		offset += arr.length;
	}
	return result;
}

/**
 * Writes a 64-bit unsigned integer in little-endian format to a buffer.
 * @param value - Value to encode (as bigint)
 * @param out - Output buffer (at least 8 bytes)
 * @param offset - Offset in output buffer (default: 0)
 */
export function le64To(value: bigint, out: Uint8Array, offset = 0): void {
	const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
	view.setUint32(offset, Number(value & 0xffffffffn), true);
	view.setUint32(offset + 4, Number((value >> 32n) & 0xffffffffn), true);
}

/**
 * Encodes a 64-bit unsigned integer in little-endian format.
 * @param value - Value to encode (as bigint)
 * @returns 8-byte little-endian representation
 */
export function le64(value: bigint): Uint8Array {
	const result = new Uint8Array(8);
	le64To(value, result);
	return result;
}

/**
 * Compares two byte arrays in constant time to prevent timing attacks.
 * @param a - First byte array
 * @param b - Second byte array
 * @returns True if arrays are equal, false otherwise
 */
export function constantTimeEqual(
	a: ArrayLike<number>,
	b: ArrayLike<number>,
): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i]! ^ b[i]!;
	}
	return diff === 0;
}

/** AEGIS initialization constant C0 (first bytes of the Fibonacci sequence mod 256). */
export const C0 = new Uint8Array([
	0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90,
	0xe9, 0x79, 0x62,
]);

/** AEGIS initialization constant C1 (derived from sqrt(5)). */
export const C1 = new Uint8Array([
	0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73,
	0xb5, 0x28, 0xdd,
]);
