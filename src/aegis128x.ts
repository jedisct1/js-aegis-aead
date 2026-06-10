/**
 * AEGIS-128X implementation with configurable parallelism degree.
 * Extends AEGIS-128L with parallel lanes for improved performance on wide
 * SIMD architectures. Each lane is an independent AEGIS-128L state kept in
 * packed bitsliced form, built on the constant-time bitsliced AES core.
 */

import {
	type AesBlock,
	type AesBlocks,
	aegisRound128,
	blockFromBytes,
	blocksPut,
	blockToBytes,
	blockXor,
	createAesBlock,
	createAesBlocks,
	keystream128,
	pack,
	packConstantInput128,
	unpack,
	wordIdx,
} from "./aes-bs.js";
import { randomBytes } from "./random.js";
import { constantTimeEqual, zeroPad } from "./utils.js";

const C0: AesBlock = new Uint32Array([
	0x02010100, 0x0d080503, 0x59372215, 0x6279e990,
]);
const C1: AesBlock = new Uint32Array([
	0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573,
]);

/**
 * AEGIS-128X cipher state with configurable parallelism degree.
 */
export class Aegis128XState {
	private d: number;
	private halfRate: number;
	private rateBytes: number;
	private lanes: AesBlocks[];
	private ci: AesBlocks;
	private ciZero: AesBlocks;
	private tmp0: AesBlock;
	private tmp1: AesBlock;
	private z0: AesBlock;
	private z1: AesBlock;

	/**
	 * Creates a new AEGIS-128X state.
	 * @param degree - Parallelism degree (default: 2). Use 2 for AEGIS-128X2, 4 for AEGIS-128X4.
	 */
	constructor(degree: number = 2) {
		this.d = degree;
		this.halfRate = 16 * degree;
		this.rateBytes = 32 * degree;
		this.lanes = Array.from({ length: degree }, () => createAesBlocks());
		this.ci = createAesBlocks();
		this.ciZero = createAesBlocks();
		this.tmp0 = createAesBlock();
		this.tmp1 = createAesBlock();
		this.z0 = createAesBlock();
		this.z1 = createAesBlock();
	}

	/**
	 * Returns the state blocks as byte arrays indexed [block][lane] (for testing).
	 */
	get v(): Uint8Array[][] {
		const out: Uint8Array[][] = Array.from({ length: 8 }, () => []);
		const unpacked = createAesBlocks();
		const w = createAesBlock();
		for (let i = 0; i < this.d; i++) {
			unpacked.set(this.lanes[i]!);
			unpack(unpacked);
			for (let b = 0; b < 8; b++) {
				for (let j = 0; j < 4; j++) w[j] = unpacked[wordIdx(b, j)]!;
				const bytes = new Uint8Array(16);
				blockToBytes(bytes, w);
				out[b]!.push(bytes);
			}
		}
		return out;
	}

	/**
	 * Initializes the state with a key and nonce.
	 * @param key - 16-byte encryption key
	 * @param nonce - 16-byte nonce (must be unique per message)
	 */
	init(key: Uint8Array, nonce: Uint8Array): void {
		const k = createAesBlock();
		const n = createAesBlock();
		const kn = createAesBlock();
		const kc0 = createAesBlock();
		const kc1 = createAesBlock();

		blockFromBytes(k, key);
		blockFromBytes(n, nonce);
		blockXor(kn, k, n);
		blockXor(kc0, k, C0);
		blockXor(kc1, k, C1);

		const base = createAesBlocks();
		blocksPut(base, kn, 0);
		blocksPut(base, C1, 1);
		blocksPut(base, C0, 2);
		blocksPut(base, C1, 3);
		blocksPut(base, kn, 4);
		blocksPut(base, kc0, 5);
		blocksPut(base, kc1, 6);
		blocksPut(base, kc0, 7);
		pack(base);

		const ciNK = createAesBlocks();
		packConstantInput128(ciNK, n, k);

		const ctx = createAesBlock();
		const deltas: AesBlocks[] = [];
		for (let i = 0; i < this.d; i++) {
			this.lanes[i]!.set(base);
			const delta = createAesBlocks();
			ctx[0] = i | ((this.d - 1) << 8);
			blocksPut(delta, ctx, 3);
			blocksPut(delta, ctx, 7);
			pack(delta);
			deltas.push(delta);
		}

		for (let round = 0; round < 10; round++) {
			for (let i = 0; i < this.d; i++) {
				const st = this.lanes[i]!;
				const delta = deltas[i]!;
				for (let w = 0; w < 32; w++) st[w] = st[w]! ^ delta[w]!;
				aegisRound128(st, ciNK);
			}
		}
	}

	/**
	 * Absorbs an associated data block into the state.
	 * @param ai - Buffer holding the 32*degree-byte associated data block
	 * @param off - Offset of the block within the buffer
	 */
	absorb(ai: Uint8Array, off = 0): void {
		for (let i = 0; i < this.d; i++) {
			blockFromBytes(this.tmp0, ai, off + i * 16);
			blockFromBytes(this.tmp1, ai, off + this.halfRate + i * 16);
			packConstantInput128(this.ci, this.tmp0, this.tmp1);
			aegisRound128(this.lanes[i]!, this.ci);
		}
	}

	/**
	 * Encrypts a plaintext block and writes to output buffer.
	 * @param xi - Buffer holding the 32*degree-byte plaintext block
	 * @param out - Output buffer receiving the ciphertext block
	 * @param inOff - Offset of the plaintext block within xi
	 * @param outOff - Offset of the ciphertext block within out
	 */
	encTo(xi: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const t0 = this.tmp0;
		const t1 = this.tmp1;

		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;
			keystream128(st, this.z0, this.z1);

			blockFromBytes(t0, xi, inOff + i * 16);
			blockFromBytes(t1, xi, inOff + this.halfRate + i * 16);

			packConstantInput128(this.ci, t0, t1);
			aegisRound128(st, this.ci);

			blockXor(t0, t0, this.z0);
			blockXor(t1, t1, this.z1);

			blockToBytes(out, t0, outOff + i * 16);
			blockToBytes(out, t1, outOff + this.halfRate + i * 16);
		}
	}

	/**
	 * Encrypts a plaintext block.
	 * @param xi - Plaintext block (32*degree bytes)
	 * @returns Ciphertext block of the same size
	 */
	enc(xi: Uint8Array): Uint8Array {
		const out = new Uint8Array(this.rateBytes);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a ciphertext block and writes to output buffer.
	 * @param ci - Buffer holding the 32*degree-byte ciphertext block
	 * @param out - Output buffer receiving the plaintext block
	 * @param inOff - Offset of the ciphertext block within ci
	 * @param outOff - Offset of the plaintext block within out
	 */
	decTo(ci: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;

		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;

			blockFromBytes(msg0, ci, inOff + i * 16);
			blockFromBytes(msg1, ci, inOff + this.halfRate + i * 16);

			keystream128(st, this.z0, this.z1);
			blockXor(msg0, msg0, this.z0);
			blockXor(msg1, msg1, this.z1);

			packConstantInput128(this.ci, msg0, msg1);
			aegisRound128(st, this.ci);

			blockToBytes(out, msg0, outOff + i * 16);
			blockToBytes(out, msg1, outOff + this.halfRate + i * 16);
		}
	}

	/**
	 * Decrypts a ciphertext block.
	 * @param ci - Ciphertext block (32*degree bytes)
	 * @returns Plaintext block of the same size
	 */
	dec(ci: Uint8Array): Uint8Array {
		const out = new Uint8Array(this.rateBytes);
		this.decTo(ci, out);
		return out;
	}

	encInPlace(block: Uint8Array): void {
		this.encTo(block, block);
	}

	decInPlace(block: Uint8Array): void {
		this.decTo(block, block);
	}

	/**
	 * Decrypts a partial (final) ciphertext block.
	 * @param cn - Partial ciphertext block (smaller than 32*degree bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		const padded = zeroPad(cn, this.rateBytes);
		const ks = new Uint8Array(this.rateBytes);

		for (let i = 0; i < this.d; i++) {
			keystream128(this.lanes[i]!, this.z0, this.z1);
			blockToBytes(ks, this.z0, i * 16);
			blockToBytes(ks, this.z1, this.halfRate + i * 16);
		}

		const out = new Uint8Array(this.rateBytes);
		for (let j = 0; j < this.rateBytes; j++) out[j] = padded[j]! ^ ks[j]!;

		const xn = new Uint8Array(out.subarray(0, cn.length));

		out.fill(0, cn.length);
		for (let i = 0; i < this.d; i++) {
			blockFromBytes(this.tmp0, out, i * 16);
			blockFromBytes(this.tmp1, out, this.halfRate + i * 16);
			packConstantInput128(this.ci, this.tmp0, this.tmp1);
			aegisRound128(this.lanes[i]!, this.ci);
		}

		return xn;
	}

	/**
	 * Finalizes encryption/decryption and produces an authentication tag.
	 * @param adLen - Associated data length in bytes
	 * @param msgLen - Message length in bytes
	 * @param tagLen - Tag length (16 or 32 bytes)
	 * @returns Authentication tag
	 */
	finalize(adLen: number, msgLen: number, tagLen: 16 | 32 = 16): Uint8Array {
		const u = this.tmp0;
		const t = this.tmp1;

		u[0] = (adLen * 8) & 0xffffffff;
		u[1] = Math.floor((adLen * 8) / 0x100000000);
		u[2] = (msgLen * 8) & 0xffffffff;
		u[3] = Math.floor((msgLen * 8) / 0x100000000);

		const unpacked = createAesBlocks();
		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;
			unpacked.set(st);
			unpack(unpacked);
			for (let j = 0; j < 4; j++) t[j] = u[j]! ^ unpacked[wordIdx(2, j)]!;
			packConstantInput128(this.ci, t, t);
			for (let round = 0; round < 7; round++) {
				aegisRound128(st, this.ci);
			}
			unpack(st);
		}

		if (tagLen === 16) {
			const tagBlock = createAesBlock();
			for (let i = 0; i < this.d; i++) {
				const st = this.lanes[i]!;
				for (let j = 0; j < 4; j++) {
					tagBlock[j] =
						tagBlock[j]! ^
						st[wordIdx(0, j)]! ^
						st[wordIdx(1, j)]! ^
						st[wordIdx(2, j)]! ^
						st[wordIdx(3, j)]! ^
						st[wordIdx(4, j)]! ^
						st[wordIdx(5, j)]! ^
						st[wordIdx(6, j)]!;
				}
			}
			const tag = new Uint8Array(16);
			blockToBytes(tag, tagBlock);
			return tag;
		} else {
			const tagBlock0 = createAesBlock();
			const tagBlock1 = createAesBlock();
			for (let i = 0; i < this.d; i++) {
				const st = this.lanes[i]!;
				for (let j = 0; j < 4; j++) {
					tagBlock0[j] =
						tagBlock0[j]! ^
						st[wordIdx(0, j)]! ^
						st[wordIdx(1, j)]! ^
						st[wordIdx(2, j)]! ^
						st[wordIdx(3, j)]!;
					tagBlock1[j] =
						tagBlock1[j]! ^
						st[wordIdx(4, j)]! ^
						st[wordIdx(5, j)]! ^
						st[wordIdx(6, j)]! ^
						st[wordIdx(7, j)]!;
				}
			}
			const tag = new Uint8Array(32);
			blockToBytes(tag, tagBlock0);
			blockToBytes(tag, tagBlock1, 16);
			return tag;
		}
	}

	/**
	 * Finalizes MAC computation and produces an authentication tag.
	 * Uses a different finalization procedure than encryption/decryption.
	 * @param dataLen - Data length in bytes
	 * @param tagLen - Tag length (16 or 32 bytes)
	 * @returns Authentication tag
	 */
	finalizeMac(dataLen: number, tagLen: 16 | 32 = 16): Uint8Array {
		const u = this.tmp0;
		const t = this.tmp1;

		u[0] = (dataLen * 8) & 0xffffffff;
		u[1] = Math.floor((dataLen * 8) / 0x100000000);
		u[2] = tagLen * 8;
		u[3] = 0;

		const unpacked = createAesBlocks();
		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;
			unpacked.set(st);
			unpack(unpacked);
			for (let j = 0; j < 4; j++) t[j] = u[j]! ^ unpacked[wordIdx(2, j)]!;
			packConstantInput128(this.ci, t, t);
			for (let round = 0; round < 7; round++) {
				aegisRound128(st, this.ci);
			}
		}

		if (this.d > 1) {
			let tags: Uint8Array;
			if (tagLen === 16) {
				tags = new Uint8Array(16 * this.d);
				const tb = createAesBlock();
				for (let i = 0; i < this.d; i++) {
					unpacked.set(this.lanes[i]!);
					unpack(unpacked);
					for (let j = 0; j < 4; j++) {
						tb[j] =
							unpacked[wordIdx(0, j)]! ^
							unpacked[wordIdx(1, j)]! ^
							unpacked[wordIdx(2, j)]! ^
							unpacked[wordIdx(3, j)]! ^
							unpacked[wordIdx(4, j)]! ^
							unpacked[wordIdx(5, j)]! ^
							unpacked[wordIdx(6, j)]!;
					}
					blockToBytes(tags, tb, i * 16);
				}
			} else {
				tags = new Uint8Array(32 * (this.d - 1));
				const tb0 = createAesBlock();
				const tb1 = createAesBlock();
				for (let i = 1; i < this.d; i++) {
					unpacked.set(this.lanes[i]!);
					unpack(unpacked);
					for (let j = 0; j < 4; j++) {
						tb0[j] =
							unpacked[wordIdx(0, j)]! ^
							unpacked[wordIdx(1, j)]! ^
							unpacked[wordIdx(2, j)]! ^
							unpacked[wordIdx(3, j)]!;
						tb1[j] =
							unpacked[wordIdx(4, j)]! ^
							unpacked[wordIdx(5, j)]! ^
							unpacked[wordIdx(6, j)]! ^
							unpacked[wordIdx(7, j)]!;
					}
					blockToBytes(tags, tb0, (i - 1) * 32);
					blockToBytes(tags, tb1, (i - 1) * 32 + 16);
				}
			}

			for (let off = 0; off + 32 <= tags.length; off += 32) {
				blockFromBytes(this.tmp0, tags, off);
				blockFromBytes(this.tmp1, tags, off + 16);
				packConstantInput128(this.ci, this.tmp0, this.tmp1);
				aegisRound128(this.lanes[0]!, this.ci);
				for (let i = 1; i < this.d; i++) {
					aegisRound128(this.lanes[i]!, this.ciZero);
				}
			}

			unpacked.set(this.lanes[0]!);
			unpack(unpacked);
			t[0] = this.d ^ unpacked[wordIdx(2, 0)]!;
			t[1] = unpacked[wordIdx(2, 1)]!;
			t[2] = (tagLen * 8) ^ unpacked[wordIdx(2, 2)]!;
			t[3] = unpacked[wordIdx(2, 3)]!;
			packConstantInput128(this.ci, t, t);
			for (let round = 0; round < 7; round++) {
				aegisRound128(this.lanes[0]!, this.ci);
				for (let i = 1; i < this.d; i++) {
					aegisRound128(this.lanes[i]!, this.ciZero);
				}
			}
		}

		const st = createAesBlocks();
		st.set(this.lanes[0]!);
		unpack(st);

		if (tagLen === 16) {
			const tag = new Uint8Array(16);
			const tagBlock = createAesBlock();
			for (let j = 0; j < 4; j++) {
				tagBlock[j] =
					st[wordIdx(0, j)]! ^
					st[wordIdx(1, j)]! ^
					st[wordIdx(2, j)]! ^
					st[wordIdx(3, j)]! ^
					st[wordIdx(4, j)]! ^
					st[wordIdx(5, j)]! ^
					st[wordIdx(6, j)]!;
			}
			blockToBytes(tag, tagBlock);
			return tag;
		} else {
			const tag = new Uint8Array(32);
			const tagBlock0 = createAesBlock();
			const tagBlock1 = createAesBlock();
			for (let j = 0; j < 4; j++) {
				tagBlock0[j] =
					st[wordIdx(0, j)]! ^
					st[wordIdx(1, j)]! ^
					st[wordIdx(2, j)]! ^
					st[wordIdx(3, j)]!;
				tagBlock1[j] =
					st[wordIdx(4, j)]! ^
					st[wordIdx(5, j)]! ^
					st[wordIdx(6, j)]! ^
					st[wordIdx(7, j)]!;
			}
			blockToBytes(tag, tagBlock0);
			blockToBytes(tag, tagBlock1, 16);
			return tag;
		}
	}
}

/**
 * Encrypts a message using AEGIS-128X (detached mode).
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Object containing ciphertext and authentication tag separately
 */
export function aegis128XEncryptDetached(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis128XState(degree);
	const rateBytes = 32 * degree;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded, i);
	}

	const ciphertext = new Uint8Array(msg.length);
	const fullBlocks = Math.floor(msg.length / rateBytes) * rateBytes;

	for (let i = 0; i < fullBlocks; i += rateBytes) {
		state.encTo(msg, ciphertext, i, i);
	}

	if (msg.length > fullBlocks) {
		const lastBlock = zeroPad(msg.subarray(fullBlocks), rateBytes);
		const encBlock = state.enc(lastBlock);
		ciphertext.set(encBlock.subarray(0, msg.length - fullBlocks), fullBlocks);
	}

	const tag = state.finalize(ad.length, msg.length, tagLen);

	return { ciphertext, tag };
}

/**
 * Decrypts a message using AEGIS-128X (detached mode).
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @param degree - Parallelism degree (default: 2)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128XDecryptDetached(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	degree: number = 2,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128XState(degree);
	const rateBytes = 32 * degree;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded, i);
	}

	const msg = new Uint8Array(ct.length);
	const fullBlocks = Math.floor(ct.length / rateBytes) * rateBytes;

	for (let i = 0; i < fullBlocks; i += rateBytes) {
		state.decTo(ct, msg, i, i);
	}

	if (ct.length > fullBlocks) {
		msg.set(state.decPartial(ct.subarray(fullBlocks)), fullBlocks);
	}

	const expectedTag = state.finalize(ad.length, msg.length, tagLen);

	if (!constantTimeEqual(tag, expectedTag)) {
		msg.fill(0);
		return null;
	}

	return msg;
}

/**
 * Encrypts a message in-place using AEGIS-128X (detached mode).
 * The input buffer is modified to contain the ciphertext.
 * @param data - Buffer containing plaintext (will be overwritten with ciphertext)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Authentication tag
 */
export function aegis128XEncryptDetachedInPlace(
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array {
	const state = new Aegis128XState(degree);
	const rateBytes = 32 * degree;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded, i);
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / rateBytes) * rateBytes;

	for (let i = 0; i < fullBlocksLen; i += rateBytes) {
		state.encTo(data, data, i, i);
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const lastBlock = zeroPad(lastPartial, rateBytes);
		const encBlock = state.enc(lastBlock);
		lastPartial.set(encBlock.subarray(0, lastPartial.length));
	}

	return state.finalize(ad.length, msgLen, tagLen);
}

/**
 * Decrypts a message in-place using AEGIS-128X (detached mode).
 * The input buffer is modified to contain the plaintext (or zeroed on failure).
 * @param data - Buffer containing ciphertext (will be overwritten with plaintext)
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @param degree - Parallelism degree (default: 2)
 * @returns True if authentication succeeds, false otherwise
 */
export function aegis128XDecryptDetachedInPlace(
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	degree: number = 2,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128XState(degree);
	const rateBytes = 32 * degree;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded, i);
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / rateBytes) * rateBytes;

	for (let i = 0; i < fullBlocksLen; i += rateBytes) {
		state.decTo(data, data, i, i);
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const decrypted = state.decPartial(lastPartial);
		lastPartial.set(decrypted);
	}

	const expectedTag = state.finalize(ad.length, msgLen, tagLen);

	if (!constantTimeEqual(tag, expectedTag)) {
		data.fill(0);
		return false;
	}

	return true;
}

/** AEGIS-128X2 in-place encryption - detached mode (degree=2). */
export const aegis128X2EncryptDetachedInPlace = (
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XEncryptDetachedInPlace(data, ad, key, nonce, tagLen, 2);

/** AEGIS-128X2 in-place decryption - detached mode (degree=2). */
export const aegis128X2DecryptDetachedInPlace = (
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis128XDecryptDetachedInPlace(data, tag, ad, key, nonce, 2);

/** AEGIS-128X4 in-place encryption - detached mode (degree=4). */
export const aegis128X4EncryptDetachedInPlace = (
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XEncryptDetachedInPlace(data, ad, key, nonce, tagLen, 4);

/** AEGIS-128X4 in-place decryption - detached mode (degree=4). */
export const aegis128X4DecryptDetachedInPlace = (
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis128XDecryptDetachedInPlace(data, tag, ad, key, nonce, 4);

/** Nonce size for AEGIS-128X in bytes. */
export const AEGIS_128X_NONCE_SIZE = 16;

/** Key size for AEGIS-128X in bytes. */
export const AEGIS_128X_KEY_SIZE = 16;

/**
 * Encrypts a message using AEGIS-128X.
 * Returns a single buffer containing nonce || ciphertext || tag.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (optional, generates random nonce if not provided)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Concatenated nonce || ciphertext || tag
 */
export function aegis128XEncrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array {
	const actualNonce = nonce ?? randomBytes(AEGIS_128X_NONCE_SIZE);
	const { ciphertext, tag } = aegis128XEncryptDetached(
		msg,
		ad,
		key,
		actualNonce,
		tagLen,
		degree,
	);

	const result = new Uint8Array(
		AEGIS_128X_NONCE_SIZE + ciphertext.length + tagLen,
	);
	result.set(actualNonce, 0);
	result.set(ciphertext, AEGIS_128X_NONCE_SIZE);
	result.set(tag, AEGIS_128X_NONCE_SIZE + ciphertext.length);

	return result;
}

/**
 * Decrypts a message using AEGIS-128X.
 * Expects input as nonce || ciphertext || tag.
 * @param sealed - Concatenated nonce || ciphertext || tag
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128XDecrypt(
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array | null {
	const nonceSize = AEGIS_128X_NONCE_SIZE;
	if (sealed.length < nonceSize + tagLen) {
		return null;
	}
	const nonce = sealed.subarray(0, nonceSize);
	const ct = sealed.subarray(nonceSize, sealed.length - tagLen);
	const tag = sealed.subarray(sealed.length - tagLen);
	return aegis128XDecryptDetached(ct, tag, ad, key, nonce, degree);
}

/** AEGIS-128X2 encryption - detached mode (degree=2). */
export const aegis128X2EncryptDetached = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XEncryptDetached(msg, ad, key, nonce, tagLen, 2);

/** AEGIS-128X2 decryption - detached mode (degree=2). */
export const aegis128X2DecryptDetached = (
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis128XDecryptDetached(ct, tag, ad, key, nonce, 2);

/** AEGIS-128X4 encryption - detached mode (degree=4). */
export const aegis128X4EncryptDetached = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XEncryptDetached(msg, ad, key, nonce, tagLen, 4);

/** AEGIS-128X4 decryption - detached mode (degree=4). */
export const aegis128X4DecryptDetached = (
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis128XDecryptDetached(ct, tag, ad, key, nonce, 4);

/** AEGIS-128X2 encryption (degree=2). */
export const aegis128X2Encrypt = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis128XEncrypt(msg, ad, key, nonce, tagLen, 2);

/** AEGIS-128X2 decryption (degree=2). */
export const aegis128X2Decrypt = (
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XDecrypt(sealed, ad, key, tagLen, 2);

/** AEGIS-128X4 encryption (degree=4). */
export const aegis128X4Encrypt = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis128XEncrypt(msg, ad, key, nonce, tagLen, 4);

/** AEGIS-128X4 decryption (degree=4). */
export const aegis128X4Decrypt = (
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XDecrypt(sealed, ad, key, tagLen, 4);

/**
 * Computes a MAC (Message Authentication Code) using AEGIS-128X.
 * @param data - Data to authenticate
 * @param key - 16-byte key
 * @param nonce - 16-byte nonce (optional, uses zero nonce if null)
 * @param tagLen - Tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Authentication tag
 */
export function aegis128XMac(
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array {
	const state = new Aegis128XState(degree);
	const rateBytes = 32 * degree;

	state.init(key, nonce ?? new Uint8Array(16));

	const dataPadded = zeroPad(data, rateBytes);
	for (let i = 0; i + rateBytes <= dataPadded.length; i += rateBytes) {
		state.absorb(dataPadded, i);
	}

	return state.finalizeMac(data.length, tagLen);
}

/**
 * Verifies a MAC computed using AEGIS-128X.
 * @param data - Data to verify
 * @param tag - Expected authentication tag (16 or 32 bytes)
 * @param key - 16-byte key
 * @param nonce - 16-byte nonce (optional, uses zero nonce if null)
 * @param degree - Parallelism degree (default: 2)
 * @returns True if the tag is valid, false otherwise
 */
export function aegis128XMacVerify(
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	degree: number = 2,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const expectedTag = aegis128XMac(data, key, nonce, tagLen, degree);
	return constantTimeEqual(tag, expectedTag);
}

/** AEGIS-128X2 MAC computation (degree=2). */
export const aegis128X2Mac = (
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis128XMac(data, key, nonce, tagLen, 2);

/** AEGIS-128X2 MAC verification (degree=2). */
export const aegis128X2MacVerify = (
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
) => aegis128XMacVerify(data, tag, key, nonce, 2);

/** AEGIS-128X4 MAC computation (degree=4). */
export const aegis128X4Mac = (
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis128XMac(data, key, nonce, tagLen, 4);

/** AEGIS-128X4 MAC verification (degree=4). */
export const aegis128X4MacVerify = (
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
) => aegis128XMacVerify(data, tag, key, nonce, 4);

/**
 * Generates a random 16-byte key for AEGIS-128X.
 * @returns 16-byte encryption key
 * @throws Error if no cryptographic random source is available
 */
export function aegis128XCreateKey(): Uint8Array {
	return randomBytes(AEGIS_128X_KEY_SIZE);
}

/**
 * Generates a random 16-byte nonce for AEGIS-128X.
 * @returns 16-byte nonce
 * @throws Error if no cryptographic random source is available
 */
export function aegis128XCreateNonce(): Uint8Array {
	return randomBytes(AEGIS_128X_NONCE_SIZE);
}

/** AEGIS-128X2 key generation (degree=2). */
export const aegis128X2CreateKey = aegis128XCreateKey;

/** AEGIS-128X2 nonce generation (degree=2). */
export const aegis128X2CreateNonce = aegis128XCreateNonce;

/** AEGIS-128X4 key generation (degree=4). */
export const aegis128X4CreateKey = aegis128XCreateKey;

/** AEGIS-128X4 nonce generation (degree=4). */
export const aegis128X4CreateNonce = aegis128XCreateNonce;
