/**
 * AEGIS-256X implementation with configurable parallelism degree.
 * Extends AEGIS-256 with parallel lanes for improved performance on wide
 * SIMD architectures. Each lane is an independent AEGIS-256 state kept in
 * packed bitsliced form, built on the constant-time bitsliced AES core.
 */

import {
	type AesBlock,
	type AesBlocks,
	aegisRound256,
	blockFromBytes,
	blocksPut,
	blockToBytes,
	blockXor,
	createAesBlock,
	createAesBlocks,
	keystream256,
	pack,
	packConstantInput256,
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
 * AEGIS-256X cipher state with configurable parallelism degree.
 */
export class Aegis256XState {
	private d: number;
	private rateBytes: number;
	private lanes: AesBlocks[];
	private ci: AesBlocks;
	private ciZero: AesBlocks;
	private tmp: AesBlock;
	private z: AesBlock;

	/**
	 * Creates a new AEGIS-256X state.
	 * @param degree - Parallelism degree (default: 2). Use 2 for AEGIS-256X2, 4 for AEGIS-256X4.
	 */
	constructor(degree: number = 2) {
		this.d = degree;
		this.rateBytes = 16 * degree;
		this.lanes = Array.from({ length: degree }, () => createAesBlocks());
		this.ci = createAesBlocks();
		this.ciZero = createAesBlocks();
		this.tmp = createAesBlock();
		this.z = createAesBlock();
	}

	/**
	 * Returns the state blocks as byte arrays indexed [block][lane] (for testing).
	 */
	get v(): Uint8Array[][] {
		const out: Uint8Array[][] = Array.from({ length: 6 }, () => []);
		const unpacked = createAesBlocks();
		const w = createAesBlock();
		for (let i = 0; i < this.d; i++) {
			unpacked.set(this.lanes[i]!);
			unpack(unpacked);
			for (let b = 0; b < 6; b++) {
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
	 * @param key - 32-byte encryption key
	 * @param nonce - 32-byte nonce (must be unique per message)
	 */
	init(key: Uint8Array, nonce: Uint8Array): void {
		const k0 = createAesBlock();
		const k1 = createAesBlock();
		const n0 = createAesBlock();
		const n1 = createAesBlock();
		const k0n0 = createAesBlock();
		const k1n1 = createAesBlock();
		const k0c0 = createAesBlock();
		const k1c1 = createAesBlock();

		blockFromBytes(k0, key);
		blockFromBytes(k1, key, 16);
		blockFromBytes(n0, nonce);
		blockFromBytes(n1, nonce, 16);
		blockXor(k0n0, k0, n0);
		blockXor(k1n1, k1, n1);
		blockXor(k0c0, k0, C0);
		blockXor(k1c1, k1, C1);

		const base = createAesBlocks();
		blocksPut(base, k0n0, 0);
		blocksPut(base, k1n1, 1);
		blocksPut(base, C1, 2);
		blocksPut(base, C0, 3);
		blocksPut(base, k0c0, 4);
		blocksPut(base, k1c1, 5);
		pack(base);

		const ciK0 = createAesBlocks();
		const ciK1 = createAesBlocks();
		const ciK0N0 = createAesBlocks();
		const ciK1N1 = createAesBlocks();
		packConstantInput256(ciK0, k0);
		packConstantInput256(ciK1, k1);
		packConstantInput256(ciK0N0, k0n0);
		packConstantInput256(ciK1N1, k1n1);

		const ctx = createAesBlock();
		const deltas: AesBlocks[] = [];
		for (let i = 0; i < this.d; i++) {
			this.lanes[i]!.set(base);
			const delta = createAesBlocks();
			ctx[0] = i | ((this.d - 1) << 8);
			blocksPut(delta, ctx, 3);
			blocksPut(delta, ctx, 5);
			pack(delta);
			deltas.push(delta);
		}

		const inputs = [ciK0, ciK1, ciK0N0, ciK1N1];
		for (let round = 0; round < 4; round++) {
			for (const input of inputs) {
				for (let i = 0; i < this.d; i++) {
					const st = this.lanes[i]!;
					const delta = deltas[i]!;
					for (let w = 0; w < 32; w++) st[w] = st[w]! ^ delta[w]!;
					aegisRound256(st, input);
				}
			}
		}
	}

	/**
	 * Absorbs an associated data block into the state.
	 * @param ai - Buffer holding the 16*degree-byte associated data block
	 * @param off - Offset of the block within the buffer
	 */
	absorb(ai: Uint8Array, off = 0): void {
		for (let i = 0; i < this.d; i++) {
			blockFromBytes(this.tmp, ai, off + i * 16);
			packConstantInput256(this.ci, this.tmp);
			aegisRound256(this.lanes[i]!, this.ci);
		}
	}

	/**
	 * Encrypts a plaintext block and writes to output buffer.
	 * @param xi - Buffer holding the 16*degree-byte plaintext block
	 * @param out - Output buffer receiving the ciphertext block
	 * @param inOff - Offset of the plaintext block within xi
	 * @param outOff - Offset of the ciphertext block within out
	 */
	encTo(xi: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const t = this.tmp;

		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;
			keystream256(st, this.z);

			blockFromBytes(t, xi, inOff + i * 16);
			packConstantInput256(this.ci, t);
			aegisRound256(st, this.ci);

			blockXor(t, t, this.z);
			blockToBytes(out, t, outOff + i * 16);
		}
	}

	/**
	 * Encrypts a plaintext block.
	 * @param xi - Plaintext block (16*degree bytes)
	 * @returns Ciphertext block of the same size
	 */
	enc(xi: Uint8Array): Uint8Array {
		const out = new Uint8Array(this.rateBytes);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a ciphertext block and writes to output buffer.
	 * @param ci - Buffer holding the 16*degree-byte ciphertext block
	 * @param out - Output buffer receiving the plaintext block
	 * @param inOff - Offset of the ciphertext block within ci
	 * @param outOff - Offset of the plaintext block within out
	 */
	decTo(ci: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const msg = this.tmp;

		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;

			blockFromBytes(msg, ci, inOff + i * 16);
			keystream256(st, this.z);
			blockXor(msg, msg, this.z);

			packConstantInput256(this.ci, msg);
			aegisRound256(st, this.ci);

			blockToBytes(out, msg, outOff + i * 16);
		}
	}

	/**
	 * Decrypts a ciphertext block.
	 * @param ci - Ciphertext block (16*degree bytes)
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
	 * @param cn - Partial ciphertext block (smaller than 16*degree bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		const padded = zeroPad(cn, this.rateBytes);
		const ks = new Uint8Array(this.rateBytes);

		for (let i = 0; i < this.d; i++) {
			keystream256(this.lanes[i]!, this.z);
			blockToBytes(ks, this.z, i * 16);
		}

		const out = new Uint8Array(this.rateBytes);
		for (let j = 0; j < this.rateBytes; j++) out[j] = padded[j]! ^ ks[j]!;

		const xn = new Uint8Array(out.subarray(0, cn.length));

		out.fill(0, cn.length);
		for (let i = 0; i < this.d; i++) {
			blockFromBytes(this.tmp, out, i * 16);
			packConstantInput256(this.ci, this.tmp);
			aegisRound256(this.lanes[i]!, this.ci);
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
		const u = createAesBlock();
		const t = this.tmp;

		u[0] = (adLen * 8) & 0xffffffff;
		u[1] = Math.floor((adLen * 8) / 0x100000000);
		u[2] = (msgLen * 8) & 0xffffffff;
		u[3] = Math.floor((msgLen * 8) / 0x100000000);

		const unpacked = createAesBlocks();
		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;
			unpacked.set(st);
			unpack(unpacked);
			for (let j = 0; j < 4; j++) t[j] = u[j]! ^ unpacked[wordIdx(3, j)]!;
			packConstantInput256(this.ci, t);
			for (let round = 0; round < 7; round++) {
				aegisRound256(st, this.ci);
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
						st[wordIdx(5, j)]!;
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
						st[wordIdx(2, j)]!;
					tagBlock1[j] =
						tagBlock1[j]! ^
						st[wordIdx(3, j)]! ^
						st[wordIdx(4, j)]! ^
						st[wordIdx(5, j)]!;
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
		const u = createAesBlock();
		const t = this.tmp;

		u[0] = (dataLen * 8) & 0xffffffff;
		u[1] = Math.floor((dataLen * 8) / 0x100000000);
		u[2] = tagLen * 8;
		u[3] = 0;

		const unpacked = createAesBlocks();
		for (let i = 0; i < this.d; i++) {
			const st = this.lanes[i]!;
			unpacked.set(st);
			unpack(unpacked);
			for (let j = 0; j < 4; j++) t[j] = u[j]! ^ unpacked[wordIdx(3, j)]!;
			packConstantInput256(this.ci, t);
			for (let round = 0; round < 7; round++) {
				aegisRound256(st, this.ci);
			}
		}

		if (this.d > 1) {
			let tags: Uint8Array;
			if (tagLen === 16) {
				tags = new Uint8Array(16 * (this.d - 1));
				const tb = createAesBlock();
				for (let i = 1; i < this.d; i++) {
					unpacked.set(this.lanes[i]!);
					unpack(unpacked);
					for (let j = 0; j < 4; j++) {
						tb[j] =
							unpacked[wordIdx(0, j)]! ^
							unpacked[wordIdx(1, j)]! ^
							unpacked[wordIdx(2, j)]! ^
							unpacked[wordIdx(3, j)]! ^
							unpacked[wordIdx(4, j)]! ^
							unpacked[wordIdx(5, j)]!;
					}
					blockToBytes(tags, tb, (i - 1) * 16);
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
							unpacked[wordIdx(2, j)]!;
						tb1[j] =
							unpacked[wordIdx(3, j)]! ^
							unpacked[wordIdx(4, j)]! ^
							unpacked[wordIdx(5, j)]!;
					}
					blockToBytes(tags, tb0, (i - 1) * 32);
					blockToBytes(tags, tb1, (i - 1) * 32 + 16);
				}
			}

			for (let off = 0; off + 16 <= tags.length; off += 16) {
				blockFromBytes(this.tmp, tags, off);
				packConstantInput256(this.ci, this.tmp);
				aegisRound256(this.lanes[0]!, this.ci);
				for (let i = 1; i < this.d; i++) {
					aegisRound256(this.lanes[i]!, this.ciZero);
				}
			}

			unpacked.set(this.lanes[0]!);
			unpack(unpacked);
			t[0] = this.d ^ unpacked[wordIdx(3, 0)]!;
			t[1] = unpacked[wordIdx(3, 1)]!;
			t[2] = (tagLen * 8) ^ unpacked[wordIdx(3, 2)]!;
			t[3] = unpacked[wordIdx(3, 3)]!;
			packConstantInput256(this.ci, t);
			for (let round = 0; round < 7; round++) {
				aegisRound256(this.lanes[0]!, this.ci);
				for (let i = 1; i < this.d; i++) {
					aegisRound256(this.lanes[i]!, this.ciZero);
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
					st[wordIdx(5, j)]!;
			}
			blockToBytes(tag, tagBlock);
			return tag;
		} else {
			const tag = new Uint8Array(32);
			const tagBlock0 = createAesBlock();
			const tagBlock1 = createAesBlock();
			for (let j = 0; j < 4; j++) {
				tagBlock0[j] =
					st[wordIdx(0, j)]! ^ st[wordIdx(1, j)]! ^ st[wordIdx(2, j)]!;
				tagBlock1[j] =
					st[wordIdx(3, j)]! ^ st[wordIdx(4, j)]! ^ st[wordIdx(5, j)]!;
			}
			blockToBytes(tag, tagBlock0);
			blockToBytes(tag, tagBlock1, 16);
			return tag;
		}
	}
}

/**
 * Encrypts a message using AEGIS-256X (detached mode).
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Object containing ciphertext and authentication tag separately
 */
export function aegis256XEncryptDetached(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis256XState(degree);
	const rateBytes = 16 * degree;

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
 * Decrypts a message using AEGIS-256X (detached mode).
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must match what was used during encryption)
 * @param degree - Parallelism degree (default: 2)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis256XDecryptDetached(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	degree: number = 2,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis256XState(degree);
	const rateBytes = 16 * degree;

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
 * Encrypts a message in-place using AEGIS-256X (detached mode).
 * The input buffer is modified to contain the ciphertext.
 * @param data - Buffer containing plaintext (will be overwritten with ciphertext)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Authentication tag
 */
export function aegis256XEncryptDetachedInPlace(
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array {
	const state = new Aegis256XState(degree);
	const rateBytes = 16 * degree;

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
 * Decrypts a message in-place using AEGIS-256X (detached mode).
 * The input buffer is modified to contain the plaintext (or zeroed on failure).
 * @param data - Buffer containing ciphertext (will be overwritten with plaintext)
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must match what was used during encryption)
 * @param degree - Parallelism degree (default: 2)
 * @returns True if authentication succeeds, false otherwise
 */
export function aegis256XDecryptDetachedInPlace(
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	degree: number = 2,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis256XState(degree);
	const rateBytes = 16 * degree;

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

/** AEGIS-256X2 in-place encryption - detached mode (degree=2). */
export const aegis256X2EncryptDetachedInPlace = (
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis256XEncryptDetachedInPlace(data, ad, key, nonce, tagLen, 2);

/** AEGIS-256X2 in-place decryption - detached mode (degree=2). */
export const aegis256X2DecryptDetachedInPlace = (
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis256XDecryptDetachedInPlace(data, tag, ad, key, nonce, 2);

/** AEGIS-256X4 in-place encryption - detached mode (degree=4). */
export const aegis256X4EncryptDetachedInPlace = (
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis256XEncryptDetachedInPlace(data, ad, key, nonce, tagLen, 4);

/** AEGIS-256X4 in-place decryption - detached mode (degree=4). */
export const aegis256X4DecryptDetachedInPlace = (
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis256XDecryptDetachedInPlace(data, tag, ad, key, nonce, 4);

/** Nonce size for AEGIS-256X in bytes. */
export const AEGIS_256X_NONCE_SIZE = 32;

/** Key size for AEGIS-256X in bytes. */
export const AEGIS_256X_KEY_SIZE = 32;

/**
 * Encrypts a message using AEGIS-256X.
 * Returns a single buffer containing nonce || ciphertext || tag.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (optional, generates random nonce if not provided)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Concatenated nonce || ciphertext || tag
 */
export function aegis256XEncrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array {
	const actualNonce = nonce ?? randomBytes(AEGIS_256X_NONCE_SIZE);
	const { ciphertext, tag } = aegis256XEncryptDetached(
		msg,
		ad,
		key,
		actualNonce,
		tagLen,
		degree,
	);

	const result = new Uint8Array(
		AEGIS_256X_NONCE_SIZE + ciphertext.length + tagLen,
	);
	result.set(actualNonce, 0);
	result.set(ciphertext, AEGIS_256X_NONCE_SIZE);
	result.set(tag, AEGIS_256X_NONCE_SIZE + ciphertext.length);

	return result;
}

/**
 * Decrypts a message using AEGIS-256X.
 * Expects input as nonce || ciphertext || tag.
 * @param sealed - Concatenated nonce || ciphertext || tag
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis256XDecrypt(
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array | null {
	const nonceSize = AEGIS_256X_NONCE_SIZE;
	if (sealed.length < nonceSize + tagLen) {
		return null;
	}
	const nonce = sealed.subarray(0, nonceSize);
	const ct = sealed.subarray(nonceSize, sealed.length - tagLen);
	const tag = sealed.subarray(sealed.length - tagLen);
	return aegis256XDecryptDetached(ct, tag, ad, key, nonce, degree);
}

/** AEGIS-256X2 encryption - detached mode (degree=2). */
export const aegis256X2EncryptDetached = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis256XEncryptDetached(msg, ad, key, nonce, tagLen, 2);

/** AEGIS-256X2 decryption - detached mode (degree=2). */
export const aegis256X2DecryptDetached = (
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis256XDecryptDetached(ct, tag, ad, key, nonce, 2);

/** AEGIS-256X4 encryption - detached mode (degree=4). */
export const aegis256X4EncryptDetached = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis256XEncryptDetached(msg, ad, key, nonce, tagLen, 4);

/** AEGIS-256X4 decryption - detached mode (degree=4). */
export const aegis256X4DecryptDetached = (
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis256XDecryptDetached(ct, tag, ad, key, nonce, 4);

/** AEGIS-256X2 encryption (degree=2). */
export const aegis256X2Encrypt = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis256XEncrypt(msg, ad, key, nonce, tagLen, 2);

/** AEGIS-256X2 decryption (degree=2). */
export const aegis256X2Decrypt = (
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis256XDecrypt(sealed, ad, key, tagLen, 2);

/** AEGIS-256X4 encryption (degree=4). */
export const aegis256X4Encrypt = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis256XEncrypt(msg, ad, key, nonce, tagLen, 4);

/** AEGIS-256X4 decryption (degree=4). */
export const aegis256X4Decrypt = (
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis256XDecrypt(sealed, ad, key, tagLen, 4);

/**
 * Computes a MAC (Message Authentication Code) using AEGIS-256X.
 * @param data - Data to authenticate
 * @param key - 32-byte key
 * @param nonce - 32-byte nonce (optional, uses zero nonce if null)
 * @param tagLen - Tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Authentication tag
 */
export function aegis256XMac(
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): Uint8Array {
	const state = new Aegis256XState(degree);
	const rateBytes = 16 * degree;

	state.init(key, nonce ?? new Uint8Array(32));

	const dataPadded = zeroPad(data, rateBytes);
	for (let i = 0; i + rateBytes <= dataPadded.length; i += rateBytes) {
		state.absorb(dataPadded, i);
	}

	return state.finalizeMac(data.length, tagLen);
}

/**
 * Verifies a MAC computed using AEGIS-256X.
 * @param data - Data to verify
 * @param tag - Expected authentication tag (16 or 32 bytes)
 * @param key - 32-byte key
 * @param nonce - 32-byte nonce (optional, uses zero nonce if null)
 * @param degree - Parallelism degree (default: 2)
 * @returns True if the tag is valid, false otherwise
 */
export function aegis256XMacVerify(
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	degree: number = 2,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const expectedTag = aegis256XMac(data, key, nonce, tagLen, degree);
	return constantTimeEqual(tag, expectedTag);
}

/** AEGIS-256X2 MAC computation (degree=2). */
export const aegis256X2Mac = (
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis256XMac(data, key, nonce, tagLen, 2);

/** AEGIS-256X2 MAC verification (degree=2). */
export const aegis256X2MacVerify = (
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
) => aegis256XMacVerify(data, tag, key, nonce, 2);

/** AEGIS-256X4 MAC computation (degree=4). */
export const aegis256X4Mac = (
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
) => aegis256XMac(data, key, nonce, tagLen, 4);

/** AEGIS-256X4 MAC verification (degree=4). */
export const aegis256X4MacVerify = (
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
) => aegis256XMacVerify(data, tag, key, nonce, 4);

/**
 * Generates a random 32-byte key for AEGIS-256X.
 * @returns 32-byte encryption key
 * @throws Error if no cryptographic random source is available
 */
export function aegis256XCreateKey(): Uint8Array {
	return randomBytes(AEGIS_256X_KEY_SIZE);
}

/**
 * Generates a random 32-byte nonce for AEGIS-256X.
 * @returns 32-byte nonce
 * @throws Error if no cryptographic random source is available
 */
export function aegis256XCreateNonce(): Uint8Array {
	return randomBytes(AEGIS_256X_NONCE_SIZE);
}

/** AEGIS-256X2 key generation (degree=2). */
export const aegis256X2CreateKey = aegis256XCreateKey;

/** AEGIS-256X2 nonce generation (degree=2). */
export const aegis256X2CreateNonce = aegis256XCreateNonce;

/** AEGIS-256X4 key generation (degree=4). */
export const aegis256X4CreateKey = aegis256XCreateKey;

/** AEGIS-256X4 nonce generation (degree=4). */
export const aegis256X4CreateNonce = aegis256XCreateNonce;
