/**
 * Bitsliced AEGIS-256 implementation.
 * Provides constant-time operation by processing state blocks simultaneously.
 */

import { constantTimeEqual, zeroPad } from "./aes.js";
import {
	type AesBlock,
	type AesBlocks,
	aesRound,
	blockFromBytes,
	blocksPut,
	blockToBytes,
	blockXor,
	createAesBlock,
	createAesBlocks,
	pack,
	unpack,
	wordIdx,
} from "./aes-bs.js";
import { randomBytes } from "./random.js";

const RATE = 16;

const C0: AesBlock = new Uint32Array([
	0x02010100, 0x0d080503, 0x59372215, 0x6279e990,
]);
const C1: AesBlock = new Uint32Array([
	0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573,
]);

/**
 * Bitsliced AEGIS-256 cipher state.
 * Uses 6 AES blocks (96 bytes) stored in bitsliced form.
 */
export class Aegis256BsState {
	private st: AesBlocks;
	private st1: AesBlocks;
	private tmp: AesBlock;

	constructor() {
		this.st = createAesBlocks();
		this.st1 = createAesBlocks();
		this.tmp = createAesBlock();
	}

	/**
	 * AEGIS round function: applies AES round to all blocks and rotates.
	 * st[i] = AES(st[i]) ^ st[(i+5) mod 6]
	 */
	private aegisRound(): void {
		const st = this.st;
		const st1 = this.st1;

		st1.set(st);
		pack(st1);
		aesRound(st1);
		unpack(st1);

		for (let i = 0; i < 6; i++) {
			const prev = (i + 5) % 6;
			st[wordIdx(i, 0)] = (st[wordIdx(i, 0)]! ^ st1[wordIdx(prev, 0)]!) >>> 0;
			st[wordIdx(i, 1)] = (st[wordIdx(i, 1)]! ^ st1[wordIdx(prev, 1)]!) >>> 0;
			st[wordIdx(i, 2)] = (st[wordIdx(i, 2)]! ^ st1[wordIdx(prev, 2)]!) >>> 0;
			st[wordIdx(i, 3)] = (st[wordIdx(i, 3)]! ^ st1[wordIdx(prev, 3)]!) >>> 0;
		}
	}

	/**
	 * Absorb rate: XOR message block into state position 0.
	 */
	private absorbRate(m: AesBlock): void {
		const st = this.st;
		st[wordIdx(0, 0)] = (st[wordIdx(0, 0)]! ^ m[0]!) >>> 0;
		st[wordIdx(0, 1)] = (st[wordIdx(0, 1)]! ^ m[1]!) >>> 0;
		st[wordIdx(0, 2)] = (st[wordIdx(0, 2)]! ^ m[2]!) >>> 0;
		st[wordIdx(0, 3)] = (st[wordIdx(0, 3)]! ^ m[3]!) >>> 0;
	}

	/**
	 * Update state with a message block.
	 */
	private update(m: AesBlock): void {
		this.aegisRound();
		this.absorbRate(m);
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

		blockFromBytes(k0, key.subarray(0, 16));
		blockFromBytes(k1, key.subarray(16, 32));
		blockFromBytes(n0, nonce.subarray(0, 16));
		blockFromBytes(n1, nonce.subarray(16, 32));
		blockXor(k0n0, k0, n0);
		blockXor(k1n1, k1, n1);
		blockXor(k0c0, k0, C0);
		blockXor(k1c1, k1, C1);

		this.st.fill(0);
		blocksPut(this.st, k0n0, 0);
		blocksPut(this.st, k1n1, 1);
		blocksPut(this.st, C1, 2);
		blocksPut(this.st, C0, 3);
		blocksPut(this.st, k0c0, 4);
		blocksPut(this.st, k1c1, 5);

		for (let i = 0; i < 4; i++) {
			this.update(k0);
			this.update(k1);
			this.update(k0n0);
			this.update(k1n1);
		}
	}

	/**
	 * Absorbs a 16-byte associated data block into the state.
	 * @param ai - 16-byte associated data block
	 */
	absorb(ai: Uint8Array): void {
		const msg = this.tmp;
		blockFromBytes(msg, ai);
		this.update(msg);
	}

	/**
	 * Encrypts a 16-byte plaintext block and writes to output buffer.
	 * @param xi - 16-byte plaintext block
	 * @param out - 16-byte output buffer
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		const st = this.st;
		const z = this.tmp;
		const t = createAesBlock();

		for (let i = 0; i < 4; i++) {
			z[i] =
				(st[wordIdx(1, i)]! ^
					st[wordIdx(4, i)]! ^
					st[wordIdx(5, i)]! ^
					(st[wordIdx(2, i)]! & st[wordIdx(3, i)]!)) >>>
				0;
		}

		blockFromBytes(t, xi);

		const outBlock = createAesBlock();
		blockXor(outBlock, t, z);
		blockToBytes(out, outBlock);

		this.update(t);
	}

	/**
	 * Encrypts a 16-byte plaintext block.
	 * @param xi - 16-byte plaintext block
	 * @returns 16-byte ciphertext block
	 */
	enc(xi: Uint8Array): Uint8Array {
		const out = new Uint8Array(16);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a 16-byte ciphertext block and writes to output buffer.
	 * @param ci - 16-byte ciphertext block
	 * @param out - 16-byte output buffer
	 */
	decTo(ci: Uint8Array, out: Uint8Array): void {
		const st = this.st;
		const msg = this.tmp;

		blockFromBytes(msg, ci);

		for (let i = 0; i < 4; i++) {
			msg[i] =
				(msg[i]! ^
					st[wordIdx(1, i)]! ^
					st[wordIdx(4, i)]! ^
					st[wordIdx(5, i)]! ^
					(st[wordIdx(2, i)]! & st[wordIdx(3, i)]!)) >>>
				0;
		}

		this.update(msg);
		blockToBytes(out, msg);
	}

	/**
	 * Decrypts a 16-byte ciphertext block.
	 * @param ci - 16-byte ciphertext block
	 * @returns 16-byte plaintext block
	 */
	dec(ci: Uint8Array): Uint8Array {
		const out = new Uint8Array(16);
		this.decTo(ci, out);
		return out;
	}

	/**
	 * Encrypts a 16-byte plaintext block in-place.
	 * @param block - 16-byte buffer (plaintext in, ciphertext out)
	 */
	encInPlace(block: Uint8Array): void {
		this.encTo(block, block);
	}

	/**
	 * Decrypts a 16-byte ciphertext block in-place.
	 * @param block - 16-byte buffer (ciphertext in, plaintext out)
	 */
	decInPlace(block: Uint8Array): void {
		this.decTo(block, block);
	}

	/**
	 * Decrypts a partial (final) ciphertext block smaller than 16 bytes.
	 * @param cn - Partial ciphertext block (1-15 bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		const st = this.st;
		const msg = this.tmp;

		const padded = zeroPad(cn, RATE);
		blockFromBytes(msg, padded);

		for (let i = 0; i < 4; i++) {
			msg[i] =
				(msg[i]! ^
					st[wordIdx(1, i)]! ^
					st[wordIdx(4, i)]! ^
					st[wordIdx(5, i)]! ^
					(st[wordIdx(2, i)]! & st[wordIdx(3, i)]!)) >>>
				0;
		}

		const pad = new Uint8Array(RATE);
		blockToBytes(pad, msg);

		const xn = new Uint8Array(pad.subarray(0, cn.length));

		pad.fill(0, cn.length);
		blockFromBytes(msg, pad);

		this.aegisRound();
		this.absorbRate(msg);

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
		const st = this.st;
		const tmp = this.tmp;

		tmp[0] = ((adLen * 8) & 0xffffffff) >>> 0;
		tmp[1] = Math.floor((adLen * 8) / 0x100000000) >>> 0;
		tmp[2] = ((msgLen * 8) & 0xffffffff) >>> 0;
		tmp[3] = Math.floor((msgLen * 8) / 0x100000000) >>> 0;

		tmp[0] = (tmp[0]! ^ st[wordIdx(3, 0)]!) >>> 0;
		tmp[1] = (tmp[1]! ^ st[wordIdx(3, 1)]!) >>> 0;
		tmp[2] = (tmp[2]! ^ st[wordIdx(3, 2)]!) >>> 0;
		tmp[3] = (tmp[3]! ^ st[wordIdx(3, 3)]!) >>> 0;

		for (let i = 0; i < 7; i++) {
			this.update(tmp);
		}

		if (tagLen === 16) {
			const tag = new Uint8Array(16);
			const tagBlock = createAesBlock();
			for (let i = 0; i < 4; i++) {
				tagBlock[i] =
					(st[wordIdx(0, i)]! ^
						st[wordIdx(1, i)]! ^
						st[wordIdx(2, i)]! ^
						st[wordIdx(3, i)]! ^
						st[wordIdx(4, i)]! ^
						st[wordIdx(5, i)]!) >>>
					0;
			}
			blockToBytes(tag, tagBlock);
			return tag;
		} else {
			const tag = new Uint8Array(32);
			const tagBlock0 = createAesBlock();
			const tagBlock1 = createAesBlock();
			for (let i = 0; i < 4; i++) {
				tagBlock0[i] =
					(st[wordIdx(0, i)]! ^ st[wordIdx(1, i)]! ^ st[wordIdx(2, i)]!) >>> 0;
			}
			for (let i = 0; i < 4; i++) {
				tagBlock1[i] =
					(st[wordIdx(3, i)]! ^ st[wordIdx(4, i)]! ^ st[wordIdx(5, i)]!) >>> 0;
			}
			blockToBytes(tag.subarray(0, 16), tagBlock0);
			blockToBytes(tag.subarray(16, 32), tagBlock1);
			return tag;
		}
	}
}

/**
 * Encrypts a message using bitsliced AEGIS-256 (detached mode).
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Object containing ciphertext and authentication tag separately
 */
export function aegis256BsEncryptDetached(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis256BsState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded.subarray(i, i + RATE));
	}

	const ciphertext = new Uint8Array(msg.length);
	const fullBlocks = Math.floor(msg.length / RATE) * RATE;

	for (let i = 0; i < fullBlocks; i += RATE) {
		state.encTo(msg.subarray(i, i + RATE), ciphertext.subarray(i, i + RATE));
	}

	if (msg.length > fullBlocks) {
		const lastBlock = zeroPad(msg.subarray(fullBlocks), RATE);
		const encBlock = state.enc(lastBlock);
		ciphertext.set(encBlock.subarray(0, msg.length - fullBlocks), fullBlocks);
	}

	const tag = state.finalize(ad.length, msg.length, tagLen);

	return { ciphertext, tag };
}

/**
 * Decrypts a message using bitsliced AEGIS-256 (detached mode).
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must match what was used during encryption)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis256BsDecryptDetached(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis256BsState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded.subarray(i, i + RATE));
	}

	const msg = new Uint8Array(ct.length);
	const fullBlocks = Math.floor(ct.length / RATE) * RATE;

	for (let i = 0; i < fullBlocks; i += RATE) {
		state.decTo(ct.subarray(i, i + RATE), msg.subarray(i, i + RATE));
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
 * Encrypts a message in-place using bitsliced AEGIS-256 (detached mode).
 * The input buffer is modified to contain the ciphertext.
 * @param data - Buffer containing plaintext (will be overwritten with ciphertext)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis256BsEncryptDetachedInPlace(
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis256BsState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded.subarray(i, i + RATE));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / RATE) * RATE;

	for (let i = 0; i < fullBlocksLen; i += RATE) {
		state.encInPlace(data.subarray(i, i + RATE));
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const lastBlock = zeroPad(lastPartial, RATE);
		const encBlock = state.enc(lastBlock);
		lastPartial.set(encBlock.subarray(0, lastPartial.length));
	}

	return state.finalize(ad.length, msgLen, tagLen);
}

/**
 * Decrypts a message in-place using bitsliced AEGIS-256 (detached mode).
 * The input buffer is modified to contain the plaintext (or zeroed on failure).
 * @param data - Buffer containing ciphertext (will be overwritten with plaintext)
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must match what was used during encryption)
 * @returns True if authentication succeeds, false otherwise
 */
export function aegis256BsDecryptDetachedInPlace(
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis256BsState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded.subarray(i, i + RATE));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / RATE) * RATE;

	for (let i = 0; i < fullBlocksLen; i += RATE) {
		state.decInPlace(data.subarray(i, i + RATE));
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

export const AEGIS_256_BS_NONCE_SIZE = 32;
export const AEGIS_256_BS_KEY_SIZE = 32;

/**
 * Encrypts a message using bitsliced AEGIS-256.
 * Returns a single buffer containing nonce || ciphertext || tag.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (optional, generates random nonce if not provided)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Concatenated nonce || ciphertext || tag
 */
export function aegis256BsEncrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const actualNonce = nonce ?? randomBytes(AEGIS_256_BS_NONCE_SIZE);
	const { ciphertext, tag } = aegis256BsEncryptDetached(
		msg,
		ad,
		key,
		actualNonce,
		tagLen,
	);

	const result = new Uint8Array(
		AEGIS_256_BS_NONCE_SIZE + ciphertext.length + tagLen,
	);
	result.set(actualNonce, 0);
	result.set(ciphertext, AEGIS_256_BS_NONCE_SIZE);
	result.set(tag, AEGIS_256_BS_NONCE_SIZE + ciphertext.length);

	return result;
}

/**
 * Decrypts a message using bitsliced AEGIS-256.
 * Expects input as nonce || ciphertext || tag.
 * @param sealed - Concatenated nonce || ciphertext || tag
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis256BsDecrypt(
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array | null {
	const nonceSize = AEGIS_256_BS_NONCE_SIZE;
	if (sealed.length < nonceSize + tagLen) {
		return null;
	}
	const nonce = sealed.subarray(0, nonceSize);
	const ct = sealed.subarray(nonceSize, sealed.length - tagLen);
	const tag = sealed.subarray(sealed.length - tagLen);
	return aegis256BsDecryptDetached(ct, tag, ad, key, nonce);
}

/**
 * Computes a MAC (Message Authentication Code) using bitsliced AEGIS-256.
 * @param data - Data to authenticate
 * @param key - 32-byte key
 * @param nonce - 32-byte nonce (optional, uses zero nonce if null)
 * @param tagLen - Tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis256BsMac(
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis256BsState();
	state.init(key, nonce ?? new Uint8Array(32));

	const dataPadded = zeroPad(data, RATE);
	for (let i = 0; i + RATE <= dataPadded.length; i += RATE) {
		state.absorb(dataPadded.subarray(i, i + RATE));
	}

	return state.finalize(data.length, tagLen, tagLen);
}

/**
 * Verifies a MAC computed using bitsliced AEGIS-256.
 * @param data - Data to verify
 * @param tag - Expected authentication tag (16 or 32 bytes)
 * @param key - 32-byte key
 * @param nonce - 32-byte nonce (optional, uses zero nonce if null)
 * @returns True if the tag is valid, false otherwise
 */
export function aegis256BsMacVerify(
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const expectedTag = aegis256BsMac(data, key, nonce, tagLen);
	return constantTimeEqual(tag, expectedTag);
}

/**
 * Generates a random 32-byte key for bitsliced AEGIS-256.
 * @returns 32-byte encryption key
 */
export function aegis256BsCreateKey(): Uint8Array {
	return randomBytes(AEGIS_256_BS_KEY_SIZE);
}

/**
 * Generates a random 32-byte nonce for bitsliced AEGIS-256.
 * @returns 32-byte nonce
 */
export function aegis256BsCreateNonce(): Uint8Array {
	return randomBytes(AEGIS_256_BS_NONCE_SIZE);
}
