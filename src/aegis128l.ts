/**
 * AEGIS-128L implementation.
 * Built on the constant-time bitsliced AES core, which processes all 8 state
 * blocks simultaneously without lookup tables.
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

const RATE = 32;

const C0: AesBlock = new Uint32Array([
	0x02010100, 0x0d080503, 0x59372215, 0x6279e990,
]);
const C1: AesBlock = new Uint32Array([
	0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573,
]);

/**
 * AEGIS-128L cipher state.
 * The state is kept in packed bitsliced form between operations so that
 * pack/unpack does not need to be applied at every round.
 */
export class Aegis128LState {
	private st: AesBlocks;
	private constantInput: AesBlocks;
	private tmp0: AesBlock;
	private tmp1: AesBlock;
	private z0: AesBlock;
	private z1: AesBlock;

	constructor() {
		this.st = createAesBlocks();
		this.constantInput = createAesBlocks();
		this.tmp0 = createAesBlock();
		this.tmp1 = createAesBlock();
		this.z0 = createAesBlock();
		this.z1 = createAesBlock();
	}

	/**
	 * Returns the 8 state blocks as byte arrays (for testing).
	 */
	get s(): Uint8Array[] {
		const unpacked = createAesBlocks();
		unpacked.set(this.st);
		unpack(unpacked);
		const blocks: Uint8Array[] = [];
		const w = createAesBlock();
		for (let i = 0; i < 8; i++) {
			for (let j = 0; j < 4; j++) w[j] = unpacked[wordIdx(i, j)]!;
			const bytes = new Uint8Array(16);
			blockToBytes(bytes, w);
			blocks.push(bytes);
		}
		return blocks;
	}

	/**
	 * Sets the 8 state blocks from byte arrays (for testing).
	 */
	set s(blocks: Uint8Array[]) {
		this.st.fill(0);
		const w = createAesBlock();
		for (let i = 0; i < 8; i++) {
			blockFromBytes(w, blocks[i]!);
			blocksPut(this.st, w, i);
		}
		pack(this.st);
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

		blocksPut(this.st, kn, 0);
		blocksPut(this.st, C1, 1);
		blocksPut(this.st, C0, 2);
		blocksPut(this.st, C1, 3);
		blocksPut(this.st, kn, 4);
		blocksPut(this.st, kc0, 5);
		blocksPut(this.st, kc1, 6);
		blocksPut(this.st, kc0, 7);

		packConstantInput128(this.constantInput, n, k);
		pack(this.st);
		for (let i = 0; i < 10; i++) {
			aegisRound128(this.st, this.constantInput);
		}
	}

	/**
	 * Updates the state with two 16-byte message blocks.
	 * @param m0 - First 16-byte message block
	 * @param m1 - Second 16-byte message block
	 */
	update(m0: Uint8Array, m1: Uint8Array): void {
		blockFromBytes(this.tmp0, m0);
		blockFromBytes(this.tmp1, m1);
		packConstantInput128(this.constantInput, this.tmp0, this.tmp1);
		aegisRound128(this.st, this.constantInput);
	}

	/**
	 * Absorbs a 32-byte associated data block into the state.
	 * @param ai - Buffer holding the 32-byte associated data block
	 * @param off - Offset of the block within the buffer
	 */
	absorb(ai: Uint8Array, off = 0): void {
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;
		blockFromBytes(msg0, ai, off);
		blockFromBytes(msg1, ai, off + 16);
		packConstantInput128(this.constantInput, msg0, msg1);
		aegisRound128(this.st, this.constantInput);
	}

	/**
	 * Encrypts a 32-byte plaintext block and writes to output buffer.
	 * @param xi - Buffer holding the 32-byte plaintext block
	 * @param out - Output buffer receiving the 32-byte ciphertext block
	 * @param inOff - Offset of the plaintext block within xi
	 * @param outOff - Offset of the ciphertext block within out
	 */
	encTo(xi: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const t0 = this.tmp0;
		const t1 = this.tmp1;

		keystream128(this.st, this.z0, this.z1);

		blockFromBytes(t0, xi, inOff);
		blockFromBytes(t1, xi, inOff + 16);

		packConstantInput128(this.constantInput, t0, t1);
		aegisRound128(this.st, this.constantInput);

		blockXor(t0, t0, this.z0);
		blockXor(t1, t1, this.z1);

		blockToBytes(out, t0, outOff);
		blockToBytes(out, t1, outOff + 16);
	}

	/**
	 * Encrypts a 32-byte plaintext block.
	 * @param xi - 32-byte plaintext block
	 * @returns 32-byte ciphertext block
	 */
	enc(xi: Uint8Array): Uint8Array {
		const out = new Uint8Array(32);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a 32-byte ciphertext block and writes to output buffer.
	 * @param ci - Buffer holding the 32-byte ciphertext block
	 * @param out - Output buffer receiving the 32-byte plaintext block
	 * @param inOff - Offset of the ciphertext block within ci
	 * @param outOff - Offset of the plaintext block within out
	 */
	decTo(ci: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;

		blockFromBytes(msg0, ci, inOff);
		blockFromBytes(msg1, ci, inOff + 16);

		keystream128(this.st, this.z0, this.z1);
		blockXor(msg0, msg0, this.z0);
		blockXor(msg1, msg1, this.z1);

		packConstantInput128(this.constantInput, msg0, msg1);
		aegisRound128(this.st, this.constantInput);

		blockToBytes(out, msg0, outOff);
		blockToBytes(out, msg1, outOff + 16);
	}

	/**
	 * Decrypts a 32-byte ciphertext block.
	 * @param ci - 32-byte ciphertext block
	 * @returns 32-byte plaintext block
	 */
	dec(ci: Uint8Array): Uint8Array {
		const out = new Uint8Array(32);
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
	 * Decrypts a partial (final) ciphertext block smaller than 32 bytes.
	 * @param cn - Partial ciphertext block (1-31 bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;

		const padded = zeroPad(cn, RATE);
		blockFromBytes(msg0, padded);
		blockFromBytes(msg1, padded, 16);

		keystream128(this.st, this.z0, this.z1);
		blockXor(msg0, msg0, this.z0);
		blockXor(msg1, msg1, this.z1);

		const pad = new Uint8Array(RATE);
		blockToBytes(pad, msg0);
		blockToBytes(pad, msg1, 16);

		const xn = new Uint8Array(pad.subarray(0, cn.length));

		pad.fill(0, cn.length);
		blockFromBytes(msg0, pad);
		blockFromBytes(msg1, pad, 16);

		packConstantInput128(this.constantInput, msg0, msg1);
		aegisRound128(this.st, this.constantInput);

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
		const tmp = this.tmp0;

		tmp[0] = (adLen * 8) & 0xffffffff;
		tmp[1] = Math.floor((adLen * 8) / 0x100000000);
		tmp[2] = (msgLen * 8) & 0xffffffff;
		tmp[3] = Math.floor((msgLen * 8) / 0x100000000);

		const unpacked = createAesBlocks();
		unpacked.set(st);
		unpack(unpacked);

		tmp[0] = tmp[0]! ^ unpacked[wordIdx(2, 0)]!;
		tmp[1] = tmp[1]! ^ unpacked[wordIdx(2, 1)]!;
		tmp[2] = tmp[2]! ^ unpacked[wordIdx(2, 2)]!;
		tmp[3] = tmp[3]! ^ unpacked[wordIdx(2, 3)]!;

		packConstantInput128(this.constantInput, tmp, tmp);
		for (let i = 0; i < 7; i++) {
			aegisRound128(st, this.constantInput);
		}
		unpack(st);

		if (tagLen === 16) {
			const tag = new Uint8Array(16);
			const tagBlock = createAesBlock();
			for (let i = 0; i < 4; i++) {
				tagBlock[i] =
					st[wordIdx(0, i)]! ^
					st[wordIdx(1, i)]! ^
					st[wordIdx(2, i)]! ^
					st[wordIdx(3, i)]! ^
					st[wordIdx(4, i)]! ^
					st[wordIdx(5, i)]! ^
					st[wordIdx(6, i)]!;
			}
			blockToBytes(tag, tagBlock);
			return tag;
		} else {
			const tag = new Uint8Array(32);
			const tagBlock0 = createAesBlock();
			const tagBlock1 = createAesBlock();
			for (let i = 0; i < 4; i++) {
				tagBlock0[i] =
					st[wordIdx(0, i)]! ^
					st[wordIdx(1, i)]! ^
					st[wordIdx(2, i)]! ^
					st[wordIdx(3, i)]!;
			}
			for (let i = 0; i < 4; i++) {
				tagBlock1[i] =
					st[wordIdx(4, i)]! ^
					st[wordIdx(5, i)]! ^
					st[wordIdx(6, i)]! ^
					st[wordIdx(7, i)]!;
			}
			blockToBytes(tag, tagBlock0);
			blockToBytes(tag, tagBlock1, 16);
			return tag;
		}
	}
}

/**
 * Encrypts a message using AEGIS-128L (detached mode).
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Object containing ciphertext and authentication tag separately
 */
export function aegis128LEncryptDetached(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis128LState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded, i);
	}

	const ciphertext = new Uint8Array(msg.length);
	const fullBlocks = Math.floor(msg.length / RATE) * RATE;

	for (let i = 0; i < fullBlocks; i += RATE) {
		state.encTo(msg, ciphertext, i, i);
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
 * Decrypts a message using AEGIS-128L (detached mode).
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128LDecryptDetached(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128LState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded, i);
	}

	const msg = new Uint8Array(ct.length);
	const fullBlocks = Math.floor(ct.length / RATE) * RATE;

	for (let i = 0; i < fullBlocks; i += RATE) {
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
 * Encrypts a message in-place using AEGIS-128L (detached mode).
 * The input buffer is modified to contain the ciphertext.
 * @param data - Buffer containing plaintext (will be overwritten with ciphertext)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis128LEncryptDetachedInPlace(
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis128LState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded, i);
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / RATE) * RATE;

	for (let i = 0; i < fullBlocksLen; i += RATE) {
		state.encTo(data, data, i, i);
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
 * Decrypts a message in-place using AEGIS-128L (detached mode).
 * The input buffer is modified to contain the plaintext (or zeroed on failure).
 * @param data - Buffer containing ciphertext (will be overwritten with plaintext)
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @returns True if authentication succeeds, false otherwise
 */
export function aegis128LDecryptDetachedInPlace(
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128LState();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, RATE);
	for (let i = 0; i + RATE <= adPadded.length; i += RATE) {
		state.absorb(adPadded, i);
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / RATE) * RATE;

	for (let i = 0; i < fullBlocksLen; i += RATE) {
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

/** Nonce size for AEGIS-128L in bytes. */
export const AEGIS_128L_NONCE_SIZE = 16;

/** Key size for AEGIS-128L in bytes. */
export const AEGIS_128L_KEY_SIZE = 16;

/**
 * Encrypts a message using AEGIS-128L.
 * Returns a single buffer containing nonce || ciphertext || tag.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (optional, generates random nonce if not provided)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Concatenated nonce || ciphertext || tag
 */
export function aegis128LEncrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const actualNonce = nonce ?? randomBytes(AEGIS_128L_NONCE_SIZE);
	const { ciphertext, tag } = aegis128LEncryptDetached(
		msg,
		ad,
		key,
		actualNonce,
		tagLen,
	);

	const result = new Uint8Array(
		AEGIS_128L_NONCE_SIZE + ciphertext.length + tagLen,
	);
	result.set(actualNonce, 0);
	result.set(ciphertext, AEGIS_128L_NONCE_SIZE);
	result.set(tag, AEGIS_128L_NONCE_SIZE + ciphertext.length);

	return result;
}

/**
 * Decrypts a message using AEGIS-128L.
 * Expects input as nonce || ciphertext || tag.
 * @param sealed - Concatenated nonce || ciphertext || tag
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128LDecrypt(
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array | null {
	const nonceSize = AEGIS_128L_NONCE_SIZE;
	if (sealed.length < nonceSize + tagLen) {
		return null;
	}
	const nonce = sealed.subarray(0, nonceSize);
	const ct = sealed.subarray(nonceSize, sealed.length - tagLen);
	const tag = sealed.subarray(sealed.length - tagLen);
	return aegis128LDecryptDetached(ct, tag, ad, key, nonce);
}

/**
 * Computes a MAC (Message Authentication Code) using AEGIS-128L.
 * @param data - Data to authenticate
 * @param key - 16-byte key
 * @param nonce - 16-byte nonce (optional, uses zero nonce if null)
 * @param tagLen - Tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis128LMac(
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis128LState();
	state.init(key, nonce ?? new Uint8Array(16));

	const dataPadded = zeroPad(data, RATE);
	for (let i = 0; i + RATE <= dataPadded.length; i += RATE) {
		state.absorb(dataPadded, i);
	}

	return state.finalize(data.length, tagLen, tagLen);
}

/**
 * Verifies a MAC computed using AEGIS-128L.
 * @param data - Data to verify
 * @param tag - Expected authentication tag (16 or 32 bytes)
 * @param key - 16-byte key
 * @param nonce - 16-byte nonce (optional, uses zero nonce if null)
 * @returns True if the tag is valid, false otherwise
 */
export function aegis128LMacVerify(
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const expectedTag = aegis128LMac(data, key, nonce, tagLen);
	return constantTimeEqual(tag, expectedTag);
}

/**
 * Generates a random 16-byte key for AEGIS-128L.
 * @returns 16-byte encryption key
 * @throws Error if no cryptographic random source is available
 */
export function aegis128LCreateKey(): Uint8Array {
	return randomBytes(AEGIS_128L_KEY_SIZE);
}

/**
 * Generates a random 16-byte nonce for AEGIS-128L.
 * @returns 16-byte nonce
 * @throws Error if no cryptographic random source is available
 */
export function aegis128LCreateNonce(): Uint8Array {
	return randomBytes(AEGIS_128L_NONCE_SIZE);
}
