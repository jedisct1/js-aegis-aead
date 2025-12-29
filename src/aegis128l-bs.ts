/**
 * Bitsliced AEGIS-128L implementation.
 * Provides constant-time operation by processing all 8 state blocks simultaneously.
 */

import { constantTimeEqual, zeroPad } from "./aes.js";
import {
	type AesBlock,
	type AesBlocks,
	aesRound,
	blockFromBytes,
	blocksPut,
	blocksRotr,
	blocksXor,
	blockToBytes,
	blockXor,
	createAesBlock,
	createAesBlocks,
	pack,
	pack04,
	unpack,
	wordIdx,
} from "./aes-bs.js";
import { randomBytes } from "./random.js";

const RATE = 32;

const C0: AesBlock = new Uint32Array([
	0x02010100, 0x0d080503, 0x59372215, 0x6279e990,
]);
const C1: AesBlock = new Uint32Array([
	0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573,
]);

/**
 * Bitsliced AEGIS-128L cipher state.
 * Uses 8 AES blocks (128 bytes) stored in bitsliced form (32 uint32 words).
 */
export class Aegis128LBsState {
	private st: AesBlocks;
	private st1: AesBlocks;
	private tmp0: AesBlock;
	private tmp1: AesBlock;
	private z0: AesBlock;
	private z1: AesBlock;

	constructor() {
		this.st = createAesBlocks();
		this.st1 = createAesBlocks();
		this.tmp0 = createAesBlock();
		this.tmp1 = createAesBlock();
		this.z0 = createAesBlock();
		this.z1 = createAesBlock();
	}

	/**
	 * AEGIS round function: applies AES round to all blocks and rotates.
	 * st[i] = AES(st[i]) ^ st[(i-1) mod 8]
	 */
	private aegisRound(): void {
		const st = this.st;
		const st1 = this.st1;

		st1.set(st);
		pack(st1);
		aesRound(st1);
		unpack(st1);

		for (let i = 0; i < 8; i++) {
			const prev = (i + 7) % 8;
			st[wordIdx(i, 0)] = (st[wordIdx(i, 0)]! ^ st1[wordIdx(prev, 0)]!) >>> 0;
			st[wordIdx(i, 1)] = (st[wordIdx(i, 1)]! ^ st1[wordIdx(prev, 1)]!) >>> 0;
			st[wordIdx(i, 2)] = (st[wordIdx(i, 2)]! ^ st1[wordIdx(prev, 2)]!) >>> 0;
			st[wordIdx(i, 3)] = (st[wordIdx(i, 3)]! ^ st1[wordIdx(prev, 3)]!) >>> 0;
		}
	}

	/**
	 * AEGIS round function with constant input (used in packed mode).
	 */
	private aegisRoundPacked(constantInput: AesBlocks): void {
		const st = this.st;
		const st1 = this.st1;

		st1.set(st);
		aesRound(st1);
		blocksRotr(st1);
		blocksXor(st, st1);
		blocksXor(st, constantInput);
	}

	/**
	 * Pack constant input for blocks 0 and 4.
	 */
	private packConstantInput(out: AesBlocks, m0: AesBlock, m1: AesBlock): void {
		out.fill(0);
		blocksPut(out, m0, 0);
		blocksPut(out, m1, 4);
		pack04(out);
	}

	/**
	 * Absorb rate: XOR message blocks into state positions 0 and 4.
	 */
	private absorbRate(m0: AesBlock, m1: AesBlock): void {
		const st = this.st;
		st[wordIdx(0, 0)] = (st[wordIdx(0, 0)]! ^ m0[0]!) >>> 0;
		st[wordIdx(0, 1)] = (st[wordIdx(0, 1)]! ^ m0[1]!) >>> 0;
		st[wordIdx(0, 2)] = (st[wordIdx(0, 2)]! ^ m0[2]!) >>> 0;
		st[wordIdx(0, 3)] = (st[wordIdx(0, 3)]! ^ m0[3]!) >>> 0;

		st[wordIdx(4, 0)] = (st[wordIdx(4, 0)]! ^ m1[0]!) >>> 0;
		st[wordIdx(4, 1)] = (st[wordIdx(4, 1)]! ^ m1[1]!) >>> 0;
		st[wordIdx(4, 2)] = (st[wordIdx(4, 2)]! ^ m1[2]!) >>> 0;
		st[wordIdx(4, 3)] = (st[wordIdx(4, 3)]! ^ m1[3]!) >>> 0;
	}

	/**
	 * Update state with two message blocks.
	 */
	private update(m0: AesBlock, m1: AesBlock): void {
		this.aegisRound();
		this.absorbRate(m0, m1);
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

		const constantInput = createAesBlocks();
		this.packConstantInput(constantInput, n, k);
		pack(this.st);
		for (let i = 0; i < 10; i++) {
			this.aegisRoundPacked(constantInput);
		}
		unpack(this.st);
	}

	/**
	 * Absorbs a 32-byte associated data block into the state.
	 * @param ai - 32-byte associated data block
	 */
	absorb(ai: Uint8Array): void {
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;
		blockFromBytes(msg0, ai.subarray(0, 16));
		blockFromBytes(msg1, ai.subarray(16, 32));
		this.update(msg0, msg1);
	}

	/**
	 * Encrypts a 32-byte plaintext block and writes to output buffer.
	 * @param xi - 32-byte plaintext block
	 * @param out - 32-byte output buffer
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		const st = this.st;
		const z0 = this.z0;
		const z1 = this.z1;
		const t0 = this.tmp0;
		const t1 = this.tmp1;

		for (let i = 0; i < 4; i++) {
			z0[i] =
				(st[wordIdx(6, i)]! ^
					st[wordIdx(1, i)]! ^
					(st[wordIdx(2, i)]! & st[wordIdx(3, i)]!)) >>>
				0;
		}
		for (let i = 0; i < 4; i++) {
			z1[i] =
				(st[wordIdx(2, i)]! ^
					st[wordIdx(5, i)]! ^
					(st[wordIdx(6, i)]! & st[wordIdx(7, i)]!)) >>>
				0;
		}

		blockFromBytes(t0, xi.subarray(0, 16));
		blockFromBytes(t1, xi.subarray(16, 32));

		const out0 = createAesBlock();
		const out1 = createAesBlock();
		blockXor(out0, t0, z0);
		blockXor(out1, t1, z1);

		blockToBytes(out.subarray(0, 16), out0);
		blockToBytes(out.subarray(16, 32), out1);

		this.update(t0, t1);
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
	 * @param ci - 32-byte ciphertext block
	 * @param out - 32-byte output buffer
	 */
	decTo(ci: Uint8Array, out: Uint8Array): void {
		const st = this.st;
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;

		blockFromBytes(msg0, ci.subarray(0, 16));
		blockFromBytes(msg1, ci.subarray(16, 32));

		for (let i = 0; i < 4; i++) {
			msg0[i] =
				(msg0[i]! ^
					st[wordIdx(6, i)]! ^
					st[wordIdx(1, i)]! ^
					(st[wordIdx(2, i)]! & st[wordIdx(3, i)]!)) >>>
				0;
		}
		for (let i = 0; i < 4; i++) {
			msg1[i] =
				(msg1[i]! ^
					st[wordIdx(2, i)]! ^
					st[wordIdx(5, i)]! ^
					(st[wordIdx(6, i)]! & st[wordIdx(7, i)]!)) >>>
				0;
		}

		this.update(msg0, msg1);

		blockToBytes(out.subarray(0, 16), msg0);
		blockToBytes(out.subarray(16, 32), msg1);
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

	/**
	 * Encrypts a 32-byte plaintext block in-place.
	 * @param block - 32-byte buffer (plaintext in, ciphertext out)
	 */
	encInPlace(block: Uint8Array): void {
		this.encTo(block, block);
	}

	/**
	 * Decrypts a 32-byte ciphertext block in-place.
	 * @param block - 32-byte buffer (ciphertext in, plaintext out)
	 */
	decInPlace(block: Uint8Array): void {
		this.decTo(block, block);
	}

	/**
	 * Decrypts a partial (final) ciphertext block smaller than 32 bytes.
	 * @param cn - Partial ciphertext block (1-31 bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		const st = this.st;
		const msg0 = this.tmp0;
		const msg1 = this.tmp1;

		const padded = zeroPad(cn, RATE);
		blockFromBytes(msg0, padded.subarray(0, 16));
		blockFromBytes(msg1, padded.subarray(16, 32));

		for (let i = 0; i < 4; i++) {
			msg0[i] =
				(msg0[i]! ^
					st[wordIdx(6, i)]! ^
					st[wordIdx(1, i)]! ^
					(st[wordIdx(2, i)]! & st[wordIdx(3, i)]!)) >>>
				0;
		}
		for (let i = 0; i < 4; i++) {
			msg1[i] =
				(msg1[i]! ^
					st[wordIdx(2, i)]! ^
					st[wordIdx(5, i)]! ^
					(st[wordIdx(6, i)]! & st[wordIdx(7, i)]!)) >>>
				0;
		}

		const pad = new Uint8Array(RATE);
		blockToBytes(pad.subarray(0, 16), msg0);
		blockToBytes(pad.subarray(16, 32), msg1);

		const xn = new Uint8Array(pad.subarray(0, cn.length));

		pad.fill(0, cn.length);
		blockFromBytes(msg0, pad.subarray(0, 16));
		blockFromBytes(msg1, pad.subarray(16, 32));

		this.aegisRound();
		this.absorbRate(msg0, msg1);

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

		tmp[0] = ((adLen * 8) & 0xffffffff) >>> 0;
		tmp[1] = Math.floor((adLen * 8) / 0x100000000) >>> 0;
		tmp[2] = ((msgLen * 8) & 0xffffffff) >>> 0;
		tmp[3] = Math.floor((msgLen * 8) / 0x100000000) >>> 0;

		tmp[0] = (tmp[0]! ^ st[wordIdx(2, 0)]!) >>> 0;
		tmp[1] = (tmp[1]! ^ st[wordIdx(2, 1)]!) >>> 0;
		tmp[2] = (tmp[2]! ^ st[wordIdx(2, 2)]!) >>> 0;
		tmp[3] = (tmp[3]! ^ st[wordIdx(2, 3)]!) >>> 0;

		const constantInput = createAesBlocks();
		this.packConstantInput(constantInput, tmp, tmp);
		pack(this.st);
		for (let i = 0; i < 7; i++) {
			this.aegisRoundPacked(constantInput);
		}
		unpack(this.st);

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
						st[wordIdx(5, i)]! ^
						st[wordIdx(6, i)]!) >>>
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
					(st[wordIdx(0, i)]! ^
						st[wordIdx(1, i)]! ^
						st[wordIdx(2, i)]! ^
						st[wordIdx(3, i)]!) >>>
					0;
			}
			for (let i = 0; i < 4; i++) {
				tagBlock1[i] =
					(st[wordIdx(4, i)]! ^
						st[wordIdx(5, i)]! ^
						st[wordIdx(6, i)]! ^
						st[wordIdx(7, i)]!) >>>
					0;
			}
			blockToBytes(tag.subarray(0, 16), tagBlock0);
			blockToBytes(tag.subarray(16, 32), tagBlock1);
			return tag;
		}
	}
}

/**
 * Encrypts a message using bitsliced AEGIS-128L (detached mode).
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Object containing ciphertext and authentication tag separately
 */
export function aegis128LBsEncryptDetached(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis128LBsState();
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
 * Decrypts a message using bitsliced AEGIS-128L (detached mode).
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128LBsDecryptDetached(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128LBsState();
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
 * Encrypts a message in-place using bitsliced AEGIS-128L (detached mode).
 * The input buffer is modified to contain the ciphertext.
 * @param data - Buffer containing plaintext (will be overwritten with ciphertext)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis128LBsEncryptDetachedInPlace(
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis128LBsState();
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
 * Decrypts a message in-place using bitsliced AEGIS-128L (detached mode).
 * The input buffer is modified to contain the plaintext (or zeroed on failure).
 * @param data - Buffer containing ciphertext (will be overwritten with plaintext)
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @returns True if authentication succeeds, false otherwise
 */
export function aegis128LBsDecryptDetachedInPlace(
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128LBsState();
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

export const AEGIS_128L_BS_NONCE_SIZE = 16;
export const AEGIS_128L_BS_KEY_SIZE = 16;

/**
 * Encrypts a message using bitsliced AEGIS-128L.
 * Returns a single buffer containing nonce || ciphertext || tag.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (optional, generates random nonce if not provided)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Concatenated nonce || ciphertext || tag
 */
export function aegis128LBsEncrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const actualNonce = nonce ?? randomBytes(AEGIS_128L_BS_NONCE_SIZE);
	const { ciphertext, tag } = aegis128LBsEncryptDetached(
		msg,
		ad,
		key,
		actualNonce,
		tagLen,
	);

	const result = new Uint8Array(
		AEGIS_128L_BS_NONCE_SIZE + ciphertext.length + tagLen,
	);
	result.set(actualNonce, 0);
	result.set(ciphertext, AEGIS_128L_BS_NONCE_SIZE);
	result.set(tag, AEGIS_128L_BS_NONCE_SIZE + ciphertext.length);

	return result;
}

/**
 * Decrypts a message using bitsliced AEGIS-128L.
 * Expects input as nonce || ciphertext || tag.
 * @param sealed - Concatenated nonce || ciphertext || tag
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128LBsDecrypt(
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array | null {
	const nonceSize = AEGIS_128L_BS_NONCE_SIZE;
	if (sealed.length < nonceSize + tagLen) {
		return null;
	}
	const nonce = sealed.subarray(0, nonceSize);
	const ct = sealed.subarray(nonceSize, sealed.length - tagLen);
	const tag = sealed.subarray(sealed.length - tagLen);
	return aegis128LBsDecryptDetached(ct, tag, ad, key, nonce);
}

/**
 * Computes a MAC (Message Authentication Code) using bitsliced AEGIS-128L.
 * @param data - Data to authenticate
 * @param key - 16-byte key
 * @param nonce - 16-byte nonce (optional, uses zero nonce if null)
 * @param tagLen - Tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis128LBsMac(
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis128LBsState();
	state.init(key, nonce ?? new Uint8Array(16));

	const dataPadded = zeroPad(data, RATE);
	for (let i = 0; i + RATE <= dataPadded.length; i += RATE) {
		state.absorb(dataPadded.subarray(i, i + RATE));
	}

	return state.finalize(data.length, tagLen, tagLen);
}

/**
 * Verifies a MAC computed using bitsliced AEGIS-128L.
 * @param data - Data to verify
 * @param tag - Expected authentication tag (16 or 32 bytes)
 * @param key - 16-byte key
 * @param nonce - 16-byte nonce (optional, uses zero nonce if null)
 * @returns True if the tag is valid, false otherwise
 */
export function aegis128LBsMacVerify(
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const expectedTag = aegis128LBsMac(data, key, nonce, tagLen);
	return constantTimeEqual(tag, expectedTag);
}

/**
 * Generates a random 16-byte key for bitsliced AEGIS-128L.
 * @returns 16-byte encryption key
 */
export function aegis128LBsCreateKey(): Uint8Array {
	return randomBytes(AEGIS_128L_BS_KEY_SIZE);
}

/**
 * Generates a random 16-byte nonce for bitsliced AEGIS-128L.
 * @returns 16-byte nonce
 */
export function aegis128LBsCreateNonce(): Uint8Array {
	return randomBytes(AEGIS_128L_BS_NONCE_SIZE);
}
