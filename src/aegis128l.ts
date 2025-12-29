import {
	aesRoundTo,
	andBlocksTo,
	C0,
	C1,
	constantTimeEqual,
	le64To,
	xorBlocksTo,
	zeroPad,
} from "./aes.js";
import { randomBytes } from "./random.js";

/**
 * AEGIS-128L cipher state.
 * Uses 8 AES blocks (128 bytes) of internal state and processes 32-byte blocks.
 */
export class Aegis128LState {
	private s0: Uint8Array;
	private s1: Uint8Array;
	private s2: Uint8Array;
	private s3: Uint8Array;
	private s4: Uint8Array;
	private s5: Uint8Array;
	private s6: Uint8Array;
	private s7: Uint8Array;
	private tmp0: Uint8Array;
	private tmp1: Uint8Array;
	private z0: Uint8Array;
	private z1: Uint8Array;
	private newS: Uint8Array[];
	private tBuf: Uint8Array;

	constructor() {
		this.s0 = new Uint8Array(16);
		this.s1 = new Uint8Array(16);
		this.s2 = new Uint8Array(16);
		this.s3 = new Uint8Array(16);
		this.s4 = new Uint8Array(16);
		this.s5 = new Uint8Array(16);
		this.s6 = new Uint8Array(16);
		this.s7 = new Uint8Array(16);
		this.tmp0 = new Uint8Array(16);
		this.tmp1 = new Uint8Array(16);
		this.z0 = new Uint8Array(16);
		this.z1 = new Uint8Array(16);
		this.newS = Array.from({ length: 8 }, () => new Uint8Array(16));
		this.tBuf = new Uint8Array(16);
	}

	get s(): Uint8Array[] {
		return [
			this.s0,
			this.s1,
			this.s2,
			this.s3,
			this.s4,
			this.s5,
			this.s6,
			this.s7,
		];
	}

	set s(states: Uint8Array[]) {
		this.s0.set(states[0]!);
		this.s1.set(states[1]!);
		this.s2.set(states[2]!);
		this.s3.set(states[3]!);
		this.s4.set(states[4]!);
		this.s5.set(states[5]!);
		this.s6.set(states[6]!);
		this.s7.set(states[7]!);
	}

	/**
	 * Initializes the state with a key and nonce.
	 * @param key - 16-byte encryption key
	 * @param nonce - 16-byte nonce (must be unique per message)
	 */
	init(key: Uint8Array, nonce: Uint8Array): void {
		xorBlocksTo(key, nonce, this.s0);
		this.s1.set(C1);
		this.s2.set(C0);
		this.s3.set(C1);
		xorBlocksTo(key, nonce, this.s4);
		xorBlocksTo(key, C0, this.s5);
		xorBlocksTo(key, C1, this.s6);
		xorBlocksTo(key, C0, this.s7);

		for (let i = 0; i < 10; i++) {
			this.update(nonce, key);
		}
	}

	/**
	 * Updates the state with two 16-byte message blocks.
	 * @param m0 - First 16-byte message block
	 * @param m1 - Second 16-byte message block
	 */
	update(m0: ArrayLike<number>, m1: ArrayLike<number>): void {
		const newS = this.newS;

		xorBlocksTo(this.s0, m0, this.tmp0);
		aesRoundTo(this.s7, this.tmp0, newS[0]!);
		aesRoundTo(this.s0, this.s1, newS[1]!);
		aesRoundTo(this.s1, this.s2, newS[2]!);
		aesRoundTo(this.s2, this.s3, newS[3]!);
		xorBlocksTo(this.s4, m1, this.tmp1);
		aesRoundTo(this.s3, this.tmp1, newS[4]!);
		aesRoundTo(this.s4, this.s5, newS[5]!);
		aesRoundTo(this.s5, this.s6, newS[6]!);
		aesRoundTo(this.s6, this.s7, newS[7]!);

		this.s0.set(newS[0]!);
		this.s1.set(newS[1]!);
		this.s2.set(newS[2]!);
		this.s3.set(newS[3]!);
		this.s4.set(newS[4]!);
		this.s5.set(newS[5]!);
		this.s6.set(newS[6]!);
		this.s7.set(newS[7]!);
	}

	/**
	 * Absorbs a 32-byte associated data block into the state.
	 * @param ai - 32-byte associated data block
	 */
	absorb(ai: Uint8Array): void {
		this.update(ai.subarray(0, 16), ai.subarray(16, 32));
	}

	/**
	 * Encrypts a 32-byte plaintext block and writes to output buffer.
	 * @param xi - 32-byte plaintext block
	 * @param out - 32-byte output buffer
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		const z0 = this.z0;
		const z1 = this.z1;
		const tmp = this.tmp0;

		xorBlocksTo(this.s1, this.s6, z0);
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z0[i] ^= tmp[i]!;

		xorBlocksTo(this.s2, this.s5, z1);
		andBlocksTo(this.s6, this.s7, tmp);
		for (let i = 0; i < 16; i++) z1[i] ^= tmp[i]!;

		const t0 = xi.subarray(0, 16);
		const t1 = xi.subarray(16, 32);

		for (let i = 0; i < 16; i++) out[i] = t0[i]! ^ z0[i]!;
		for (let i = 0; i < 16; i++) out[16 + i] = t1[i]! ^ z1[i]!;

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
		const z0 = this.z0;
		const z1 = this.z1;
		const tmp = this.tmp0;

		xorBlocksTo(this.s1, this.s6, z0);
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z0[i] ^= tmp[i]!;

		xorBlocksTo(this.s2, this.s5, z1);
		andBlocksTo(this.s6, this.s7, tmp);
		for (let i = 0; i < 16; i++) z1[i] ^= tmp[i]!;

		const t0 = ci.subarray(0, 16);
		const t1 = ci.subarray(16, 32);

		for (let i = 0; i < 16; i++) out[i] = t0[i]! ^ z0[i]!;
		for (let i = 0; i < 16; i++) out[16 + i] = t1[i]! ^ z1[i]!;

		this.update(out.subarray(0, 16), out.subarray(16, 32));
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
		const z0 = this.z0;
		const z1 = this.z1;
		const tmp = this.tmp0;

		xorBlocksTo(this.s1, this.s6, z0);
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z0[i] ^= tmp[i]!;

		xorBlocksTo(this.s2, this.s5, z1);
		andBlocksTo(this.s6, this.s7, tmp);
		for (let i = 0; i < 16; i++) z1[i] ^= tmp[i]!;

		this.update(block.subarray(0, 16), block.subarray(16, 32));

		for (let i = 0; i < 16; i++) block[i] ^= z0[i]!;
		for (let i = 0; i < 16; i++) block[16 + i] ^= z1[i]!;
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
		const z0 = this.z0;
		const z1 = this.z1;
		const tmp = this.tmp0;

		xorBlocksTo(this.s1, this.s6, z0);
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z0[i] ^= tmp[i]!;

		xorBlocksTo(this.s2, this.s5, z1);
		andBlocksTo(this.s6, this.s7, tmp);
		for (let i = 0; i < 16; i++) z1[i] ^= tmp[i]!;

		const padded = zeroPad(cn, 32);
		const t0 = padded.subarray(0, 16);
		const t1 = padded.subarray(16, 32);

		const out = new Uint8Array(32);
		for (let i = 0; i < 16; i++) out[i] = t0[i]! ^ z0[i]!;
		for (let i = 0; i < 16; i++) out[16 + i] = t1[i]! ^ z1[i]!;

		const xn = new Uint8Array(out.subarray(0, cn.length));

		const v = zeroPad(xn, 32);
		this.update(v.subarray(0, 16), v.subarray(16, 32));

		return xn;
	}

	/**
	 * Finalizes encryption/decryption and produces an authentication tag.
	 * @param adLenBits - Associated data length in bits
	 * @param msgLenBits - Message length in bits
	 * @param tagLen - Tag length (16 or 32 bytes)
	 * @returns Authentication tag
	 */
	finalize(
		adLenBits: bigint,
		msgLenBits: bigint,
		tagLen: 16 | 32 = 16,
	): Uint8Array {
		const t = this.tBuf;
		le64To(adLenBits, t, 0);
		le64To(msgLenBits, t, 8);
		for (let i = 0; i < 16; i++) t[i] ^= this.s2[i]!;

		for (let i = 0; i < 7; i++) {
			this.update(t, t);
		}

		if (tagLen === 16) {
			const tag = new Uint8Array(16);
			for (let i = 0; i < 16; i++) {
				tag[i] =
					this.s0[i]! ^
					this.s1[i]! ^
					this.s2[i]! ^
					this.s3[i]! ^
					this.s4[i]! ^
					this.s5[i]! ^
					this.s6[i]!;
			}
			return tag;
		} else {
			const tag = new Uint8Array(32);
			for (let i = 0; i < 16; i++) {
				tag[i] = this.s0[i]! ^ this.s1[i]! ^ this.s2[i]! ^ this.s3[i]!;
			}
			for (let i = 0; i < 16; i++) {
				tag[16 + i] = this.s4[i]! ^ this.s5[i]! ^ this.s6[i]! ^ this.s7[i]!;
			}
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

	const adPadded = zeroPad(ad, 32);
	for (let i = 0; i + 32 <= adPadded.length; i += 32) {
		state.absorb(adPadded.subarray(i, i + 32));
	}

	const msgPadded = zeroPad(msg, 32);
	const ct = new Uint8Array(msgPadded.length);
	for (let i = 0; i + 32 <= msgPadded.length; i += 32) {
		state.encTo(msgPadded.subarray(i, i + 32), ct.subarray(i, i + 32));
	}

	const tag = state.finalize(
		BigInt(ad.length * 8),
		BigInt(msg.length * 8),
		tagLen,
	);
	const ciphertext = new Uint8Array(ct.subarray(0, msg.length));

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

	const adPadded = zeroPad(ad, 32);
	for (let i = 0; i + 32 <= adPadded.length; i += 32) {
		state.absorb(adPadded.subarray(i, i + 32));
	}

	const fullBlocksLen = Math.floor(ct.length / 32) * 32;
	const cn = ct.subarray(fullBlocksLen);

	const msg = new Uint8Array(fullBlocksLen + (cn.length > 0 ? cn.length : 0));
	for (let i = 0; i + 32 <= ct.length; i += 32) {
		state.decTo(ct.subarray(i, i + 32), msg.subarray(i, i + 32));
	}

	if (cn.length > 0) {
		msg.set(state.decPartial(cn), fullBlocksLen);
	}

	const expectedTag = state.finalize(
		BigInt(ad.length * 8),
		BigInt(msg.length * 8),
		tagLen,
	);

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

	const adPadded = zeroPad(ad, 32);
	for (let i = 0; i + 32 <= adPadded.length; i += 32) {
		state.absorb(adPadded.subarray(i, i + 32));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / 32) * 32;

	for (let i = 0; i < fullBlocksLen; i += 32) {
		state.encInPlace(data.subarray(i, i + 32));
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const lastBlock = zeroPad(lastPartial, 32);
		const encBlock = state.enc(lastBlock);
		lastPartial.set(encBlock.subarray(0, lastPartial.length));
	}

	return state.finalize(BigInt(ad.length * 8), BigInt(msgLen * 8), tagLen);
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

	const adPadded = zeroPad(ad, 32);
	for (let i = 0; i + 32 <= adPadded.length; i += 32) {
		state.absorb(adPadded.subarray(i, i + 32));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / 32) * 32;

	for (let i = 0; i < fullBlocksLen; i += 32) {
		state.decInPlace(data.subarray(i, i + 32));
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const decrypted = state.decPartial(lastPartial);
		lastPartial.set(decrypted);
	}

	const expectedTag = state.finalize(
		BigInt(ad.length * 8),
		BigInt(msgLen * 8),
		tagLen,
	);

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
	const state = new Aegis128LState();
	state.init(key, actualNonce);

	const adPadded = zeroPad(ad, 32);
	for (let i = 0; i + 32 <= adPadded.length; i += 32) {
		state.absorb(adPadded.subarray(i, i + 32));
	}

	const nonceSize = AEGIS_128L_NONCE_SIZE;
	const result = new Uint8Array(nonceSize + msg.length + tagLen);
	result.set(actualNonce, 0);

	const fullBlocks = Math.floor(msg.length / 32) * 32;
	for (let i = 0; i < fullBlocks; i += 32) {
		state.encTo(
			msg.subarray(i, i + 32),
			result.subarray(nonceSize + i, nonceSize + i + 32),
		);
	}

	if (msg.length > fullBlocks) {
		const lastBlock = zeroPad(msg.subarray(fullBlocks), 32);
		const encBlock = state.enc(lastBlock);
		result.set(
			encBlock.subarray(0, msg.length - fullBlocks),
			nonceSize + fullBlocks,
		);
	}

	const tag = state.finalize(
		BigInt(ad.length * 8),
		BigInt(msg.length * 8),
		tagLen,
	);
	result.set(tag, nonceSize + msg.length);

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

	const dataPadded = zeroPad(data, 32);
	for (let i = 0; i + 32 <= dataPadded.length; i += 32) {
		state.absorb(dataPadded.subarray(i, i + 32));
	}

	return state.finalize(BigInt(data.length * 8), BigInt(tagLen * 8), tagLen);
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
