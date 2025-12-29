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
 * AEGIS-256 cipher state.
 * Uses 6 AES blocks (96 bytes) of internal state and processes 16-byte blocks.
 */
export class Aegis256State {
	private s0: Uint8Array;
	private s1: Uint8Array;
	private s2: Uint8Array;
	private s3: Uint8Array;
	private s4: Uint8Array;
	private s5: Uint8Array;
	private tmp: Uint8Array;
	private z: Uint8Array;
	private newS: Uint8Array[];
	private tBuf: Uint8Array;

	constructor() {
		this.s0 = new Uint8Array(16);
		this.s1 = new Uint8Array(16);
		this.s2 = new Uint8Array(16);
		this.s3 = new Uint8Array(16);
		this.s4 = new Uint8Array(16);
		this.s5 = new Uint8Array(16);
		this.tmp = new Uint8Array(16);
		this.z = new Uint8Array(16);
		this.newS = Array.from({ length: 6 }, () => new Uint8Array(16));
		this.tBuf = new Uint8Array(16);
	}

	get s(): Uint8Array[] {
		return [this.s0, this.s1, this.s2, this.s3, this.s4, this.s5];
	}

	set s(states: Uint8Array[]) {
		this.s0.set(states[0]!);
		this.s1.set(states[1]!);
		this.s2.set(states[2]!);
		this.s3.set(states[3]!);
		this.s4.set(states[4]!);
		this.s5.set(states[5]!);
	}

	/**
	 * Initializes the state with a key and nonce.
	 * @param key - 32-byte encryption key
	 * @param nonce - 32-byte nonce (must be unique per message)
	 */
	init(key: Uint8Array, nonce: Uint8Array): void {
		const k0 = key.subarray(0, 16);
		const k1 = key.subarray(16, 32);
		const n0 = nonce.subarray(0, 16);
		const n1 = nonce.subarray(16, 32);

		xorBlocksTo(k0, n0, this.s0);
		xorBlocksTo(k1, n1, this.s1);
		this.s2.set(C1);
		this.s3.set(C0);
		xorBlocksTo(k0, C0, this.s4);
		xorBlocksTo(k1, C1, this.s5);

		const k0Xorn0 = new Uint8Array(16);
		const k1Xorn1 = new Uint8Array(16);
		xorBlocksTo(k0, n0, k0Xorn0);
		xorBlocksTo(k1, n1, k1Xorn1);

		for (let i = 0; i < 4; i++) {
			this.update(k0);
			this.update(k1);
			this.update(k0Xorn0);
			this.update(k1Xorn1);
		}
	}

	/**
	 * Updates the state with a 16-byte message block.
	 * @param m - ArrayLike<number> - 16-byte message block
	 */
	update(m: ArrayLike<number>): void {
		const newS = this.newS;

		xorBlocksTo(this.s0, m, this.tmp);
		aesRoundTo(this.s5, this.tmp, newS[0]!);
		aesRoundTo(this.s0, this.s1, newS[1]!);
		aesRoundTo(this.s1, this.s2, newS[2]!);
		aesRoundTo(this.s2, this.s3, newS[3]!);
		aesRoundTo(this.s3, this.s4, newS[4]!);
		aesRoundTo(this.s4, this.s5, newS[5]!);

		this.s0.set(newS[0]!);
		this.s1.set(newS[1]!);
		this.s2.set(newS[2]!);
		this.s3.set(newS[3]!);
		this.s4.set(newS[4]!);
		this.s5.set(newS[5]!);
	}

	/**
	 * Absorbs a 16-byte associated data block into the state.
	 * @param ai - 16-byte associated data block
	 */
	absorb(ai: Uint8Array): void {
		this.update(ai);
	}

	/**
	 * Encrypts a 16-byte plaintext block and writes to output.
	 * @param xi - 16-byte plaintext block
	 * @param out - 16-byte output buffer
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		const z = this.z;
		const tmp = this.tmp;

		xorBlocksTo(this.s1, this.s4, z);
		for (let i = 0; i < 16; i++) z[i] ^= this.s5[i]!;
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z[i] ^= tmp[i]!;

		this.update(xi);

		for (let i = 0; i < 16; i++) out[i] = xi[i]! ^ z[i]!;
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
	 * Decrypts a 16-byte ciphertext block and writes to output.
	 * @param ci - 16-byte ciphertext block
	 * @param out - 16-byte output buffer
	 */
	decTo(ci: Uint8Array, out: Uint8Array): void {
		const z = this.z;
		const tmp = this.tmp;

		xorBlocksTo(this.s1, this.s4, z);
		for (let i = 0; i < 16; i++) z[i] ^= this.s5[i]!;
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z[i] ^= tmp[i]!;

		for (let i = 0; i < 16; i++) out[i] = ci[i]! ^ z[i]!;
		this.update(out);
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
		const z = this.z;
		const tmp = this.tmp;

		xorBlocksTo(this.s1, this.s4, z);
		for (let i = 0; i < 16; i++) z[i] ^= this.s5[i]!;
		andBlocksTo(this.s2, this.s3, tmp);
		for (let i = 0; i < 16; i++) z[i] ^= tmp[i]!;

		const t = zeroPad(cn, 16);
		const out = new Uint8Array(16);
		for (let i = 0; i < 16; i++) out[i] = t[i]! ^ z[i]!;
		const xn = new Uint8Array(out.subarray(0, cn.length));

		const v = zeroPad(xn, 16);
		this.update(v);

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
		for (let i = 0; i < 16; i++) t[i] ^= this.s3[i]!;

		for (let i = 0; i < 7; i++) {
			this.update(t);
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
					this.s5[i]!;
			}
			return tag;
		} else {
			const tag = new Uint8Array(32);
			for (let i = 0; i < 16; i++) {
				tag[i] = this.s0[i]! ^ this.s1[i]! ^ this.s2[i]!;
			}
			for (let i = 0; i < 16; i++) {
				tag[16 + i] = this.s3[i]! ^ this.s4[i]! ^ this.s5[i]!;
			}
			return tag;
		}
	}
}

/**
 * Encrypts a message using AEGIS-256 (detached mode).
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Object containing ciphertext and authentication tag separately
 */
export function aegis256EncryptDetached(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis256State();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, 16);
	for (let i = 0; i + 16 <= adPadded.length; i += 16) {
		state.absorb(adPadded.subarray(i, i + 16));
	}

	const msgPadded = zeroPad(msg, 16);
	const ct = new Uint8Array(msgPadded.length);
	for (let i = 0; i + 16 <= msgPadded.length; i += 16) {
		state.encTo(msgPadded.subarray(i, i + 16), ct.subarray(i, i + 16));
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
 * Decrypts a message using AEGIS-256 (detached mode).
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must match what was used during encryption)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis256DecryptDetached(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis256State();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, 16);
	for (let i = 0; i + 16 <= adPadded.length; i += 16) {
		state.absorb(adPadded.subarray(i, i + 16));
	}

	const fullBlocksLen = Math.floor(ct.length / 16) * 16;
	const cn = ct.subarray(fullBlocksLen);

	const msg = new Uint8Array(fullBlocksLen + (cn.length > 0 ? cn.length : 0));
	for (let i = 0; i + 16 <= ct.length; i += 16) {
		state.decTo(ct.subarray(i, i + 16), msg.subarray(i, i + 16));
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
 * Encrypts a message in-place using AEGIS-256 (detached mode).
 * The input buffer is modified to contain the ciphertext.
 * @param data - Buffer containing plaintext (will be overwritten with ciphertext)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis256EncryptDetachedInPlace(
	data: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis256State();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, 16);
	for (let i = 0; i + 16 <= adPadded.length; i += 16) {
		state.absorb(adPadded.subarray(i, i + 16));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / 16) * 16;

	for (let i = 0; i < fullBlocksLen; i += 16) {
		state.encInPlace(data.subarray(i, i + 16));
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const lastBlock = zeroPad(lastPartial, 16);
		const encBlock = state.enc(lastBlock);
		lastPartial.set(encBlock.subarray(0, lastPartial.length));
	}

	return state.finalize(BigInt(ad.length * 8), BigInt(msgLen * 8), tagLen);
}

/**
 * Decrypts a message in-place using AEGIS-256 (detached mode).
 * The input buffer is modified to contain the plaintext (or zeroed on failure).
 * @param data - Buffer containing ciphertext (will be overwritten with plaintext)
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (must match what was used during encryption)
 * @returns True if authentication succeeds, false otherwise
 */
export function aegis256DecryptDetachedInPlace(
	data: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis256State();
	state.init(key, nonce);

	const adPadded = zeroPad(ad, 16);
	for (let i = 0; i + 16 <= adPadded.length; i += 16) {
		state.absorb(adPadded.subarray(i, i + 16));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / 16) * 16;

	for (let i = 0; i < fullBlocksLen; i += 16) {
		state.decInPlace(data.subarray(i, i + 16));
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

/** Nonce size for AEGIS-256 in bytes. */
export const AEGIS_256_NONCE_SIZE = 32;

/** Key size for AEGIS-256 in bytes. */
export const AEGIS_256_KEY_SIZE = 32;

/**
 * Encrypts a message using AEGIS-256.
 * Returns a single buffer containing nonce || ciphertext || tag.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 32-byte encryption key
 * @param nonce - 32-byte nonce (optional, generates random nonce if not provided)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Concatenated nonce || ciphertext || tag
 */
export function aegis256Encrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const actualNonce = nonce ?? randomBytes(AEGIS_256_NONCE_SIZE);
	const state = new Aegis256State();
	state.init(key, actualNonce);

	const adPadded = zeroPad(ad, 16);
	for (let i = 0; i + 16 <= adPadded.length; i += 16) {
		state.absorb(adPadded.subarray(i, i + 16));
	}

	const nonceSize = AEGIS_256_NONCE_SIZE;
	const result = new Uint8Array(nonceSize + msg.length + tagLen);
	result.set(actualNonce, 0);

	const fullBlocks = Math.floor(msg.length / 16) * 16;
	for (let i = 0; i < fullBlocks; i += 16) {
		state.encTo(
			msg.subarray(i, i + 16),
			result.subarray(nonceSize + i, nonceSize + i + 16),
		);
	}

	if (msg.length > fullBlocks) {
		const lastBlock = zeroPad(msg.subarray(fullBlocks), 16);
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
 * Decrypts a message using AEGIS-256.
 * Expects input as nonce || ciphertext || tag.
 * @param sealed - Concatenated nonce || ciphertext || tag
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 32-byte encryption key
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis256Decrypt(
	sealed: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	tagLen: 16 | 32 = 16,
): Uint8Array | null {
	const nonceSize = AEGIS_256_NONCE_SIZE;
	if (sealed.length < nonceSize + tagLen) {
		return null;
	}
	const nonce = sealed.subarray(0, nonceSize);
	const ct = sealed.subarray(nonceSize, sealed.length - tagLen);
	const tag = sealed.subarray(sealed.length - tagLen);
	return aegis256DecryptDetached(ct, tag, ad, key, nonce);
}

/**
 * Computes a MAC (Message Authentication Code) using AEGIS-256.
 * @param data - Data to authenticate
 * @param key - 32-byte key
 * @param nonce - 32-byte nonce (optional, uses zero nonce if null)
 * @param tagLen - Tag length: 16 or 32 bytes (default: 16)
 * @returns Authentication tag
 */
export function aegis256Mac(
	data: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
	tagLen: 16 | 32 = 16,
): Uint8Array {
	const state = new Aegis256State();
	state.init(key, nonce ?? new Uint8Array(32));

	const dataPadded = zeroPad(data, 16);
	for (let i = 0; i + 16 <= dataPadded.length; i += 16) {
		state.absorb(dataPadded.subarray(i, i + 16));
	}

	return state.finalize(BigInt(data.length * 8), BigInt(tagLen * 8), tagLen);
}

/**
 * Verifies a MAC computed using AEGIS-256.
 * @param data - Data to verify
 * @param tag - Expected authentication tag (16 or 32 bytes)
 * @param key - 32-byte key
 * @param nonce - 32-byte nonce (optional, uses zero nonce if null)
 * @returns True if the tag is valid, false otherwise
 */
export function aegis256MacVerify(
	data: Uint8Array,
	tag: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array | null = null,
): boolean {
	const tagLen = tag.length as 16 | 32;
	const expectedTag = aegis256Mac(data, key, nonce, tagLen);
	return constantTimeEqual(tag, expectedTag);
}

/**
 * Generates a random 32-byte key for AEGIS-256.
 * @returns 32-byte encryption key
 * @throws Error if no cryptographic random source is available
 */
export function aegis256CreateKey(): Uint8Array {
	return randomBytes(AEGIS_256_KEY_SIZE);
}

/**
 * Generates a random 32-byte nonce for AEGIS-256.
 * @returns 32-byte nonce
 * @throws Error if no cryptographic random source is available
 */
export function aegis256CreateNonce(): Uint8Array {
	return randomBytes(AEGIS_256_NONCE_SIZE);
}
