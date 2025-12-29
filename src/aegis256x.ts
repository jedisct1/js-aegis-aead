import {
	aesRoundTo,
	andBlocksTo,
	C0,
	C1,
	concatBytes,
	constantTimeEqual,
	le64,
	xorBlocks,
	xorBlocksTo,
	zeroPad,
} from "./aes.js";
import { randomBytes } from "./random.js";

/**
 * AEGIS-256X cipher state with configurable parallelism degree.
 * Extends AEGIS-256 with parallel AES rounds for improved performance on wide SIMD architectures.
 */
export class Aegis256XState {
	private v: Uint8Array[][];
	private d: number;
	private rate: number;
	private newV: Uint8Array[][];
	private tmp: Uint8Array;
	private z: Uint8Array;
	private ctxBufs: Uint8Array[];

	/**
	 * Creates a new AEGIS-256X state.
	 * @param degree - Parallelism degree (default: 2). Use 2 for AEGIS-256X2, 4 for AEGIS-256X4.
	 */
	constructor(degree: number = 2) {
		this.d = degree;
		this.rate = 128 * degree;
		this.v = Array.from({ length: 6 }, () =>
			Array.from({ length: degree }, () => new Uint8Array(16)),
		);
		this.newV = Array.from({ length: 6 }, () =>
			Array.from({ length: degree }, () => new Uint8Array(16)),
		);
		this.tmp = new Uint8Array(16);
		this.z = new Uint8Array(16 * degree);
		this.ctxBufs = Array.from({ length: degree }, (_, i) => {
			const buf = new Uint8Array(16);
			buf[0] = i;
			buf[1] = degree - 1;
			return buf;
		});
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

		const k0n0 = new Uint8Array(16);
		const k1n1 = new Uint8Array(16);
		const k0c0 = new Uint8Array(16);
		const k1c1 = new Uint8Array(16);
		xorBlocksTo(k0, n0, k0n0);
		xorBlocksTo(k1, n1, k1n1);
		xorBlocksTo(k0, C0, k0c0);
		xorBlocksTo(k1, C1, k1c1);

		for (let i = 0; i < this.d; i++) {
			this.v[0]![i]!.set(k0n0);
			this.v[1]![i]!.set(k1n1);
			this.v[2]![i]!.set(C1);
			this.v[3]![i]!.set(C0);
			this.v[4]![i]!.set(k0c0);
			this.v[5]![i]!.set(k1c1);
		}

		const k0V = new Uint8Array(16 * this.d);
		const k1V = new Uint8Array(16 * this.d);
		const k0n0V = new Uint8Array(16 * this.d);
		const k1n1V = new Uint8Array(16 * this.d);

		for (let i = 0; i < this.d; i++) {
			k0V.set(k0, i * 16);
			k1V.set(k1, i * 16);
			k0n0V.set(k0n0, i * 16);
			k1n1V.set(k1n1, i * 16);
		}

		for (let round = 0; round < 4; round++) {
			for (let i = 0; i < this.d; i++) {
				const ctx = this.ctxBufs[i]!;
				for (let j = 0; j < 16; j++) this.v[3]![i]![j] ^= ctx[j]!;
				for (let j = 0; j < 16; j++) this.v[5]![i]![j] ^= ctx[j]!;
			}
			this.update(k0V);

			for (let i = 0; i < this.d; i++) {
				const ctx = this.ctxBufs[i]!;
				for (let j = 0; j < 16; j++) this.v[3]![i]![j] ^= ctx[j]!;
				for (let j = 0; j < 16; j++) this.v[5]![i]![j] ^= ctx[j]!;
			}
			this.update(k1V);

			for (let i = 0; i < this.d; i++) {
				const ctx = this.ctxBufs[i]!;
				for (let j = 0; j < 16; j++) this.v[3]![i]![j] ^= ctx[j]!;
				for (let j = 0; j < 16; j++) this.v[5]![i]![j] ^= ctx[j]!;
			}
			this.update(k0n0V);

			for (let i = 0; i < this.d; i++) {
				const ctx = this.ctxBufs[i]!;
				for (let j = 0; j < 16; j++) this.v[3]![i]![j] ^= ctx[j]!;
				for (let j = 0; j < 16; j++) this.v[5]![i]![j] ^= ctx[j]!;
			}
			this.update(k1n1V);
		}
	}

	/**
	 * Updates the state with a message vector.
	 * @param m - Message vector (16*degree bytes)
	 */
	update(m: Uint8Array): void {
		const newV = this.newV;
		const tmp = this.tmp;

		for (let i = 0; i < this.d; i++) {
			const mi = m.subarray(i * 16, (i + 1) * 16);
			xorBlocksTo(this.v[0]![i]!, mi, tmp);
			aesRoundTo(this.v[5]![i]!, tmp, newV[0]![i]!);
			aesRoundTo(this.v[0]![i]!, this.v[1]![i]!, newV[1]![i]!);
			aesRoundTo(this.v[1]![i]!, this.v[2]![i]!, newV[2]![i]!);
			aesRoundTo(this.v[2]![i]!, this.v[3]![i]!, newV[3]![i]!);
			aesRoundTo(this.v[3]![i]!, this.v[4]![i]!, newV[4]![i]!);
			aesRoundTo(this.v[4]![i]!, this.v[5]![i]!, newV[5]![i]!);
		}

		for (let j = 0; j < 6; j++) {
			for (let i = 0; i < this.d; i++) {
				this.v[j]![i]!.set(newV[j]![i]!);
			}
		}
	}

	/**
	 * Absorbs an associated data block into the state.
	 * @param ai - Associated data block (16*degree bytes)
	 */
	absorb(ai: Uint8Array): void {
		this.update(ai);
	}

	private computeZ(): void {
		const z = this.z;
		const tmp = this.tmp;

		for (let i = 0; i < this.d; i++) {
			const off = i * 16;
			xorBlocksTo(this.v[1]![i]!, this.v[4]![i]!, z.subarray(off, off + 16));
			for (let j = 0; j < 16; j++) z[off + j] ^= this.v[5]![i]![j]!;
			andBlocksTo(this.v[2]![i]!, this.v[3]![i]!, tmp);
			for (let j = 0; j < 16; j++) z[off + j] ^= tmp[j]!;
		}
	}

	/**
	 * Encrypts a plaintext block and writes to output buffer.
	 * @param xi - Plaintext block (16*degree bytes)
	 * @param out - Output buffer (16*degree bytes)
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		this.computeZ();
		const z = this.z;
		const rateBytes = this.rate / 8;

		this.update(xi);

		for (let i = 0; i < rateBytes; i++) out[i] = xi[i]! ^ z[i]!;
	}

	/**
	 * Encrypts a plaintext block.
	 * @param xi - Plaintext block (16*degree bytes)
	 * @returns Ciphertext block of the same size
	 */
	enc(xi: Uint8Array): Uint8Array {
		const rateBytes = this.rate / 8;
		const out = new Uint8Array(rateBytes);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a ciphertext block and writes to output buffer.
	 * @param ci - Ciphertext block (16*degree bytes)
	 * @param out - Output buffer (16*degree bytes)
	 */
	decTo(ci: Uint8Array, out: Uint8Array): void {
		this.computeZ();
		const z = this.z;
		const rateBytes = this.rate / 8;

		for (let i = 0; i < rateBytes; i++) out[i] = ci[i]! ^ z[i]!;
		this.update(out);
	}

	/**
	 * Decrypts a ciphertext block.
	 * @param ci - Ciphertext block (16*degree bytes)
	 * @returns Plaintext block of the same size
	 */
	dec(ci: Uint8Array): Uint8Array {
		const rateBytes = this.rate / 8;
		const out = new Uint8Array(rateBytes);
		this.decTo(ci, out);
		return out;
	}

	/**
	 * Encrypts a plaintext block in-place.
	 * @param block - Buffer (plaintext in, ciphertext out), size 16*degree bytes
	 */
	encInPlace(block: Uint8Array): void {
		this.encTo(block, block);
	}

	/**
	 * Decrypts a ciphertext block in-place.
	 * @param block - Buffer (ciphertext in, plaintext out), size 16*degree bytes
	 */
	decInPlace(block: Uint8Array): void {
		this.decTo(block, block);
	}

	/**
	 * Decrypts a partial (final) ciphertext block.
	 * @param cn - Partial ciphertext block (smaller than 16*degree bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		this.computeZ();
		const z = this.z;

		const rateBytes = this.rate / 8;
		const t = zeroPad(cn, rateBytes);
		const out = new Uint8Array(rateBytes);
		for (let i = 0; i < rateBytes; i++) out[i] = t[i]! ^ z[i]!;
		const xn = new Uint8Array(out.subarray(0, cn.length));

		const v = zeroPad(xn, 16 * this.d);
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
		let t = new Uint8Array(0);
		const u = concatBytes(le64(adLenBits), le64(msgLenBits));

		for (let i = 0; i < this.d; i++) {
			t = concatBytes(t, xorBlocks(this.v[3]![i]!, u));
		}

		for (let round = 0; round < 7; round++) {
			this.update(t);
		}

		if (tagLen === 16) {
			let tag = new Uint8Array(16);
			for (let i = 0; i < this.d; i++) {
				let ti = xorBlocks(this.v[0]![i]!, this.v[1]![i]!);
				ti = xorBlocks(ti, this.v[2]![i]!);
				ti = xorBlocks(ti, this.v[3]![i]!);
				ti = xorBlocks(ti, this.v[4]![i]!);
				ti = xorBlocks(ti, this.v[5]![i]!);
				tag = xorBlocks(tag, ti);
			}
			return tag;
		} else {
			let ti0 = new Uint8Array(16);
			let ti1 = new Uint8Array(16);
			for (let i = 0; i < this.d; i++) {
				ti0 = xorBlocks(ti0, this.v[0]![i]!);
				ti0 = xorBlocks(ti0, this.v[1]![i]!);
				ti0 = xorBlocks(ti0, this.v[2]![i]!);
				ti1 = xorBlocks(ti1, this.v[3]![i]!);
				ti1 = xorBlocks(ti1, this.v[4]![i]!);
				ti1 = xorBlocks(ti1, this.v[5]![i]!);
			}
			return concatBytes(ti0, ti1);
		}
	}

	/**
	 * Finalizes MAC computation and produces an authentication tag.
	 * Uses a different finalization procedure than encryption/decryption.
	 * @param dataLenBits - Data length in bits
	 * @param tagLen - Tag length (16 or 32 bytes)
	 * @returns Authentication tag
	 */
	finalizeMac(dataLenBits: bigint, tagLen: 16 | 32 = 16): Uint8Array {
		let t = new Uint8Array(0);
		const u = concatBytes(le64(dataLenBits), le64(BigInt(tagLen * 8)));

		for (let i = 0; i < this.d; i++) {
			t = concatBytes(t, xorBlocks(this.v[3]![i]!, u));
		}

		for (let round = 0; round < 7; round++) {
			this.update(t);
		}

		let tags = new Uint8Array(0);
		if (tagLen === 16) {
			for (let i = 1; i < this.d; i++) {
				let ti = xorBlocks(this.v[0]![i]!, this.v[1]![i]!);
				ti = xorBlocks(ti, this.v[2]![i]!);
				ti = xorBlocks(ti, this.v[3]![i]!);
				ti = xorBlocks(ti, this.v[4]![i]!);
				ti = xorBlocks(ti, this.v[5]![i]!);
				tags = concatBytes(tags, ti);
			}
		} else {
			for (let i = 1; i < this.d; i++) {
				let ti0 = xorBlocks(this.v[0]![i]!, this.v[1]![i]!);
				ti0 = xorBlocks(ti0, this.v[2]![i]!);
				let ti1 = xorBlocks(this.v[3]![i]!, this.v[4]![i]!);
				ti1 = xorBlocks(ti1, this.v[5]![i]!);
				tags = concatBytes(tags, ti0, ti1);
			}
		}

		if (this.d > 1) {
			for (let i = 0; i + 16 <= tags.length; i += 16) {
				const v = zeroPad(tags.subarray(i, i + 16), 16 * this.d);
				this.absorb(v);
			}

			const u2 = concatBytes(le64(BigInt(this.d)), le64(BigInt(tagLen * 8)));
			const t2 = zeroPad(xorBlocks(this.v[3]![0]!, u2), this.rate / 8);
			for (let round = 0; round < 7; round++) {
				this.update(t2);
			}
		}

		if (tagLen === 16) {
			let tag = xorBlocks(this.v[0]![0]!, this.v[1]![0]!);
			tag = xorBlocks(tag, this.v[2]![0]!);
			tag = xorBlocks(tag, this.v[3]![0]!);
			tag = xorBlocks(tag, this.v[4]![0]!);
			tag = xorBlocks(tag, this.v[5]![0]!);
			return tag;
		} else {
			let t0 = xorBlocks(this.v[0]![0]!, this.v[1]![0]!);
			t0 = xorBlocks(t0, this.v[2]![0]!);
			let t1 = xorBlocks(this.v[3]![0]!, this.v[4]![0]!);
			t1 = xorBlocks(t1, this.v[5]![0]!);
			return concatBytes(t0, t1);
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
	const rateBytes = (128 * degree) / 8;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded.subarray(i, i + rateBytes));
	}

	const msgPadded = zeroPad(msg, rateBytes);
	const ct = new Uint8Array(msgPadded.length);
	for (let i = 0; i + rateBytes <= msgPadded.length; i += rateBytes) {
		state.encTo(
			msgPadded.subarray(i, i + rateBytes),
			ct.subarray(i, i + rateBytes),
		);
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
	const rateBytes = (128 * degree) / 8;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded.subarray(i, i + rateBytes));
	}

	const fullBlocksLen = Math.floor(ct.length / rateBytes) * rateBytes;
	const cn = ct.subarray(fullBlocksLen);

	const msg = new Uint8Array(fullBlocksLen + (cn.length > 0 ? cn.length : 0));
	for (let i = 0; i + rateBytes <= ct.length; i += rateBytes) {
		state.decTo(ct.subarray(i, i + rateBytes), msg.subarray(i, i + rateBytes));
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
	const rateBytes = (128 * degree) / 8;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded.subarray(i, i + rateBytes));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / rateBytes) * rateBytes;

	for (let i = 0; i < fullBlocksLen; i += rateBytes) {
		state.encInPlace(data.subarray(i, i + rateBytes));
	}

	if (msgLen > fullBlocksLen) {
		const lastPartial = data.subarray(fullBlocksLen);
		const lastBlock = zeroPad(lastPartial, rateBytes);
		const encBlock = state.enc(lastBlock);
		lastPartial.set(encBlock.subarray(0, lastPartial.length));
	}

	return state.finalize(BigInt(ad.length * 8), BigInt(msgLen * 8), tagLen);
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
	const rateBytes = (128 * degree) / 8;

	state.init(key, nonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded.subarray(i, i + rateBytes));
	}

	const msgLen = data.length;
	const fullBlocksLen = Math.floor(msgLen / rateBytes) * rateBytes;

	for (let i = 0; i < fullBlocksLen; i += rateBytes) {
		state.decInPlace(data.subarray(i, i + rateBytes));
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
	const state = new Aegis256XState(degree);
	const rateBytes = (128 * degree) / 8;

	state.init(key, actualNonce);

	const adPadded = zeroPad(ad, rateBytes);
	for (let i = 0; i + rateBytes <= adPadded.length; i += rateBytes) {
		state.absorb(adPadded.subarray(i, i + rateBytes));
	}

	const nonceSize = AEGIS_256X_NONCE_SIZE;
	const result = new Uint8Array(nonceSize + msg.length + tagLen);
	result.set(actualNonce, 0);

	const fullBlocks = Math.floor(msg.length / rateBytes) * rateBytes;
	for (let i = 0; i < fullBlocks; i += rateBytes) {
		state.encTo(
			msg.subarray(i, i + rateBytes),
			result.subarray(nonceSize + i, nonceSize + i + rateBytes),
		);
	}

	if (msg.length > fullBlocks) {
		const lastBlock = zeroPad(msg.subarray(fullBlocks), rateBytes);
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
	const rateBytes = (128 * degree) / 8;

	state.init(key, nonce ?? new Uint8Array(32));

	const dataPadded = zeroPad(data, rateBytes);
	for (let i = 0; i + rateBytes <= dataPadded.length; i += rateBytes) {
		state.absorb(dataPadded.subarray(i, i + rateBytes));
	}

	return state.finalizeMac(BigInt(data.length * 8), tagLen);
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
