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

/**
 * AEGIS-128X cipher state with configurable parallelism degree.
 * Extends AEGIS-128L with parallel AES rounds for improved performance on wide SIMD architectures.
 */
export class Aegis128XState {
	private v: Uint8Array[][];
	private d: number;
	private rate: number;
	private newV: Uint8Array[][];
	private tmp: Uint8Array;
	private z0: Uint8Array;
	private z1: Uint8Array;
	private ctxBufs: Uint8Array[];

	/**
	 * Creates a new AEGIS-128X state.
	 * @param degree - Parallelism degree (default: 2). Use 2 for AEGIS-128X2, 4 for AEGIS-128X4.
	 */
	constructor(degree: number = 2) {
		this.d = degree;
		this.rate = 256 * degree;
		this.v = Array.from({ length: 8 }, () =>
			Array.from({ length: degree }, () => new Uint8Array(16)),
		);
		this.newV = Array.from({ length: 8 }, () =>
			Array.from({ length: degree }, () => new Uint8Array(16)),
		);
		this.tmp = new Uint8Array(16);
		this.z0 = new Uint8Array(16 * degree);
		this.z1 = new Uint8Array(16 * degree);
		this.ctxBufs = Array.from({ length: degree }, (_, i) => {
			const buf = new Uint8Array(16);
			buf[0] = i;
			buf[1] = degree - 1;
			return buf;
		});
	}

	/**
	 * Initializes the state with a key and nonce.
	 * @param key - 16-byte encryption key
	 * @param nonce - 16-byte nonce (must be unique per message)
	 */
	init(key: Uint8Array, nonce: Uint8Array): void {
		const keyXorNonce = new Uint8Array(16);
		const keyXorC0 = new Uint8Array(16);
		const keyXorC1 = new Uint8Array(16);
		xorBlocksTo(key, nonce, keyXorNonce);
		xorBlocksTo(key, C0, keyXorC0);
		xorBlocksTo(key, C1, keyXorC1);

		for (let i = 0; i < this.d; i++) {
			this.v[0]![i]!.set(keyXorNonce);
			this.v[1]![i]!.set(C1);
			this.v[2]![i]!.set(C0);
			this.v[3]![i]!.set(C1);
			this.v[4]![i]!.set(keyXorNonce);
			this.v[5]![i]!.set(keyXorC0);
			this.v[6]![i]!.set(keyXorC1);
			this.v[7]![i]!.set(keyXorC0);
		}

		const nonceV = new Uint8Array(16 * this.d);
		const keyV = new Uint8Array(16 * this.d);
		for (let i = 0; i < this.d; i++) {
			nonceV.set(nonce, i * 16);
			keyV.set(key, i * 16);
		}

		for (let round = 0; round < 10; round++) {
			for (let i = 0; i < this.d; i++) {
				const ctx = this.ctxBufs[i]!;
				for (let j = 0; j < 16; j++) this.v[3]![i]![j] ^= ctx[j]!;
				for (let j = 0; j < 16; j++) this.v[7]![i]![j] ^= ctx[j]!;
			}
			this.update(nonceV, keyV);
		}
	}

	/**
	 * Updates the state with two message vectors.
	 * @param m0 - First message vector (16*degree bytes)
	 * @param m1 - Second message vector (16*degree bytes)
	 */
	update(m0: Uint8Array, m1: Uint8Array): void {
		const newV = this.newV;
		const tmp = this.tmp;

		for (let i = 0; i < this.d; i++) {
			const m0i = m0.subarray(i * 16, (i + 1) * 16);
			const m1i = m1.subarray(i * 16, (i + 1) * 16);

			xorBlocksTo(this.v[0]![i]!, m0i, tmp);
			aesRoundTo(this.v[7]![i]!, tmp, newV[0]![i]!);
			aesRoundTo(this.v[0]![i]!, this.v[1]![i]!, newV[1]![i]!);
			aesRoundTo(this.v[1]![i]!, this.v[2]![i]!, newV[2]![i]!);
			aesRoundTo(this.v[2]![i]!, this.v[3]![i]!, newV[3]![i]!);
			xorBlocksTo(this.v[4]![i]!, m1i, tmp);
			aesRoundTo(this.v[3]![i]!, tmp, newV[4]![i]!);
			aesRoundTo(this.v[4]![i]!, this.v[5]![i]!, newV[5]![i]!);
			aesRoundTo(this.v[5]![i]!, this.v[6]![i]!, newV[6]![i]!);
			aesRoundTo(this.v[6]![i]!, this.v[7]![i]!, newV[7]![i]!);
		}

		for (let j = 0; j < 8; j++) {
			for (let i = 0; i < this.d; i++) {
				this.v[j]![i]!.set(newV[j]![i]!);
			}
		}
	}

	/**
	 * Absorbs an associated data block into the state.
	 * @param ai - Associated data block (32*degree bytes)
	 */
	absorb(ai: Uint8Array): void {
		const halfRateBytes = this.rate / 16;
		const rateBytes = this.rate / 8;
		this.update(
			ai.subarray(0, halfRateBytes),
			ai.subarray(halfRateBytes, rateBytes),
		);
	}

	private computeZ(): void {
		const z0 = this.z0;
		const z1 = this.z1;
		const tmp = this.tmp;

		for (let i = 0; i < this.d; i++) {
			const off = i * 16;
			xorBlocksTo(this.v[6]![i]!, this.v[1]![i]!, z0.subarray(off, off + 16));
			andBlocksTo(this.v[2]![i]!, this.v[3]![i]!, tmp);
			for (let j = 0; j < 16; j++) z0[off + j] ^= tmp[j]!;

			xorBlocksTo(this.v[2]![i]!, this.v[5]![i]!, z1.subarray(off, off + 16));
			andBlocksTo(this.v[6]![i]!, this.v[7]![i]!, tmp);
			for (let j = 0; j < 16; j++) z1[off + j] ^= tmp[j]!;
		}
	}

	/**
	 * Encrypts a plaintext block and writes to output buffer.
	 * @param xi - Plaintext block (32*degree bytes)
	 * @param out - Output buffer (32*degree bytes)
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		this.computeZ();
		const z0 = this.z0;
		const z1 = this.z1;

		const halfRateBytes = this.rate / 16;
		const rateBytes = this.rate / 8;
		const t0 = xi.subarray(0, halfRateBytes);
		const t1 = xi.subarray(halfRateBytes, rateBytes);

		for (let i = 0; i < halfRateBytes; i++) out[i] = t0[i]! ^ z0[i]!;
		for (let i = 0; i < halfRateBytes; i++)
			out[halfRateBytes + i] = t1[i]! ^ z1[i]!;

		this.update(t0, t1);
	}

	/**
	 * Encrypts a plaintext block.
	 * @param xi - Plaintext block (32*degree bytes)
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
	 * @param ci - Ciphertext block (32*degree bytes)
	 * @param out - Output buffer (32*degree bytes)
	 */
	decTo(ci: Uint8Array, out: Uint8Array): void {
		this.computeZ();
		const z0 = this.z0;
		const z1 = this.z1;

		const halfRateBytes = this.rate / 16;
		const rateBytes = this.rate / 8;
		const t0 = ci.subarray(0, halfRateBytes);
		const t1 = ci.subarray(halfRateBytes, rateBytes);

		for (let i = 0; i < halfRateBytes; i++) out[i] = t0[i]! ^ z0[i]!;
		for (let i = 0; i < halfRateBytes; i++)
			out[halfRateBytes + i] = t1[i]! ^ z1[i]!;

		this.update(
			out.subarray(0, halfRateBytes),
			out.subarray(halfRateBytes, rateBytes),
		);
	}

	/**
	 * Decrypts a ciphertext block.
	 * @param ci - Ciphertext block (32*degree bytes)
	 * @returns Plaintext block of the same size
	 */
	dec(ci: Uint8Array): Uint8Array {
		const rateBytes = this.rate / 8;
		const out = new Uint8Array(rateBytes);
		this.decTo(ci, out);
		return out;
	}

	/**
	 * Decrypts a partial (final) ciphertext block.
	 * @param cn - Partial ciphertext block (smaller than 32*degree bytes)
	 * @returns Decrypted plaintext of the same length
	 */
	decPartial(cn: Uint8Array): Uint8Array {
		this.computeZ();
		const z0 = this.z0;
		const z1 = this.z1;

		const rateBytes = this.rate / 8;
		const halfRateBytes = rateBytes / 2;
		const padded = zeroPad(cn, rateBytes);
		const t0 = padded.subarray(0, halfRateBytes);
		const t1 = padded.subarray(halfRateBytes, rateBytes);

		const out = new Uint8Array(rateBytes);
		for (let i = 0; i < halfRateBytes; i++) out[i] = t0[i]! ^ z0[i]!;
		for (let i = 0; i < halfRateBytes; i++)
			out[halfRateBytes + i] = t1[i]! ^ z1[i]!;

		const xn = new Uint8Array(out.subarray(0, cn.length));

		const v = zeroPad(xn, rateBytes);
		this.update(
			v.subarray(0, halfRateBytes),
			v.subarray(halfRateBytes, rateBytes),
		);

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
			t = concatBytes(t, xorBlocks(this.v[2]![i]!, u));
		}

		for (let round = 0; round < 7; round++) {
			this.update(t, t);
		}

		if (tagLen === 16) {
			let tag = new Uint8Array(16);
			for (let i = 0; i < this.d; i++) {
				let ti = xorBlocks(this.v[0]![i]!, this.v[1]![i]!);
				ti = xorBlocks(ti, this.v[2]![i]!);
				ti = xorBlocks(ti, this.v[3]![i]!);
				ti = xorBlocks(ti, this.v[4]![i]!);
				ti = xorBlocks(ti, this.v[5]![i]!);
				ti = xorBlocks(ti, this.v[6]![i]!);
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
				ti0 = xorBlocks(ti0, this.v[3]![i]!);
				ti1 = xorBlocks(ti1, this.v[4]![i]!);
				ti1 = xorBlocks(ti1, this.v[5]![i]!);
				ti1 = xorBlocks(ti1, this.v[6]![i]!);
				ti1 = xorBlocks(ti1, this.v[7]![i]!);
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
			t = concatBytes(t, xorBlocks(this.v[2]![i]!, u));
		}

		for (let round = 0; round < 7; round++) {
			this.update(t, t);
		}

		let tags = new Uint8Array(0);
		if (tagLen === 16) {
			for (let i = 0; i < this.d; i++) {
				let ti = xorBlocks(this.v[0]![i]!, this.v[1]![i]!);
				ti = xorBlocks(ti, this.v[2]![i]!);
				ti = xorBlocks(ti, this.v[3]![i]!);
				ti = xorBlocks(ti, this.v[4]![i]!);
				ti = xorBlocks(ti, this.v[5]![i]!);
				ti = xorBlocks(ti, this.v[6]![i]!);
				tags = concatBytes(tags, ti);
			}
		} else {
			for (let i = 1; i < this.d; i++) {
				let ti0 = xorBlocks(this.v[0]![i]!, this.v[1]![i]!);
				ti0 = xorBlocks(ti0, this.v[2]![i]!);
				ti0 = xorBlocks(ti0, this.v[3]![i]!);
				let ti1 = xorBlocks(this.v[4]![i]!, this.v[5]![i]!);
				ti1 = xorBlocks(ti1, this.v[6]![i]!);
				ti1 = xorBlocks(ti1, this.v[7]![i]!);
				tags = concatBytes(tags, ti0, ti1);
			}
		}

		if (this.d > 1) {
			for (let i = 0; i + 32 <= tags.length; i += 32) {
				const tb = tags.subarray(i, i + 32);
				const x0 = zeroPad(tb.subarray(0, 16), 16 * this.d);
				const x1 = zeroPad(tb.subarray(16, 32), 16 * this.d);
				this.absorb(concatBytes(x0, x1));
			}

			const u2 = concatBytes(le64(BigInt(this.d)), le64(BigInt(tagLen * 8)));
			const t2 = zeroPad(xorBlocks(this.v[2]![0]!, u2), this.rate / 8);
			for (let round = 0; round < 7; round++) {
				this.update(t2, t2);
			}
		}

		if (tagLen === 16) {
			let tag = xorBlocks(this.v[0]![0]!, this.v[1]![0]!);
			tag = xorBlocks(tag, this.v[2]![0]!);
			tag = xorBlocks(tag, this.v[3]![0]!);
			tag = xorBlocks(tag, this.v[4]![0]!);
			tag = xorBlocks(tag, this.v[5]![0]!);
			tag = xorBlocks(tag, this.v[6]![0]!);
			return tag;
		} else {
			let t0 = xorBlocks(this.v[0]![0]!, this.v[1]![0]!);
			t0 = xorBlocks(t0, this.v[2]![0]!);
			t0 = xorBlocks(t0, this.v[3]![0]!);
			let t1 = xorBlocks(this.v[4]![0]!, this.v[5]![0]!);
			t1 = xorBlocks(t1, this.v[6]![0]!);
			t1 = xorBlocks(t1, this.v[7]![0]!);
			return concatBytes(t0, t1);
		}
	}
}

/**
 * Encrypts a message using AEGIS-128X.
 * @param msg - Plaintext message
 * @param ad - Associated data (authenticated but not encrypted)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must be unique per message with the same key)
 * @param tagLen - Authentication tag length: 16 or 32 bytes (default: 16)
 * @param degree - Parallelism degree (default: 2)
 * @returns Object containing ciphertext and authentication tag
 */
export function aegis128XEncrypt(
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
	degree: number = 2,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const state = new Aegis128XState(degree);
	const rateBytes = (256 * degree) / 8;

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
 * Decrypts a message using AEGIS-128X.
 * @param ct - Ciphertext
 * @param tag - Authentication tag (16 or 32 bytes)
 * @param ad - Associated data (must match what was used during encryption)
 * @param key - 16-byte encryption key
 * @param nonce - 16-byte nonce (must match what was used during encryption)
 * @param degree - Parallelism degree (default: 2)
 * @returns Decrypted plaintext, or null if authentication fails
 */
export function aegis128XDecrypt(
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	degree: number = 2,
): Uint8Array | null {
	const tagLen = tag.length as 16 | 32;
	const state = new Aegis128XState(degree);
	const rateBytes = (256 * degree) / 8;

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

/** AEGIS-128X2 encryption (degree=2). */
export const aegis128X2Encrypt = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XEncrypt(msg, ad, key, nonce, tagLen, 2);

/** AEGIS-128X2 decryption (degree=2). */
export const aegis128X2Decrypt = (
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis128XDecrypt(ct, tag, ad, key, nonce, 2);

/** AEGIS-128X4 encryption (degree=4). */
export const aegis128X4Encrypt = (
	msg: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tagLen: 16 | 32 = 16,
) => aegis128XEncrypt(msg, ad, key, nonce, tagLen, 4);

/** AEGIS-128X4 decryption (degree=4). */
export const aegis128X4Decrypt = (
	ct: Uint8Array,
	tag: Uint8Array,
	ad: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
) => aegis128XDecrypt(ct, tag, ad, key, nonce, 4);

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
	const rateBytes = (256 * degree) / 8;

	state.init(key, nonce ?? new Uint8Array(16));

	const dataPadded = zeroPad(data, rateBytes);
	for (let i = 0; i + rateBytes <= dataPadded.length; i += rateBytes) {
		state.absorb(dataPadded.subarray(i, i + rateBytes));
	}

	return state.finalizeMac(BigInt(data.length * 8), tagLen);
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
