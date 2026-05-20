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
	blocksRotr6,
	blocksXor,
	blockToBytes,
	blockXor,
	createAesBlock,
	createAesBlocks,
	pack,
	pack04_6,
	unpack,
	unpack04_6,
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
 * Uses 6 AES blocks stored in packed bitsliced form throughout the lifetime
 * of the state.
 */
export class Aegis256BsState {
	private st: AesBlocks;
	private st1: AesBlocks;
	private constantInput: AesBlocks;
	private tmp: AesBlock;
	private z: AesBlock;

	constructor() {
		this.st = createAesBlocks();
		this.st1 = createAesBlocks();
		this.constantInput = createAesBlocks();
		this.tmp = createAesBlock();
		this.z = createAesBlock();
	}

	private aegisRoundPacked(): void {
		const st = this.st;
		const st1 = this.st1;

		st1.set(st);
		aesRound(st1);
		blocksRotr6(st1);
		blocksXor(st, st1);
		blocksXor(st, this.constantInput);
	}

	private packConstantInput(m: AesBlock): void {
		const out = this.constantInput;
		out.fill(0);
		blocksPut(out, m, 0);
		pack04_6(out);
	}

	/**
	 * Extract the keystream block z directly from the packed state.
	 *
	 *   z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	 *
	 * In the packed layout, logical block j lives at bit position (7 - j) of
	 * every byte, so S1 = bit 6, S4 = bit 3, S5 = bit 2, S2 = bit 5,
	 * S3 = bit 4. The combination is computed lane-wise into bit position 7
	 * and unpack04_6 then extracts the AES block at logical index 0.
	 */
	private keystreamPacked(): void {
		const st = this.st;
		const zPacked = this.st1;
		for (let i = 0; i < 32; i++) {
			const x = st[i]!;
			zPacked[i] =
				((x & 0x40404040) << 1) ^
				((x & 0x08080808) << 4) ^
				((x & 0x04040404) << 5) ^
				((x & (x >>> 1) & 0x10101010) << 3);
		}
		unpack04_6(zPacked);
		const z = this.z;
		for (let i = 0; i < 4; i++) {
			z[i] = zPacked[wordIdx(0, i)]!;
		}
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

		pack(this.st);
		for (let i = 0; i < 4; i++) {
			this.packConstantInput(k0);
			this.aegisRoundPacked();
			this.packConstantInput(k1);
			this.aegisRoundPacked();
			this.packConstantInput(k0n0);
			this.aegisRoundPacked();
			this.packConstantInput(k1n1);
			this.aegisRoundPacked();
		}
	}

	/**
	 * Absorbs a 16-byte associated data block into the state.
	 */
	absorb(ai: Uint8Array): void {
		const msg = this.tmp;
		blockFromBytes(msg, ai);
		this.packConstantInput(msg);
		this.aegisRoundPacked();
	}

	/**
	 * Encrypts a 16-byte plaintext block and writes to output buffer.
	 */
	encTo(xi: Uint8Array, out: Uint8Array): void {
		const t = this.tmp;

		this.keystreamPacked();

		blockFromBytes(t, xi);
		this.packConstantInput(t);
		this.aegisRoundPacked();

		blockXor(t, t, this.z);
		blockToBytes(out, t);
	}

	enc(xi: Uint8Array): Uint8Array {
		const out = new Uint8Array(16);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a 16-byte ciphertext block and writes to output buffer.
	 */
	decTo(ci: Uint8Array, out: Uint8Array): void {
		const msg = this.tmp;

		blockFromBytes(msg, ci);
		this.keystreamPacked();
		blockXor(msg, msg, this.z);

		this.packConstantInput(msg);
		this.aegisRoundPacked();

		blockToBytes(out, msg);
	}

	dec(ci: Uint8Array): Uint8Array {
		const out = new Uint8Array(16);
		this.decTo(ci, out);
		return out;
	}

	encInPlace(block: Uint8Array): void {
		this.encTo(block, block);
	}

	decInPlace(block: Uint8Array): void {
		this.decTo(block, block);
	}

	decPartial(cn: Uint8Array): Uint8Array {
		const msg = this.tmp;

		const padded = zeroPad(cn, RATE);
		blockFromBytes(msg, padded);

		this.keystreamPacked();
		blockXor(msg, msg, this.z);

		const pad = new Uint8Array(RATE);
		blockToBytes(pad, msg);

		const xn = new Uint8Array(pad.subarray(0, cn.length));

		pad.fill(0, cn.length);
		blockFromBytes(msg, pad);

		this.packConstantInput(msg);
		this.aegisRoundPacked();

		return xn;
	}

	/**
	 * Finalizes encryption/decryption and produces an authentication tag.
	 */
	finalize(adLen: number, msgLen: number, tagLen: 16 | 32 = 16): Uint8Array {
		const st = this.st;
		const tmp = this.tmp;

		tmp[0] = ((adLen * 8) & 0xffffffff) >>> 0;
		tmp[1] = Math.floor((adLen * 8) / 0x100000000) >>> 0;
		tmp[2] = ((msgLen * 8) & 0xffffffff) >>> 0;
		tmp[3] = Math.floor((msgLen * 8) / 0x100000000) >>> 0;

		const unpacked = this.st1;
		unpacked.set(st);
		unpack(unpacked);

		tmp[0] = (tmp[0]! ^ unpacked[wordIdx(3, 0)]!) >>> 0;
		tmp[1] = (tmp[1]! ^ unpacked[wordIdx(3, 1)]!) >>> 0;
		tmp[2] = (tmp[2]! ^ unpacked[wordIdx(3, 2)]!) >>> 0;
		tmp[3] = (tmp[3]! ^ unpacked[wordIdx(3, 3)]!) >>> 0;

		this.packConstantInput(tmp);
		for (let i = 0; i < 7; i++) {
			this.aegisRoundPacked();
		}
		unpack(st);

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

export function aegis256BsCreateKey(): Uint8Array {
	return randomBytes(AEGIS_256_BS_KEY_SIZE);
}

export function aegis256BsCreateNonce(): Uint8Array {
	return randomBytes(AEGIS_256_BS_NONCE_SIZE);
}
