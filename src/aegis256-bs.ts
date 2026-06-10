/**
 * Bitsliced AEGIS-256 implementation.
 * Provides constant-time operation by processing state blocks simultaneously.
 */

import { constantTimeEqual, zeroPad } from "./aes.js";
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
	private constantInput: AesBlocks;
	private tmp: AesBlock;
	private z: AesBlock;

	constructor() {
		this.st = createAesBlocks();
		this.constantInput = createAesBlocks();
		this.tmp = createAesBlock();
		this.z = createAesBlock();
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

		this.st.fill(0);
		blocksPut(this.st, k0n0, 0);
		blocksPut(this.st, k1n1, 1);
		blocksPut(this.st, C1, 2);
		blocksPut(this.st, C0, 3);
		blocksPut(this.st, k0c0, 4);
		blocksPut(this.st, k1c1, 5);

		const ciK0 = createAesBlocks();
		const ciK1 = createAesBlocks();
		const ciK0N0 = createAesBlocks();
		const ciK1N1 = createAesBlocks();
		packConstantInput256(ciK0, k0);
		packConstantInput256(ciK1, k1);
		packConstantInput256(ciK0N0, k0n0);
		packConstantInput256(ciK1N1, k1n1);

		pack(this.st);
		for (let i = 0; i < 4; i++) {
			aegisRound256(this.st, ciK0);
			aegisRound256(this.st, ciK1);
			aegisRound256(this.st, ciK0N0);
			aegisRound256(this.st, ciK1N1);
		}
	}

	/**
	 * Absorbs a 16-byte associated data block into the state.
	 * @param ai - Buffer holding the 16-byte associated data block
	 * @param off - Offset of the block within the buffer
	 */
	absorb(ai: Uint8Array, off = 0): void {
		const msg = this.tmp;
		blockFromBytes(msg, ai, off);
		packConstantInput256(this.constantInput, msg);
		aegisRound256(this.st, this.constantInput);
	}

	/**
	 * Encrypts a 16-byte plaintext block and writes to output buffer.
	 * @param xi - Buffer holding the 16-byte plaintext block
	 * @param out - Output buffer receiving the 16-byte ciphertext block
	 * @param inOff - Offset of the plaintext block within xi
	 * @param outOff - Offset of the ciphertext block within out
	 */
	encTo(xi: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const t = this.tmp;

		keystream256(this.st, this.z);

		blockFromBytes(t, xi, inOff);
		packConstantInput256(this.constantInput, t);
		aegisRound256(this.st, this.constantInput);

		blockXor(t, t, this.z);
		blockToBytes(out, t, outOff);
	}

	enc(xi: Uint8Array): Uint8Array {
		const out = new Uint8Array(16);
		this.encTo(xi, out);
		return out;
	}

	/**
	 * Decrypts a 16-byte ciphertext block and writes to output buffer.
	 * @param ci - Buffer holding the 16-byte ciphertext block
	 * @param out - Output buffer receiving the 16-byte plaintext block
	 * @param inOff - Offset of the ciphertext block within ci
	 * @param outOff - Offset of the plaintext block within out
	 */
	decTo(ci: Uint8Array, out: Uint8Array, inOff = 0, outOff = 0): void {
		const msg = this.tmp;

		blockFromBytes(msg, ci, inOff);
		keystream256(this.st, this.z);
		blockXor(msg, msg, this.z);

		packConstantInput256(this.constantInput, msg);
		aegisRound256(this.st, this.constantInput);

		blockToBytes(out, msg, outOff);
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

		keystream256(this.st, this.z);
		blockXor(msg, msg, this.z);

		const pad = new Uint8Array(RATE);
		blockToBytes(pad, msg);

		const xn = new Uint8Array(pad.subarray(0, cn.length));

		pad.fill(0, cn.length);
		blockFromBytes(msg, pad);

		packConstantInput256(this.constantInput, msg);
		aegisRound256(this.st, this.constantInput);

		return xn;
	}

	/**
	 * Finalizes encryption/decryption and produces an authentication tag.
	 */
	finalize(adLen: number, msgLen: number, tagLen: 16 | 32 = 16): Uint8Array {
		const st = this.st;
		const tmp = this.tmp;

		tmp[0] = (adLen * 8) & 0xffffffff;
		tmp[1] = Math.floor((adLen * 8) / 0x100000000);
		tmp[2] = (msgLen * 8) & 0xffffffff;
		tmp[3] = Math.floor((msgLen * 8) / 0x100000000);

		const unpacked = createAesBlocks();
		unpacked.set(st);
		unpack(unpacked);

		tmp[0] = tmp[0]! ^ unpacked[wordIdx(3, 0)]!;
		tmp[1] = tmp[1]! ^ unpacked[wordIdx(3, 1)]!;
		tmp[2] = tmp[2]! ^ unpacked[wordIdx(3, 2)]!;
		tmp[3] = tmp[3]! ^ unpacked[wordIdx(3, 3)]!;

		packConstantInput256(this.constantInput, tmp);
		for (let i = 0; i < 7; i++) {
			aegisRound256(st, this.constantInput);
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
					st[wordIdx(5, i)]!;
			}
			blockToBytes(tag, tagBlock);
			return tag;
		} else {
			const tag = new Uint8Array(32);
			const tagBlock0 = createAesBlock();
			const tagBlock1 = createAesBlock();
			for (let i = 0; i < 4; i++) {
				tagBlock0[i] =
					st[wordIdx(0, i)]! ^ st[wordIdx(1, i)]! ^ st[wordIdx(2, i)]!;
			}
			for (let i = 0; i < 4; i++) {
				tagBlock1[i] =
					st[wordIdx(3, i)]! ^ st[wordIdx(4, i)]! ^ st[wordIdx(5, i)]!;
			}
			blockToBytes(tag, tagBlock0);
			blockToBytes(tag, tagBlock1, 16);
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
		state.absorb(dataPadded, i);
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
