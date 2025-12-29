import { describe, expect, test } from "bun:test";
import {
	AEGIS_128X_NONCE_SIZE,
	Aegis128XState,
	aegis128X2Decrypt,
	aegis128X2DecryptDetached,
	aegis128X2DecryptDetachedInPlace,
	aegis128X2Encrypt,
	aegis128X2EncryptDetached,
	aegis128X2EncryptDetachedInPlace,
	aegis128X2Mac,
	aegis128X2MacVerify,
	aegis128X4Mac,
	aegis128X4MacVerify,
} from "../src/aegis128x.ts";

function hexToBytes(hex: string): Uint8Array {
	if (hex === "") return new Uint8Array(0);
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

describe("AEGIS-128X2 Init", () => {
	test("Initial state after initialization", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");

		const state = new Aegis128XState(2);
		state.init(key, nonce);

		expect(bytesToHex((state as any).v[0][0])).toBe(
			"a4fc1ad9a72942fb88bd2cabbba6509a",
		);
		expect(bytesToHex((state as any).v[0][1])).toBe(
			"80a40e392fc71084209b6c3319bdc6cc",
		);
		expect(bytesToHex((state as any).v[1][0])).toBe(
			"380f435cf801763b1f0c2a2f7212052d",
		);
		expect(bytesToHex((state as any).v[1][1])).toBe(
			"73796607b59b1b650ee91c152af1f18a",
		);
		expect(bytesToHex((state as any).v[2][0])).toBe(
			"6ee1de433ea877fa33bc0782abff2dcb",
		);
		expect(bytesToHex((state as any).v[2][1])).toBe(
			"b9fab2ab496e16d1facaffd5453cbf14",
		);
		expect(bytesToHex((state as any).v[3][0])).toBe(
			"85f94b0d4263bfa86fdf45a603d8b6ac",
		);
		expect(bytesToHex((state as any).v[3][1])).toBe(
			"90356c8cadbaa2c969001da02e3feca0",
		);
		expect(bytesToHex((state as any).v[4][0])).toBe(
			"09bd69ad3730174bcd2ce9a27cd1357e",
		);
		expect(bytesToHex((state as any).v[4][1])).toBe(
			"e610b45125796a4fcf1708cef5c4f718",
		);
		expect(bytesToHex((state as any).v[5][0])).toBe(
			"fcdeb0cf0a87bf442fc82383ddb0f6d6",
		);
		expect(bytesToHex((state as any).v[5][1])).toBe(
			"61ad32a4694d6f3cca313a2d3f4687aa",
		);
		expect(bytesToHex((state as any).v[6][0])).toBe(
			"571c207988659e2cdfbdaae77f4f37e3",
		);
		expect(bytesToHex((state as any).v[6][1])).toBe(
			"32e6094e217573bf91fb28c145a3efa8",
		);
		expect(bytesToHex((state as any).v[7][0])).toBe(
			"ca549badf8faa58222412478598651cf",
		);
		expect(bytesToHex((state as any).v[7][1])).toBe(
			"3407279a54ce76d2e2e8a90ec5d108eb",
		);
	});
});

describe("AEGIS-128X2 Encrypt Detached", () => {
	test("Test Vector 1 - empty message, 128-bit tag", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis128X2EncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe("63117dc57756e402819a82e13eca8379");
	});

	test("Test Vector 1 - empty message, 256-bit tag", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis128X2EncryptDetached(
			msg,
			ad,
			key,
			nonce,
			32,
		);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe(
			"b92c71fdbd358b8a4de70b27631ace90cffd9b9cfba82028412bac41b4f53759",
		);
	});

	test("Test Vector 2 - with AD and message", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0102030401020304");
		const msg = hexToBytes(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);

		const { ciphertext, tag } = aegis128X2EncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe(
			"5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f",
		);
		expect(bytesToHex(tag)).toBe("1aebc200804f405cab637f2adebb6d77");
	});

	test("Test Vector 2 - 256-bit tag", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0102030401020304");
		const msg = hexToBytes(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);

		const { ciphertext, tag } = aegis128X2EncryptDetached(
			msg,
			ad,
			key,
			nonce,
			32,
		);

		expect(bytesToHex(ciphertext)).toBe(
			"5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f",
		);
		expect(bytesToHex(tag)).toBe(
			"c471876f9b4978c44f2ae1ce770cdb11a094ee3feca64e7afcd48bfe52c60eca",
		);
	});
});

describe("AEGIS-128X2 Decrypt Detached", () => {
	test("Decrypt Test Vector 2", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0102030401020304");
		const ct = hexToBytes(
			"5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f",
		);
		const tag = hexToBytes("1aebc200804f405cab637f2adebb6d77");

		const msg = aegis128X2DecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);
	});

	test("Wrong tag fails", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0102030401020304");
		const ct = hexToBytes(
			"5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f",
		);
		const tag = hexToBytes("2aebc200804f405cab637f2adebb6d77");

		const msg = aegis128X2DecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});
});

describe("AEGIS-128X2 Encrypt/Decrypt (combined)", () => {
	test("Roundtrip with 128-bit tag", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0102030401020304");
		const msg = hexToBytes(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);

		const sealed = aegis128X2Encrypt(msg, ad, key, nonce, 16);

		expect(sealed.length).toBe(AEGIS_128X_NONCE_SIZE + msg.length + 16);

		const decrypted = aegis128X2Decrypt(sealed, ad, key, 16);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe(bytesToHex(msg));
	});

	test("Roundtrip with 256-bit tag", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const sealed = aegis128X2Encrypt(msg, ad, key, nonce, 32);

		expect(sealed.length).toBe(AEGIS_128X_NONCE_SIZE + 32);

		const decrypted = aegis128X2Decrypt(sealed, ad, key, 32);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe("");
	});

	test("Decrypt returns null for tampered ciphertext", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const sealed = aegis128X2Encrypt(msg, ad, key, nonce, 16);
		sealed[AEGIS_128X_NONCE_SIZE] ^= 1;

		const decrypted = aegis128X2Decrypt(sealed, ad, key, 16);
		expect(decrypted).toBeNull();
	});
});

describe("AEGISMAC-128X2", () => {
	test("Test Vector - 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis128X2Mac(data, key, nonce, 16);

		expect(bytesToHex(tag)).toBe("6873ee34e6b5c59143b6d35c5e4f2c6e");
	});

	test("Test Vector - 256-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis128X2Mac(data, key, nonce, 32);

		expect(bytesToHex(tag)).toBe(
			"afcba3fc2d63c8d6c7f2d63f3ec8fbbbaf022e15ac120e78ffa7755abccd959c",
		);
	});

	test("Verify valid tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("6873ee34e6b5c59143b6d35c5e4f2c6e");

		expect(aegis128X2MacVerify(data, tag, key, nonce)).toBe(true);
	});

	test("Reject invalid tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("6873ee34e6b5c59143b6d35c5e4f2c6f");

		expect(aegis128X2MacVerify(data, tag, key, nonce)).toBe(false);
	});
});

describe("AEGISMAC-128X4", () => {
	test("Test Vector - 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis128X4Mac(data, key, nonce, 16);

		expect(bytesToHex(tag)).toBe("c45a98fd9ab8956ce616eb008cfe4e53");
	});

	test("Test Vector - 256-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis128X4Mac(data, key, nonce, 32);

		expect(bytesToHex(tag)).toBe(
			"26fdc76f41b1da7aec7779f6e964beae8904e662f05aca8345ae3befb357412a",
		);
	});

	test("Verify valid tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("c45a98fd9ab8956ce616eb008cfe4e53");

		expect(aegis128X4MacVerify(data, tag, key, nonce)).toBe(true);
	});

	test("Reject invalid tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("c45a98fd9ab8956ce616eb008cfe4e54");

		expect(aegis128X4MacVerify(data, tag, key, nonce)).toBe(false);
	});
});

describe("AEGIS-128X2 In-Place Encryption/Decryption", () => {
	test("In-place encrypt produces same ciphertext as regular encrypt", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const { ciphertext: expected, tag: expectedTag } =
			aegis128X2EncryptDetached(msg, ad, key, nonce, 16);

		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const tag = aegis128X2EncryptDetachedInPlace(data, ad, key, nonce, 16);

		expect(bytesToHex(data)).toBe(bytesToHex(expected));
		expect(bytesToHex(tag)).toBe(bytesToHex(expectedTag));
	});

	test("In-place roundtrip", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0001020304050607");
		const originalMsg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const data = new Uint8Array(originalMsg);
		const tag = aegis128X2EncryptDetachedInPlace(data, ad, key, nonce, 16);

		const result = aegis128X2DecryptDetachedInPlace(data, tag, ad, key, nonce);
		expect(result).toBe(true);
		expect(bytesToHex(data)).toBe(bytesToHex(originalMsg));
	});

	test("In-place decrypt fails with wrong tag", () => {
		const key = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const nonce = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const ad = hexToBytes("0001020304050607");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		aegis128X2EncryptDetachedInPlace(data, ad, key, nonce, 16);

		const wrongTag = new Uint8Array(16);
		const result = aegis128X2DecryptDetachedInPlace(
			data,
			wrongTag,
			ad,
			key,
			nonce,
		);

		expect(result).toBe(false);
		expect(data.every((b) => b === 0)).toBe(true);
	});
});
