import { describe, expect, test } from "bun:test";
import {
	Aegis256XState,
	aegis256X2Decrypt,
	aegis256X2Encrypt,
	aegis256X2Mac,
	aegis256X2MacVerify,
	aegis256X4Mac,
	aegis256X4MacVerify,
} from "../src/aegis256x.ts";

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

describe("AEGIS-256X2 Init", () => {
	test("Initial state after initialization", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);

		const state = new Aegis256XState(2);
		state.init(key, nonce);

		expect(bytesToHex((state as any).v[0][0])).toBe(
			"eca2bf4538442e8712d4972595744039",
		);
		expect(bytesToHex((state as any).v[0][1])).toBe(
			"201405efa9264f07911db58101903087",
		);
		expect(bytesToHex((state as any).v[1][0])).toBe(
			"3e536a998799408a97f3479a6f779d48",
		);
		expect(bytesToHex((state as any).v[1][1])).toBe(
			"0d79a7d822a5d215f78c3bf2feb33ae1",
		);
		expect(bytesToHex((state as any).v[2][0])).toBe(
			"cf8c63d6f2b4563cdd9231107c85950e",
		);
		expect(bytesToHex((state as any).v[2][1])).toBe(
			"78d17ed7d8d563ff11bd202c76864839",
		);
		expect(bytesToHex((state as any).v[3][0])).toBe(
			"d7e0707e6bfbbad913bc94b6993a9fa0",
		);
		expect(bytesToHex((state as any).v[3][1])).toBe(
			"097e4b1bff40d4c19cb29dfd125d62f2",
		);
		expect(bytesToHex((state as any).v[4][0])).toBe(
			"a373cf6d537dd66bc0ef0f2f9285359f",
		);
		expect(bytesToHex((state as any).v[4][1])).toBe(
			"c0d0ae0c48f9df3faaf0e7be7768c326",
		);
		expect(bytesToHex((state as any).v[5][0])).toBe(
			"9f76560dcae1efacabdcce446ae283bc",
		);
		expect(bytesToHex((state as any).v[5][1])).toBe(
			"bd52a6b9c8f976a26ec1409df19e8bfe",
		);
	});
});

describe("AEGIS-256X2 Encrypt", () => {
	test("Test Vector 1 - empty message, 128-bit tag", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis256X2Encrypt(msg, ad, key, nonce, 16);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe("62cdbab084c83dacdb945bb446f049c8");
	});

	test("Test Vector 1 - empty message, 256-bit tag", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis256X2Encrypt(msg, ad, key, nonce, 32);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe(
			"25d7e799b49a80354c3f881ac2f1027f471a5d293052bd9997abd3ae84014bb7",
		);
	});

	test("Test Vector 2 - with AD and message", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);
		const ad = hexToBytes("0102030401020304");
		const msg = hexToBytes(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);

		const { ciphertext, tag } = aegis256X2Encrypt(msg, ad, key, nonce, 16);

		expect(bytesToHex(ciphertext)).toBe(
			"72120c2ea8236180d67859001f4729077b7064c414384fe3a7b52f1571f4f8a7d0f01e18db4f3bc0adb150702e5d147a8d36522132761b994c1bd395589e2ccf0790dfe2a3d12d61cd666b2859827739db4037dd3124c78424459376f6cac08e1a7223a2a43e398ce6385cd654a19f481cba3b8f25910b42",
		);
		expect(bytesToHex(tag)).toBe("635d391828520bf1512763f0c8f5cdbd");
	});

	test("Test Vector 2 - 256-bit tag", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);
		const ad = hexToBytes("0102030401020304");
		const msg = hexToBytes(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);

		const { ciphertext, tag } = aegis256X2Encrypt(msg, ad, key, nonce, 32);

		expect(bytesToHex(ciphertext)).toBe(
			"72120c2ea8236180d67859001f4729077b7064c414384fe3a7b52f1571f4f8a7d0f01e18db4f3bc0adb150702e5d147a8d36522132761b994c1bd395589e2ccf0790dfe2a3d12d61cd666b2859827739db4037dd3124c78424459376f6cac08e1a7223a2a43e398ce6385cd654a19f481cba3b8f25910b42",
		);
		expect(bytesToHex(tag)).toBe(
			"b5668d3317159e9cc5d46e4803c3a76ad63bb42b3f47956d94f30db8cb366ad7",
		);
	});
});

describe("AEGIS-256X2 Decrypt", () => {
	test("Decrypt Test Vector 2", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);
		const ad = hexToBytes("0102030401020304");
		const ct = hexToBytes(
			"72120c2ea8236180d67859001f4729077b7064c414384fe3a7b52f1571f4f8a7d0f01e18db4f3bc0adb150702e5d147a8d36522132761b994c1bd395589e2ccf0790dfe2a3d12d61cd666b2859827739db4037dd3124c78424459376f6cac08e1a7223a2a43e398ce6385cd654a19f481cba3b8f25910b42",
		);
		const tag = hexToBytes("635d391828520bf1512763f0c8f5cdbd");

		const msg = aegis256X2Decrypt(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe(
			"040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607040506070405060704050607",
		);
	});

	test("Wrong tag fails", () => {
		const key = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const nonce = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		);
		const ad = hexToBytes("0102030401020304");
		const ct = hexToBytes(
			"72120c2ea8236180d67859001f4729077b7064c414384fe3a7b52f1571f4f8a7d0f01e18db4f3bc0adb150702e5d147a8d36522132761b994c1bd395589e2ccf0790dfe2a3d12d61cd666b2859827739db4037dd3124c78424459376f6cac08e1a7223a2a43e398ce6385cd654a19f481cba3b8f25910b42",
		);
		const tag = hexToBytes("735d391828520bf1512763f0c8f5cdbd");

		const msg = aegis256X2Decrypt(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});
});

describe("AEGISMAC-256X2", () => {
	test("Test Vector - 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis256X2Mac(data, key, nonce, 16);

		expect(bytesToHex(tag)).toBe("fb319cb6dd728a764606fb14d37f2a5e");
	});

	test("Test Vector - 256-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis256X2Mac(data, key, nonce, 32);

		expect(bytesToHex(tag)).toBe(
			"0844b20ed5147ceae89c7a160263afd4b1382d6b154ecf560ce8a342cb6a8fd1",
		);
	});

	test("Verify valid tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("fb319cb6dd728a764606fb14d37f2a5e");

		expect(aegis256X2MacVerify(data, tag, key, nonce)).toBe(true);
	});

	test("Reject invalid tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("fb319cb6dd728a764606fb14d37f2a5f");

		expect(aegis256X2MacVerify(data, tag, key, nonce)).toBe(false);
	});
});

describe("AEGISMAC-256X4", () => {
	test("Test Vector - 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis256X4Mac(data, key, nonce, 16);

		expect(bytesToHex(tag)).toBe("a51f9bc5beae60cce77f0dbc60761edd");
	});

	test("Test Vector - 256-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis256X4Mac(data, key, nonce, 32);

		expect(bytesToHex(tag)).toBe(
			"b36a16ef07c36d75a91f437502f24f545b8dfa88648ed116943c29fead3bf10c",
		);
	});

	test("Verify valid tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("a51f9bc5beae60cce77f0dbc60761edd");

		expect(aegis256X4MacVerify(data, tag, key, nonce)).toBe(true);
	});

	test("Reject invalid tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("a51f9bc5beae60cce77f0dbc60761ede");

		expect(aegis256X4MacVerify(data, tag, key, nonce)).toBe(false);
	});
});
