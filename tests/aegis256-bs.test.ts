import { describe, expect, test } from "bun:test";
import {
	AEGIS_256_BS_NONCE_SIZE,
	aegis256BsDecrypt,
	aegis256BsDecryptDetached,
	aegis256BsDecryptDetachedInPlace,
	aegis256BsEncrypt,
	aegis256BsEncryptDetached,
	aegis256BsEncryptDetachedInPlace,
	aegis256BsMac,
	aegis256BsMacVerify,
} from "../src/aegis256-bs.ts";

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

describe("AEGIS-256 Bitsliced Encrypt Detached", () => {
	test("Test Vector 1 - 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const { ciphertext, tag } = aegis256BsEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("754fc3d8c973246dcc6d741412a4b236");
		expect(bytesToHex(tag)).toBe("3fe91994768b332ed7f570a19ec5896e");
	});

	test("Test Vector 1 - 256-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const { ciphertext, tag } = aegis256BsEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			32,
		);

		expect(bytesToHex(ciphertext)).toBe("754fc3d8c973246dcc6d741412a4b236");
		expect(bytesToHex(tag)).toBe(
			"1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13",
		);
	});

	test("Test Vector 2 - empty message, 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis256BsEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe("e3def978a0f054afd1e761d7553afba3");
	});

	test("Test Vector 3 - with AD, 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const { ciphertext, tag } = aegis256BsEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe(
			"f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
		);
		expect(bytesToHex(tag)).toBe("8d86f91ee606e9ff26a01b64ccbdd91d");
	});

	test("Test Vector 4 - partial block, 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes("000102030405060708090a0b0c0d");

		const { ciphertext, tag } = aegis256BsEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("f373079ed84b2709faee37358458");
		expect(bytesToHex(tag)).toBe("c60b9c2d33ceb058f96e6dd03c215652");
	});

	test("Test Vector 5 - long message and AD", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
		);
		const msg = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
		);

		const { ciphertext, tag } = aegis256BsEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe(
			"57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67",
		);
		expect(bytesToHex(tag)).toBe("ab8a7d53fd0e98d727accca94925e128");
	});
});

describe("AEGIS-256 Bitsliced Decrypt Detached", () => {
	test("Decrypt Test Vector 1", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const ct = hexToBytes("754fc3d8c973246dcc6d741412a4b236");
		const tag = hexToBytes("3fe91994768b332ed7f570a19ec5896e");

		const msg = aegis256BsDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe("00000000000000000000000000000000");
	});

	test("Decrypt Test Vector 4 - partial block", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("f373079ed84b2709faee37358458");
		const tag = hexToBytes("c60b9c2d33ceb058f96e6dd03c215652");

		const msg = aegis256BsDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe("000102030405060708090a0b0c0d");
	});

	test("Test Vector 6 - wrong key", () => {
		const key = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("f373079ed84b2709faee37358458");
		const tag = hexToBytes("c60b9c2d33ceb058f96e6dd03c215652");

		const msg = aegis256BsDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});

	test("Test Vector 7 - wrong ciphertext", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("f373079ed84b2709faee37358459");
		const tag = hexToBytes("c60b9c2d33ceb058f96e6dd03c215652");

		const msg = aegis256BsDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});

	test("Test Vector 8 - wrong AD", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050608");
		const ct = hexToBytes("f373079ed84b2709faee37358458");
		const tag = hexToBytes("c60b9c2d33ceb058f96e6dd03c215652");

		const msg = aegis256BsDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});

	test("Test Vector 9 - wrong tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("f373079ed84b2709faee37358458");
		const tag = hexToBytes("7a348c930adbd654896e1666aad67de0");

		const msg = aegis256BsDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});
});

describe("AEGIS-256 Bitsliced Encrypt/Decrypt (combined)", () => {
	test("Roundtrip with 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes("000102030405060708090a0b0c0d0e0f");

		const sealed = aegis256BsEncrypt(msg, ad, key, nonce, 16);

		expect(sealed.length).toBe(AEGIS_256_BS_NONCE_SIZE + msg.length + 16);

		const decrypted = aegis256BsDecrypt(sealed, ad, key, 16);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe(bytesToHex(msg));
	});

	test("Roundtrip with 256-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const sealed = aegis256BsEncrypt(msg, ad, key, nonce, 32);

		expect(sealed.length).toBe(AEGIS_256_BS_NONCE_SIZE + msg.length + 32);

		const decrypted = aegis256BsDecrypt(sealed, ad, key, 32);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe(bytesToHex(msg));
	});

	test("Roundtrip with empty message", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const sealed = aegis256BsEncrypt(msg, ad, key, nonce, 16);

		expect(sealed.length).toBe(AEGIS_256_BS_NONCE_SIZE + 16);

		const decrypted = aegis256BsDecrypt(sealed, ad, key, 16);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe("");
	});

	test("Decrypt returns null for too-short input", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");

		const decrypted = aegis256BsDecrypt(new Uint8Array(31), ad, key, 16);
		expect(decrypted).toBeNull();
	});

	test("Decrypt returns null for tampered ciphertext", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const sealed = aegis256BsEncrypt(msg, ad, key, nonce, 16);
		sealed[AEGIS_256_BS_NONCE_SIZE] ^= 1;

		const decrypted = aegis256BsDecrypt(sealed, ad, key, 16);
		expect(decrypted).toBeNull();
	});
});

describe("AEGISMAC-256 Bitsliced", () => {
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

		const tag = aegis256BsMac(data, key, nonce, 16);

		expect(bytesToHex(tag)).toBe("c08e20cfc56f27195a46c9cef5c162d4");
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

		const tag = aegis256BsMac(data, key, nonce, 32);

		expect(bytesToHex(tag)).toBe(
			"a5c906ede3d69545c11e20afa360b221f936e946ed2dba3d7c75ad6dc2784126",
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
		const tag = hexToBytes("c08e20cfc56f27195a46c9cef5c162d4");

		expect(aegis256BsMacVerify(data, tag, key, nonce)).toBe(true);
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
		const tag = hexToBytes("8441d68a83671d6c24ab93cf39c98c1a");

		expect(aegis256BsMacVerify(data, tag, key, nonce)).toBe(false);
	});
});

describe("AEGIS-256-BS In-Place Encryption/Decryption", () => {
	test("In-place encrypt produces same ciphertext as regular encrypt", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const { ciphertext: expected, tag: expectedTag } =
			aegis256BsEncryptDetached(msg, ad, key, nonce, 16);

		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		const tag = aegis256BsEncryptDetachedInPlace(data, ad, key, nonce, 16);

		expect(bytesToHex(data)).toBe(bytesToHex(expected));
		expect(bytesToHex(tag)).toBe(bytesToHex(expectedTag));
	});

	test("In-place roundtrip", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const originalMsg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const data = new Uint8Array(originalMsg);
		const tag = aegis256BsEncryptDetachedInPlace(data, ad, key, nonce, 16);

		const result = aegis256BsDecryptDetachedInPlace(data, tag, ad, key, nonce);
		expect(result).toBe(true);
		expect(bytesToHex(data)).toBe(bytesToHex(originalMsg));
	});

	test("In-place decrypt fails with wrong tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
		aegis256BsEncryptDetachedInPlace(data, ad, key, nonce, 16);

		const wrongTag = new Uint8Array(16);
		const result = aegis256BsDecryptDetachedInPlace(
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
