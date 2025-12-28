import { describe, expect, test } from "bun:test";
import {
	AEGIS_256_NONCE_SIZE,
	Aegis256State,
	aegis256Decrypt,
	aegis256DecryptDetached,
	aegis256Encrypt,
	aegis256EncryptDetached,
	aegis256Mac,
	aegis256MacVerify,
} from "../src/aegis256.ts";

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

describe("AEGIS-256 Update", () => {
	test("Update test vector", () => {
		const state = new Aegis256State();
		(state as any).s = [
			hexToBytes("1fa1207ed76c86f2c4bb40e8b395b43e"),
			hexToBytes("b44c375e6c1e1978db64bcd12e9e332f"),
			hexToBytes("0dab84bfa9f0226432ff630f233d4e5b"),
			hexToBytes("d7ef65c9b93e8ee60c75161407b066e7"),
			hexToBytes("a760bb3da073fbd92bdc24734b1f56fb"),
			hexToBytes("a828a18d6a964497ac6e7e53c5f55c73"),
		];

		const m = hexToBytes("b165617ed04ab738afb2612c6d18a1ec");
		state.update(m);

		expect(bytesToHex((state as any).s[0])).toBe(
			"e6bc643bae82dfa3d991b1b323839dcd",
		);
		expect(bytesToHex((state as any).s[1])).toBe(
			"648578232ba0f2f0a3677f617dc052c3",
		);
		expect(bytesToHex((state as any).s[2])).toBe(
			"ea788e0e572044a46059212dd007a789",
		);
		expect(bytesToHex((state as any).s[3])).toBe(
			"2f1498ae19b80da13fba698f088a8590",
		);
		expect(bytesToHex((state as any).s[4])).toBe(
			"a54c2ee95e8c2a2c3dae2ec743ae6b86",
		);
		expect(bytesToHex((state as any).s[5])).toBe(
			"a3240fceb68e32d5d114df1b5363ab67",
		);
	});
});

describe("AEGIS-256 Encrypt Detached", () => {
	test("Test Vector 1 - 128-bit tag", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const { ciphertext, tag } = aegis256EncryptDetached(
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

		const { ciphertext, tag } = aegis256EncryptDetached(
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

	test("Test Vector 2 - empty message", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis256EncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe("e3def978a0f054afd1e761d7553afba3");
	});

	test("Test Vector 3 - with AD", () => {
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

		const { ciphertext, tag } = aegis256EncryptDetached(
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

	test("Test Vector 4 - partial block", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes("000102030405060708090a0b0c0d");

		const { ciphertext, tag } = aegis256EncryptDetached(
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

		const { ciphertext, tag } = aegis256EncryptDetached(
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

describe("AEGIS-256 Decrypt Detached", () => {
	test("Decrypt Test Vector 3", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const nonce = hexToBytes(
			"1000020000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes(
			"f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
		);
		const tag = hexToBytes("8d86f91ee606e9ff26a01b64ccbdd91d");

		const msg = aegis256DecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
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

		const msg = aegis256DecryptDetached(ct, tag, ad, key, nonce);

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

		const msg = aegis256DecryptDetached(ct, tag, ad, key, nonce);

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

		const msg = aegis256DecryptDetached(ct, tag, ad, key, nonce);

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

		const msg = aegis256DecryptDetached(ct, tag, ad, key, nonce);

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
		const tag = hexToBytes("c60b9c2d33ceb058f96e6dd03c215653");

		const msg = aegis256DecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});
});

describe("AEGIS-256 Encrypt/Decrypt (combined)", () => {
	test("Roundtrip with 128-bit tag", () => {
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

		const sealed = aegis256Encrypt(msg, ad, key, nonce, 16);

		expect(sealed.length).toBe(AEGIS_256_NONCE_SIZE + msg.length + 16);

		const decrypted = aegis256Decrypt(sealed, ad, key, 16);

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

		const sealed = aegis256Encrypt(msg, ad, key, nonce, 32);

		expect(sealed.length).toBe(AEGIS_256_NONCE_SIZE + msg.length + 32);

		const decrypted = aegis256Decrypt(sealed, ad, key, 32);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe(bytesToHex(msg));
	});

	test("Decrypt returns null for too-short input", () => {
		const key = hexToBytes(
			"1001000000000000000000000000000000000000000000000000000000000000",
		);
		const ad = hexToBytes("");

		const decrypted = aegis256Decrypt(new Uint8Array(31), ad, key, 16);
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

		const sealed = aegis256Encrypt(msg, ad, key, nonce, 16);
		sealed[AEGIS_256_NONCE_SIZE] ^= 1;

		const decrypted = aegis256Decrypt(sealed, ad, key, 16);
		expect(decrypted).toBeNull();
	});
});

describe("AEGISMAC-256", () => {
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

		const tag = aegis256Mac(data, key, nonce, 16);

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

		const tag = aegis256Mac(data, key, nonce, 32);

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

		expect(aegis256MacVerify(data, tag, key, nonce)).toBe(true);
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
		const tag = hexToBytes("c08e20cfc56f27195a46c9cef5c162d5");

		expect(aegis256MacVerify(data, tag, key, nonce)).toBe(false);
	});
});
