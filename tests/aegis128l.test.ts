import { describe, expect, test } from "bun:test";
import {
	AEGIS_128L_NONCE_SIZE,
	Aegis128LState,
	aegis128LDecrypt,
	aegis128LDecryptDetached,
	aegis128LEncrypt,
	aegis128LEncryptDetached,
	aegis128LMac,
	aegis128LMacVerify,
} from "../src/aegis128l.ts";

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

describe("AEGIS-128L Update", () => {
	test("Update test vector", () => {
		const state = new Aegis128LState();
		(state as any).s = [
			hexToBytes("9b7e60b24cc873ea894ecc07911049a3"),
			hexToBytes("330be08f35300faa2ebf9a7b0d274658"),
			hexToBytes("7bbd5bd2b049f7b9b515cf26fbe7756c"),
			hexToBytes("c35a00f55ea86c3886ec5e928f87db18"),
			hexToBytes("9ebccafce87cab446396c4334592c91f"),
			hexToBytes("58d83e31f256371e60fc6bb257114601"),
			hexToBytes("1639b56ea322c88568a176585bc915de"),
			hexToBytes("640818ffb57dc0fbc2e72ae93457e39a"),
		];

		const m0 = hexToBytes("033e6975b94816879e42917650955aa0");
		const m1 = hexToBytes("fcc1968a46b7e97861bd6e89af6aa55f");
		state.update(m0, m1);

		expect(bytesToHex((state as any).s[0])).toBe(
			"596ab773e4433ca0127c73f60536769d",
		);
		expect(bytesToHex((state as any).s[1])).toBe(
			"790394041a3d26ab697bde865014652d",
		);
		expect(bytesToHex((state as any).s[2])).toBe(
			"38cf49e4b65248acd533041b64dd0611",
		);
		expect(bytesToHex((state as any).s[3])).toBe(
			"16d8e58748f437bfff1797f780337cee",
		);
		expect(bytesToHex((state as any).s[4])).toBe(
			"9689ecdf08228c74d7e3360cca53d0a5",
		);
		expect(bytesToHex((state as any).s[5])).toBe(
			"a21746bb193a569e331e1aa985d0d729",
		);
		expect(bytesToHex((state as any).s[6])).toBe(
			"09d714e6fcf9177a8ed1cde7e3d259a6",
		);
		expect(bytesToHex((state as any).s[7])).toBe(
			"61279ba73167f0ab76f0a11bf203bdff",
		);
	});
});

describe("AEGIS-128L Encrypt Detached", () => {
	test("Test Vector 1 - 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const { ciphertext, tag } = aegis128LEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("c1c0e58bd913006feba00f4b3cc3594e");
		expect(bytesToHex(tag)).toBe("abe0ece80c24868a226a35d16bdae37a");
	});

	test("Test Vector 1 - 256-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const { ciphertext, tag } = aegis128LEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			32,
		);

		expect(bytesToHex(ciphertext)).toBe("c1c0e58bd913006feba00f4b3cc3594e");
		expect(bytesToHex(tag)).toBe(
			"25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4",
		);
	});

	test("Test Vector 2 - empty message, 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const { ciphertext, tag } = aegis128LEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("");
		expect(bytesToHex(tag)).toBe("c2b879a67def9d74e6c14f708bbcc9b4");
	});

	test("Test Vector 3 - with AD, 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const { ciphertext, tag } = aegis128LEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe(
			"79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
		);
		expect(bytesToHex(tag)).toBe("cc6f3372f6aa1bb82388d695c3962d9a");
	});

	test("Test Vector 4 - partial block, 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes("000102030405060708090a0b0c0d");

		const { ciphertext, tag } = aegis128LEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe("79d94593d8c2119d7e8fd9b8fc77");
		expect(bytesToHex(tag)).toBe("5c04b3dba849b2701effbe32c7f0fab7");
	});

	test("Test Vector 5 - long message and AD", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
		);
		const msg = hexToBytes(
			"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
		);

		const { ciphertext, tag } = aegis128LEncryptDetached(
			msg,
			ad,
			key,
			nonce,
			16,
		);

		expect(bytesToHex(ciphertext)).toBe(
			"b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
		);
		expect(bytesToHex(tag)).toBe("7542a745733014f9474417b337399507");
	});
});

describe("AEGIS-128L Decrypt Detached", () => {
	test("Decrypt Test Vector 3", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes(
			"79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
		);
		const tag = hexToBytes("cc6f3372f6aa1bb82388d695c3962d9a");

		const msg = aegis128LDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);
	});

	test("Decrypt Test Vector 4 - partial block", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("79d94593d8c2119d7e8fd9b8fc77");
		const tag = hexToBytes("5c04b3dba849b2701effbe32c7f0fab7");

		const msg = aegis128LDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).not.toBeNull();
		expect(bytesToHex(msg!)).toBe("000102030405060708090a0b0c0d");
	});

	test("Test Vector 6 - wrong key", () => {
		const key = hexToBytes("10000200000000000000000000000000");
		const nonce = hexToBytes("10010000000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("79d94593d8c2119d7e8fd9b8fc77");
		const tag = hexToBytes("5c04b3dba849b2701effbe32c7f0fab7");

		const msg = aegis128LDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});

	test("Test Vector 7 - wrong ciphertext", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("79d94593d8c2119d7e8fd9b8fc78");
		const tag = hexToBytes("5c04b3dba849b2701effbe32c7f0fab7");

		const msg = aegis128LDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});

	test("Test Vector 8 - wrong AD", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050608");
		const ct = hexToBytes("79d94593d8c2119d7e8fd9b8fc77");
		const tag = hexToBytes("5c04b3dba849b2701effbe32c7f0fab7");

		const msg = aegis128LDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});

	test("Test Vector 9 - wrong tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const ct = hexToBytes("79d94593d8c2119d7e8fd9b8fc77");
		const tag = hexToBytes("6c04b3dba849b2701effbe32c7f0fab8");

		const msg = aegis128LDecryptDetached(ct, tag, ad, key, nonce);

		expect(msg).toBeNull();
	});
});

describe("AEGIS-128L Encrypt/Decrypt (combined)", () => {
	test("Roundtrip with 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("0001020304050607");
		const msg = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		);

		const sealed = aegis128LEncrypt(msg, ad, key, nonce, 16);

		expect(sealed.length).toBe(AEGIS_128L_NONCE_SIZE + msg.length + 16);

		const decrypted = aegis128LDecrypt(sealed, ad, key, 16);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe(bytesToHex(msg));
	});

	test("Roundtrip with 256-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const sealed = aegis128LEncrypt(msg, ad, key, nonce, 32);

		expect(sealed.length).toBe(AEGIS_128L_NONCE_SIZE + msg.length + 32);

		const decrypted = aegis128LDecrypt(sealed, ad, key, 32);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe(bytesToHex(msg));
	});

	test("Roundtrip with empty message", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("");
		const msg = hexToBytes("");

		const sealed = aegis128LEncrypt(msg, ad, key, nonce, 16);

		expect(sealed.length).toBe(AEGIS_128L_NONCE_SIZE + 16);

		const decrypted = aegis128LDecrypt(sealed, ad, key, 16);

		expect(decrypted).not.toBeNull();
		expect(bytesToHex(decrypted!)).toBe("");
	});

	test("Decrypt returns null for too-short input", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const ad = hexToBytes("");

		const decrypted = aegis128LDecrypt(new Uint8Array(15), ad, key, 16);
		expect(decrypted).toBeNull();
	});

	test("Decrypt returns null for tampered ciphertext", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const ad = hexToBytes("");
		const msg = hexToBytes("00000000000000000000000000000000");

		const sealed = aegis128LEncrypt(msg, ad, key, nonce, 16);
		sealed[AEGIS_128L_NONCE_SIZE] ^= 1;

		const decrypted = aegis128LDecrypt(sealed, ad, key, 16);
		expect(decrypted).toBeNull();
	});
});

describe("AEGISMAC-128L", () => {
	test("Test Vector - 128-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis128LMac(data, key, nonce, 16);

		expect(bytesToHex(tag)).toBe("d3f09b2842ad301687d6902c921d7818");
	});

	test("Test Vector - 256-bit tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);

		const tag = aegis128LMac(data, key, nonce, 32);

		expect(bytesToHex(tag)).toBe(
			"9490e7c89d420c9f37417fa625eb38e8cad53c5cbec55285e8499ea48377f2a3",
		);
	});

	test("Verify valid tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("d3f09b2842ad301687d6902c921d7818");

		expect(aegis128LMacVerify(data, tag, key, nonce)).toBe(true);
	});

	test("Reject invalid tag", () => {
		const key = hexToBytes("10010000000000000000000000000000");
		const nonce = hexToBytes("10000200000000000000000000000000");
		const data = hexToBytes(
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
		);
		const tag = hexToBytes("d3f09b2842ad301687d6902c921d7819");

		expect(aegis128LMacVerify(data, tag, key, nonce)).toBe(false);
	});
});
