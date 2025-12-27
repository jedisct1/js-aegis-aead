import { describe, expect, test } from "bun:test";
import { aesRound } from "../src/aes.ts";

function hexToBytes(hex: string): Uint8Array {
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

describe("AES Round", () => {
	test("AESRound test vector from spec", () => {
		const input = hexToBytes("000102030405060708090a0b0c0d0e0f");
		const rk = hexToBytes("101112131415161718191a1b1c1d1e1f");
		const expected = "7a7b4e5638782546a8c0477a3b813f43";

		const result = aesRound(input, rk);
		expect(bytesToHex(result)).toBe(expected);
	});
});
