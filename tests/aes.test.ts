import { describe, expect, test } from "bun:test";
import {
	aegisRound128,
	blockFromBytes,
	blocksPut,
	blockToBytes,
	createAesBlock,
	createAesBlocks,
	pack,
	unpack,
	wordIdx,
} from "../src/aes-bs.ts";

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

describe("Bitsliced AES", () => {
	test("AESRound test vector from spec", () => {
		// With a zero constant input, the AEGIS round computes
		// block1' = AESRound(block0, block1), which is exactly the
		// AESRound(in, rk) function from the specification.
		const input = createAesBlock();
		const rk = createAesBlock();
		blockFromBytes(input, hexToBytes("000102030405060708090a0b0c0d0e0f"));
		blockFromBytes(rk, hexToBytes("101112131415161718191a1b1c1d1e1f"));

		const st = createAesBlocks();
		blocksPut(st, input, 0);
		blocksPut(st, rk, 1);
		pack(st);

		const zeroInput = createAesBlocks();
		aegisRound128(st, zeroInput);
		unpack(st);

		const w = createAesBlock();
		for (let j = 0; j < 4; j++) w[j] = st[wordIdx(1, j)]!;
		const out = new Uint8Array(16);
		blockToBytes(out, w);

		expect(bytesToHex(out)).toBe("7a7b4e5638782546a8c0477a3b813f43");
	});

	test("pack/unpack roundtrip", () => {
		const st = createAesBlocks();
		for (let i = 0; i < 32; i++) {
			st[i] = (i * 0x9e3779b9) >>> 0;
		}
		const original = new Uint32Array(st);

		pack(st);
		unpack(st);

		expect(Array.from(st)).toEqual(Array.from(original));
	});
});
