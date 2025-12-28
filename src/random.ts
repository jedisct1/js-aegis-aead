/**
 * Cross-platform cryptographically secure random byte generation.
 *
 * Uses the Web Crypto API (globalThis.crypto.getRandomValues) which is available in:
 * - All modern browsers
 * - Node.js 19+
 * - Deno
 * - Bun
 *
 * For older Node.js versions, you can polyfill:
 * ```
 * globalThis.crypto = require('crypto').webcrypto;
 * ```
 */

function getCrypto(): Crypto {
	if (
		typeof globalThis !== "undefined" &&
		globalThis.crypto &&
		typeof globalThis.crypto.getRandomValues === "function"
	) {
		return globalThis.crypto;
	}
	throw new Error(
		"No cryptographic random source available. " +
			"In older Node.js versions, use: globalThis.crypto = require('crypto').webcrypto",
	);
}

/**
 * Generates cryptographically secure random bytes.
 * @param length - Number of random bytes to generate
 * @returns Uint8Array of random bytes
 * @throws Error if no cryptographic random source is available
 */
export function randomBytes(length: number): Uint8Array {
	const crypto = getCrypto();
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return bytes;
}
