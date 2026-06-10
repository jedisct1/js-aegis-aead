/**
 * Pads data with zeros to a multiple of the block size.
 * @param data - Input data
 * @param blockSizeBytes - Block size in bytes
 * @returns Padded data (or empty array if data is empty)
 */
export function zeroPad(
	data: ArrayLike<number>,
	blockSizeBytes: number,
): Uint8Array {
	if (data.length === 0) return new Uint8Array(0);
	const paddedLen = Math.ceil(data.length / blockSizeBytes) * blockSizeBytes;
	if (paddedLen === data.length) return new Uint8Array(data);
	const padded = new Uint8Array(paddedLen);
	padded.set(data);
	return padded;
}

/**
 * Compares two byte arrays in constant time to prevent timing attacks.
 * @param a - First byte array
 * @param b - Second byte array
 * @returns True if arrays are equal, false otherwise
 */
export function constantTimeEqual(
	a: ArrayLike<number>,
	b: ArrayLike<number>,
): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i]! ^ b[i]!;
	}
	return diff === 0;
}
