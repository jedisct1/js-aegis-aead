declare global {
	interface Uint8ArrayConstructor {
		new (length: number): Uint8Array;
		new (array: ArrayLike<number> | ArrayBufferLike): Uint8Array;
		new (
			buffer: ArrayBufferLike,
			byteOffset?: number,
			length?: number,
		): Uint8Array;
	}

	interface Uint8Array {
		subarray(begin?: number, end?: number): Uint8Array;
		slice(start?: number, end?: number): Uint8Array;
	}
}

export {};
