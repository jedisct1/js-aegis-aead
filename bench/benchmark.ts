import {
	aegis128LEncrypt,
	aegis128X2Encrypt,
	aegis128X4Encrypt,
	aegis256Encrypt,
	aegis256X2Encrypt,
	aegis256X4Encrypt,
} from "../src/index.ts";

const SIZES = [64, 1024, 16384, 1048576];

function formatSize(bytes: number): string {
	if (bytes >= 1048576) return `${bytes / 1048576}MB`;
	if (bytes >= 1024) return `${bytes / 1024}KB`;
	return `${bytes}B`;
}

function formatThroughput(bytesPerSecond: number): string {
	if (bytesPerSecond >= 1e9) return `${(bytesPerSecond / 1e9).toFixed(2)} GB/s`;
	if (bytesPerSecond >= 1e6) return `${(bytesPerSecond / 1e6).toFixed(2)} MB/s`;
	if (bytesPerSecond >= 1e3) return `${(bytesPerSecond / 1e3).toFixed(2)} KB/s`;
	return `${bytesPerSecond.toFixed(2)} B/s`;
}

function benchmark(
	name: string,
	fn: () => void,
	msgSize: number,
	warmupMs = 100,
	runMs = 1000,
): { opsPerSec: number; throughput: number } {
	const warmupEnd = performance.now() + warmupMs;
	while (performance.now() < warmupEnd) {
		fn();
	}

	let ops = 0;
	const start = performance.now();
	const end = start + runMs;
	while (performance.now() < end) {
		fn();
		ops++;
	}
	const elapsed = performance.now() - start;
	const opsPerSec = (ops / elapsed) * 1000;
	const throughput = opsPerSec * msgSize;

	return { opsPerSec, throughput };
}

const key16 = new Uint8Array(16);
const key32 = new Uint8Array(32);
const nonce16 = new Uint8Array(16);
const nonce32 = new Uint8Array(32);
const ad = new Uint8Array(0);

crypto.getRandomValues(key16);
crypto.getRandomValues(key32);
crypto.getRandomValues(nonce16);
crypto.getRandomValues(nonce32);

const variants = [
	{
		name: "AEGIS-128L",
		fn: (msg: Uint8Array) => aegis128LEncrypt(msg, ad, key16, nonce16),
	},
	{
		name: "AEGIS-256",
		fn: (msg: Uint8Array) => aegis256Encrypt(msg, ad, key32, nonce32),
	},
	{
		name: "AEGIS-128X2",
		fn: (msg: Uint8Array) => aegis128X2Encrypt(msg, ad, key16, nonce16),
	},
	{
		name: "AEGIS-128X4",
		fn: (msg: Uint8Array) => aegis128X4Encrypt(msg, ad, key16, nonce16),
	},
	{
		name: "AEGIS-256X2",
		fn: (msg: Uint8Array) => aegis256X2Encrypt(msg, ad, key32, nonce32),
	},
	{
		name: "AEGIS-256X4",
		fn: (msg: Uint8Array) => aegis256X4Encrypt(msg, ad, key32, nonce32),
	},
];

console.log("AEGIS Benchmark\n");
console.log("=".repeat(70));

for (const size of SIZES) {
	const msg = new Uint8Array(size);
	crypto.getRandomValues(msg);

	console.log(`\nMessage size: ${formatSize(size)}`);
	console.log("-".repeat(70));
	console.log(
		`${"Algorithm".padEnd(20)} ${"ops/sec".padStart(15)} ${"throughput".padStart(15)}`,
	);
	console.log("-".repeat(70));

	for (const variant of variants) {
		const { opsPerSec, throughput } = benchmark(
			variant.name,
			() => variant.fn(msg),
			size,
		);
		console.log(
			`${variant.name.padEnd(20)} ${opsPerSec.toFixed(0).padStart(15)} ${formatThroughput(throughput).padStart(15)}`,
		);
	}
}

console.log("\n" + "=".repeat(70));
