/**
 * Generator for the hot-path functions of src/aes-bs.ts.
 *
 * Everything below the marker comment in src/aes-bs.ts is produced by this
 * script; run `bun scripts/gen-aes-bs.ts && bun run format` to regenerate
 * after changing it.
 *
 * Emits fully unrolled, allocation-free code derived from the reference C
 * implementation of bitsliced AEGIS (aes-bs8.h, permuted scalar layout).
 * Three families of functions are produced:
 *
 * - aegisRound128 / aegisRound256: fused SubBytes + ShiftRows + MixColumns +
 *   AEGIS block rotation + state/constant-input XOR over local variables.
 * - packConstantInput128 / packConstantInput256: pack04 / pack04_6 with
 *   zero-tracking (the input state is sparse, so most swapmoves simplify).
 * - keystream128 / keystream256: keystream mask + unpack04 / unpack04_6
 *   sliced by backward liveness so only the words feeding the extracted
 *   blocks are computed.
 */

type Op = [number, number, number, number]; // aIdx, bIdx, mask, shift

function hex(n: number): string {
	return `0x${(n >>> 0).toString(16).padStart(8, "0")}`;
}

// Swapmove op lists, transcribed from the C reference (new permuted layout).

function pack04Ops(): Op[] {
	const ops: Op[] = [
		[0, 1, 0x00ff00ff, 8],
		[2, 3, 0x00ff00ff, 8],
		[16, 17, 0x00ff00ff, 8],
		[18, 19, 0x00ff00ff, 8],
		[0, 2, 0x0000ffff, 16],
		[16, 18, 0x0000ffff, 16],
		[1, 3, 0x0000ffff, 16],
		[17, 19, 0x0000ffff, 16],
	];
	for (let i = 0; i < 4; i++) {
		ops.push(
			[i + 4, i, 0x55555555, 1],
			[i + 20, i + 16, 0x55555555, 1],
			[i + 8, i, 0x33333333, 2],
			[i + 12, i + 4, 0x33333333, 2],
			[i + 24, i + 16, 0x33333333, 2],
			[i + 28, i + 20, 0x33333333, 2],
			[i + 16, i, 0x0f0f0f0f, 4],
			[i + 20, i + 4, 0x0f0f0f0f, 4],
			[i + 24, i + 8, 0x0f0f0f0f, 4],
			[i + 28, i + 12, 0x0f0f0f0f, 4],
		);
	}
	return ops;
}

function unpack04Ops(): Op[] {
	const ops: Op[] = [];
	for (let i = 0; i < 4; i++) {
		ops.push(
			[i + 28, i + 12, 0x0f0f0f0f, 4],
			[i + 24, i + 8, 0x0f0f0f0f, 4],
			[i + 20, i + 4, 0x0f0f0f0f, 4],
			[i + 16, i, 0x0f0f0f0f, 4],
			[i + 28, i + 20, 0x33333333, 2],
			[i + 24, i + 16, 0x33333333, 2],
			[i + 12, i + 4, 0x33333333, 2],
			[i + 8, i, 0x33333333, 2],
			[i + 20, i + 16, 0x55555555, 1],
			[i + 4, i, 0x55555555, 1],
		);
	}
	ops.push(
		[17, 19, 0x0000ffff, 16],
		[1, 3, 0x0000ffff, 16],
		[16, 18, 0x0000ffff, 16],
		[0, 2, 0x0000ffff, 16],
		[18, 19, 0x00ff00ff, 8],
		[16, 17, 0x00ff00ff, 8],
		[2, 3, 0x00ff00ff, 8],
		[0, 1, 0x00ff00ff, 8],
	);
	return ops;
}

function pack04_6Ops(): Op[] {
	const ops: Op[] = [
		[0, 1, 0x00ff00ff, 8],
		[2, 3, 0x00ff00ff, 8],
		[0, 2, 0x0000ffff, 16],
		[1, 3, 0x0000ffff, 16],
	];
	for (let i = 0; i < 4; i++) {
		ops.push(
			[i + 4, i, 0x55555555, 1],
			[i + 8, i, 0x33333333, 2],
			[i + 12, i + 4, 0x33333333, 2],
			[i + 16, i, 0x0f0f0f0f, 4],
			[i + 20, i + 4, 0x0f0f0f0f, 4],
			[i + 24, i + 8, 0x0f0f0f0f, 4],
			[i + 28, i + 12, 0x0f0f0f0f, 4],
		);
	}
	return ops;
}

function unpack04_6Ops(): Op[] {
	const ops: Op[] = [];
	for (let i = 0; i < 4; i++) {
		ops.push(
			[i + 28, i + 12, 0x0f0f0f0f, 4],
			[i + 24, i + 8, 0x0f0f0f0f, 4],
			[i + 20, i + 4, 0x0f0f0f0f, 4],
			[i + 16, i, 0x0f0f0f0f, 4],
			[i + 12, i + 4, 0x33333333, 2],
			[i + 8, i, 0x33333333, 2],
			[i + 4, i, 0x55555555, 1],
		);
	}
	ops.push(
		[1, 3, 0x0000ffff, 16],
		[0, 2, 0x0000ffff, 16],
		[2, 3, 0x00ff00ff, 8],
		[0, 1, 0x00ff00ff, 8],
	);
	return ops;
}

/**
 * Pack with zero-tracking: cells start as either an expression or null (zero).
 * Swapmoves over zero operands are simplified or skipped.
 */
function genPackConstantInput(
	name: string,
	params: string,
	initCells: (string | null)[],
	ops: Op[],
	doc: string,
): string {
	const cells = initCells.slice();
	const lines: string[] = [];
	let n = 0;
	for (const [a, b, mask, sh] of ops) {
		const ca = cells[a] ?? null;
		const cb = cells[b] ?? null;
		if (ca === null && cb === null) continue;
		if (ca === null) {
			const t = `t${n++}`;
			lines.push(`const ${t} = ${cb} & ${hex(mask)};`);
			const nb = `t${n++}`;
			lines.push(`const ${nb} = ${cb} ^ ${t};`);
			const na = `t${n++}`;
			lines.push(`const ${na} = ${t} << ${sh};`);
			cells[b] = nb;
			cells[a] = na;
		} else if (cb === null) {
			const t = `t${n++}`;
			lines.push(`const ${t} = (${ca} >>> ${sh}) & ${hex(mask)};`);
			const na = `t${n++}`;
			lines.push(`const ${na} = ${ca} ^ (${t} << ${sh});`);
			cells[b] = t;
			cells[a] = na;
		} else {
			const t = `t${n++}`;
			lines.push(`const ${t} = (${cb} ^ (${ca} >>> ${sh})) & ${hex(mask)};`);
			const nb = `t${n++}`;
			lines.push(`const ${nb} = ${cb} ^ ${t};`);
			const na = `t${n++}`;
			lines.push(`const ${na} = ${ca} ^ (${t} << ${sh});`);
			cells[b] = nb;
			cells[a] = na;
		}
	}
	const stores: string[] = [];
	for (let i = 0; i < 32; i++) {
		stores.push(`out[${i}] = ${cells[i] ?? "0"};`);
	}
	return `${doc}
export function ${name}(${params}): void {
${[...lines, ...stores].map((l) => `\t${l}`).join("\n")}
}
`;
}

/**
 * Keystream extraction: apply the keystream bit-combination to every packed
 * word, then run the unpack network restricted (by backward liveness) to the
 * words that feed the extracted output blocks.
 */
function genKeystream(
	name: string,
	params: string,
	formula: (x: string) => string,
	ops: Op[],
	liveOut: number[],
	outWrites: (cells: string[]) => string[],
	doc: string,
): string {
	// Backward liveness over the swapmove list.
	const live = new Set<number>(liveOut);
	const kept: { op: Op; aOut: boolean; bOut: boolean }[] = [];
	for (let i = ops.length - 1; i >= 0; i--) {
		const op = ops[i]!;
		const [a, b] = op;
		const aOut = live.has(a);
		const bOut = live.has(b);
		if (!aOut && !bOut) continue;
		kept.unshift({ op, aOut, bOut });
		live.add(a);
		live.add(b);
	}
	// `live` now holds every cell whose initial value is needed.
	const cells: string[] = [];
	const lines: string[] = [];
	const liveIn = [...live].sort((x, y) => x - y);
	for (const i of liveIn) {
		lines.push(`const x${i} = st[${i}]!;`);
		lines.push(`const c${i} = ${formula(`x${i}`)};`);
		cells[i] = `c${i}`;
	}
	let n = 0;
	for (const { op, aOut, bOut } of kept) {
		const [a, b, mask, sh] = op;
		const t = `t${n++}`;
		lines.push(
			`const ${t} = (${cells[b]} ^ (${cells[a]} >>> ${sh})) & ${hex(mask)};`,
		);
		if (bOut) {
			const nb = `t${n++}`;
			lines.push(`const ${nb} = ${cells[b]} ^ ${t};`);
			cells[b] = nb;
		}
		if (aOut) {
			const na = `t${n++}`;
			lines.push(`const ${na} = ${cells[a]} ^ (${t} << ${sh});`);
			cells[a] = na;
		}
	}
	lines.push(...outWrites(cells));
	return `${doc}
export function ${name}(${params}): void {
${lines.map((l) => `\t${l}`).join("\n")}
}
`;
}

// S-box circuit (Maximov & Ekdahl), identical to the previous JS version but
// reading the permuted layout: plane k of group $ lives at word 4k + $.
// `$` is replaced by the group suffix.
const SBOX_TEMPLATE = `
const z24$ = u3$ ^ u4$;
const q17$ = u1$ ^ u7$;
const q16$ = u5$ ^ q17$;
const q0$ = z24$ ^ q16$;
const q7$ = z24$ ^ u1$ ^ u6$;
const q2$ = u2$ ^ q0$;
const q1$ = q7$ ^ q2$;
const q3$ = u0$ ^ q7$;
const q4$ = u0$ ^ q2$;
const q5$ = u1$ ^ q4$;
const q6$ = u2$ ^ u3$;
const q10$ = q6$ ^ q7$;
const q8$ = u0$ ^ q10$;
const q9$ = q8$ ^ q2$;
const q12$ = z24$ ^ q17$;
const q15$ = u7$ ^ q4$;
const m02$ = u0$ ^ u2$;
const m15$ = u1$ ^ u5$;
const q13$ = m02$ ^ m15$;
const q14$ = m02$ ^ u7$;
const q11$ = u5$;
const t20$ = q6$ & q12$;
const t21$ = q3$ & q14$;
const t22$ = q1$ & q16$;
const t23$ = q2$ & q17$;
const x0$ = (q3$ | q14$) ^ (q0$ & q7$) ^ (t20$ ^ t22$);
const x1$ = (q4$ | q13$) ^ (q10$ & q11$) ^ (t21$ ^ t20$);
const x2$ = (q2$ | q17$) ^ (q5$ & q9$) ^ (t21$ ^ t22$);
const x3$ = (q8$ | q15$) ^ t23$ ^ (t21$ ^ (q4$ & q13$));
const va$ = x1$ & ~x3$;
const vb$ = x0$ & ~x3$;
const vc$ = x3$ & ~x1$;
const vd$ = x2$ & ~x1$;
const ve$ = x0$ ^ va$;
const y0$ = x3$ ^ (x2$ & ~ve$);
const vf$ = x1$ ^ vb$;
const y1$ = vc$ ^ (x2$ & vf$);
const vg$ = x2$ ^ vc$;
const y2$ = x1$ ^ (x0$ & ~vg$);
const vh$ = x3$ ^ vd$;
const y3$ = va$ ^ (x0$ & vh$);
const y02$ = y2$ ^ y0$;
const y13$ = y3$ ^ y1$;
const y23$ = y3$ ^ y2$;
const y01$ = y1$ ^ y0$;
const y00$ = y02$ ^ y13$;
const a0$ = y01$ & q11$;
const a1$ = y0$ & q12$;
const a2$ = y1$ & q0$;
const a3$ = y23$ & q17$;
const a4$ = y2$ & q5$;
const a5$ = y3$ & q15$;
const a6$ = y13$ & q14$;
const a7$ = y00$ & q16$;
const a8$ = y02$ & q13$;
const a9$ = y01$ & q7$;
const a10$ = y0$ & q10$;
const a11$ = y1$ & q6$;
const a12$ = y23$ & q2$;
const a13$ = y2$ & q9$;
const a14$ = y3$ & q8$;
const a15$ = y13$ & q3$;
const a16$ = y00$ & q1$;
const a17$ = y02$ & q4$;
const r0$ = a1$ ^ a5$;
const r1$ = a9$ ^ a15$;
const r2$ = a4$ ^ r0$;
const r3$ = a2$ ^ a10$;
const r4$ = a11$ ^ a17$;
const r5$ = a8$ ^ r1$;
const r6$ = a0$ ^ a16$;
const r7$ = a7$ ^ a13$;
const r8$ = a11$ ^ a14$;
const r9$ = r3$ ^ r4$;
const r10$ = r5$ ^ r6$;
const r11$ = r2$ ^ r9$;
const r12$ = a3$ ^ r0$;
const r13$ = r7$ ^ r8$;
const r14$ = r12$ ^ r13$;
const o0$ = r10$ ^ r14$;
const r15$ = a6$ ^ a10$;
const r16$ = r15$ ^ r2$;
const o1$ = ~(r10$ ^ r16$);
const o2$ = ~(a2$ ^ r2$);
const r17$ = a12$ ^ a13$;
const r18$ = a15$ ^ r17$;
const o3$ = r18$ ^ r11$;
const r19$ = a1$ ^ a14$;
const r20$ = a17$ ^ r3$;
const r21$ = r7$ ^ r19$;
const r22$ = r5$ ^ r20$;
const o4$ = r21$ ^ r22$;
const r23$ = a9$ ^ a12$;
const o5$ = r8$ ^ r23$;
const o6$ = ~(r1$ ^ r4$);
const o7$ = ~(a16$ ^ r11$);
`.trim();

/**
 * Fused AEGIS round on the packed state:
 *   st = st ^ blocksRotr(MixColumns(ShiftRows(SubBytes(st)))) ^ ci
 * Everything is kept in locals; the only array traffic is two reads of st,
 * one read of ci and one write of st per word.
 */
function genRound(
	name: string,
	maskHi: number,
	maskLo: number,
	loShift: number,
	doc: string,
): string {
	const lines: string[] = [];
	for (let g = 0; g < 4; g++) {
		for (let k = 0; k < 8; k++) {
			lines.push(`const u${k}_${g} = st[${4 * k + g}]!;`);
		}
		lines.push(...SBOX_TEMPLATE.replace(/\$/g, `_${g}`).split("\n"));
	}
	// ShiftRows: group g rotated left by 8 * (4 - g) (g = 1, 2, 3).
	const p = (k: number, g: number) => (g === 0 ? `o${k}_0` : `p${k}_${g}`);
	for (let k = 0; k < 8; k++) {
		for (let g = 1; g < 4; g++) {
			const amt = 8 * (4 - g);
			lines.push(
				`const p${k}_${g} = (o${k}_${g} << ${amt}) | (o${k}_${g} >>> ${32 - amt});`,
			);
		}
	}
	// MixColumns: d[k][j] = p[k][j] ^ p[k][j+1];
	// out[k][j] = d[k+1][j] ^ d[k][j+1] ^ p[k][j+3] (^ d[0][j] for k = 3, 4, 6).
	for (let k = 0; k < 8; k++) {
		for (let j = 0; j < 4; j++) {
			lines.push(`const d${k}_${j} = ${p(k, j)} ^ ${p(k, (j + 1) % 4)};`);
		}
	}
	for (let k = 0; k < 8; k++) {
		for (let j = 0; j < 4; j++) {
			const extra = k === 3 || k === 4 || k === 6 ? ` ^ d0_${j}` : "";
			lines.push(
				`const m${k}_${j} = d${(k + 1) % 8}_${j} ^ d${k}_${(j + 1) % 4} ^ ${p(k, (j + 3) % 4)}${extra};`,
			);
		}
	}
	// AEGIS block rotation within lanes + XOR with previous state and input.
	for (let k = 0; k < 8; k++) {
		for (let j = 0; j < 4; j++) {
			const i = 4 * k + j;
			const m = `m${k}_${j}`;
			lines.push(
				`st[${i}] = st[${i}]! ^ ci[${i}]! ^ (((${m} & ${hex(maskHi)}) >>> 1) | ((${m} & ${hex(maskLo)}) << ${loShift}));`,
			);
		}
	}
	return `${doc}
export function ${name}(st: AesBlocks, ci: AesBlocks): void {
${lines.map((l) => `\t${l}`).join("\n")}
}
`;
}

const ks128Formula = (x: string) =>
	`((${x} & 0x02020202) << 6) ^ ((${x} & 0x40404040) << 1) ^ ((${x} & (${x} >>> 1) & 0x10101010) << 3) ^ ((${x} & 0x20202020) >>> 2) ^ ((${x} & 0x04040404) << 1) ^ ((${x} & (${x} >>> 1) & 0x01010101) << 3)`;

const ks256Formula = (x: string) =>
	`((${x} & 0x40404040) << 1) ^ ((${x} & 0x08080808) << 4) ^ ((${x} & 0x04040404) << 5) ^ ((${x} & (${x} >>> 1) & 0x10101010) << 3)`;

const m0Cells: (string | null)[] = new Array(32).fill(null);
for (let j = 0; j < 4; j++) m0Cells[j] = `a${j}`;
const m01Cells = m0Cells.slice();
for (let j = 0; j < 4; j++) m01Cells[16 + j] = `b${j}`;

const loadM0 = (v: string) =>
	[0, 1, 2, 3].map((j) => `\tconst a${j} = ${v}[${j}]!;`).join("\n");
const loadM1 = (v: string) =>
	[0, 1, 2, 3].map((j) => `\tconst b${j} = ${v}[${j}]!;`).join("\n");

const MARKER =
	"// Generated code below: produced by scripts/gen-aes-bs.ts, do not edit by hand.";

let out = "";

out += genRound(
	"aegisRound128",
	0xfefefefe,
	0x01010101,
	7,
	`/**
 * Fused AEGIS-128L update round on the packed state:
 * st = st ^ rotr8(AESRound(st)) ^ ci, where rotr8 rotates the 8 block lanes.
 */`,
);
out += "\n";
out += genRound(
	"aegisRound256",
	0xf8f8f8f8,
	0x04040404,
	5,
	`/**
 * Fused AEGIS-256 update round on the packed state:
 * st = st ^ rotr6(AESRound(st)) ^ ci, where rotr6 rotates the 6 block lanes.
 */`,
);
out += "\n";
out += genPackConstantInput(
	"packConstantInput128",
	"out: AesBlocks, m0: AesBlock, m1: AesBlock",
	m01Cells,
	pack04Ops(),
	`/**
 * Pack two message blocks (at positions 0 and 4) into a constant-input state
 * for the AEGIS-128L round. Specialized pack04 exploiting the sparse input.
 */`,
);
out += "\n";
out += genPackConstantInput(
	"packConstantInput256",
	"out: AesBlocks, m: AesBlock",
	m0Cells,
	pack04_6Ops(),
	`/**
 * Pack one message block (at position 0) into a constant-input state for the
 * AEGIS-256 round. Specialized pack04_6 exploiting the sparse input.
 */`,
);
out += "\n";
out += genKeystream(
	"keystream128",
	"st: AesBlocks, z0: AesBlock, z1: AesBlock",
	ks128Formula,
	unpack04Ops(),
	[0, 1, 2, 3, 16, 17, 18, 19],
	(cells) => [
		...[0, 1, 2, 3].map((j) => `z0[${j}] = ${cells[j]};`),
		...[0, 1, 2, 3].map((j) => `z1[${j}] = ${cells[16 + j]};`),
	],
	`/**
 * AEGIS-128L keystream extraction from the packed state:
 * z0 = S6 ^ S1 ^ (S2 & S3), z1 = S2 ^ S5 ^ (S6 & S7), computed lane-wise,
 * then unpacked (unpack04 restricted to the words feeding blocks 0 and 4).
 */`,
);
out += "\n";
out += genKeystream(
	"keystream256",
	"st: AesBlocks, z: AesBlock",
	ks256Formula,
	unpack04_6Ops(),
	[0, 1, 2, 3],
	(cells) => [0, 1, 2, 3].map((j) => `z[${j}] = ${cells[j]};`),
	`/**
 * AEGIS-256 keystream extraction from the packed state:
 * z = S1 ^ S4 ^ S5 ^ (S2 & S3), computed lane-wise, then unpacked
 * (unpack04_6 restricted to the words feeding block 0).
 */`,
);

// Inject the input-block loads at the top of the pack functions.
out = out.replace(
	"export function packConstantInput128(out: AesBlocks, m0: AesBlock, m1: AesBlock): void {",
	`export function packConstantInput128(out: AesBlocks, m0: AesBlock, m1: AesBlock): void {\n${loadM0("m0")}\n${loadM1("m1")}`,
);
out = out.replace(
	"export function packConstantInput256(out: AesBlocks, m: AesBlock): void {",
	`export function packConstantInput256(out: AesBlocks, m: AesBlock): void {\n${loadM0("m")}`,
);

const target = new URL("../src/aes-bs.ts", import.meta.url).pathname;
const current = await Bun.file(target).text();
const markerPos = current.indexOf(MARKER);
if (markerPos < 0) {
	throw new Error(`marker comment not found in ${target}`);
}
const head = current.slice(0, markerPos);
const banner = `${"// ".concat("-".repeat(75))}\n${MARKER}\n${"// ".concat("-".repeat(75))}\n\n`;
await Bun.write(target, head + banner + out);
console.log(`rewrote generated section of ${target}`);
