import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** RFC 4648 §5 base64url, no padding. */
export function base64url(data: Buffer | Uint8Array | string): string {
	const buf = typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
	return buf.toString("base64url");
}

export function base64urlDecode(value: string): Buffer {
	if (!/^[A-Za-z0-9_-]*$/.test(value)) {
		throw new Error("invalid base64url");
	}
	return Buffer.from(value, "base64url");
}

export function randomId(bytes = 16): string {
	return base64url(randomBytes(bytes));
}

export function sha256(data: Buffer | string): Buffer {
	return createHash("sha256").update(data).digest();
}

export function sha256Base64Url(data: Buffer | string): string {
	return base64url(sha256(data));
}

/** Constant-time string compare. Length mismatch returns false. */
export function safeEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	if (ab.length !== bb.length) return false;
	return timingSafeEqual(ab, bb);
}

export function canonicalJson(value: unknown): string {
	return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(sortValue);
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value as Record<string, unknown>).sort()) {
			out[key] = sortValue((value as Record<string, unknown>)[key]);
		}
		return out;
	}
	return value;
}

const ID_RE = /^[A-Za-z0-9_-]{1,256}$/;

export function isOpaqueId(value: string): boolean {
	return ID_RE.test(value);
}

/** Decimal string compare for money amounts without floating point. */
export function decimalLte(amount: string, max: string): boolean {
	const a = normalizeDecimal(amount);
	const b = normalizeDecimal(max);
	if (!a || !b) return false;
	if (a.neg !== b.neg) return a.neg;
	if (a.neg) return compareAbs(b, a) <= 0;
	return compareAbs(a, b) <= 0;
}

function normalizeDecimal(value: string): { neg: boolean; whole: string; frac: string } | undefined {
	const match = /^(-?)(\d+)(?:\.(\d+))?$/.exec(value);
	if (!match) return undefined;
	return { neg: match[1] === "-", whole: match[2].replace(/^0+(?=\d)/, ""), frac: (match[3] ?? "").replace(/0+$/, "") };
}

function compareAbs(
	a: { whole: string; frac: string },
	b: { whole: string; frac: string },
): number {
	if (a.whole.length !== b.whole.length) return a.whole.length - b.whole.length;
	if (a.whole !== b.whole) return a.whole < b.whole ? -1 : 1;
	const len = Math.max(a.frac.length, b.frac.length);
	const af = a.frac.padEnd(len, "0");
	const bf = b.frac.padEnd(len, "0");
	if (af === bf) return 0;
	return af < bf ? -1 : 1;
}
