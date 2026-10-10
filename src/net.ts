import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import type { IncomingMessage } from "node:http";
import { isIP } from "node:net";

export class HttpError extends Error {
	readonly code: string;
	readonly status: number | undefined;
	constructor(message: string, code: string, status?: number) {
		super(message);
		this.name = "HttpError";
		this.code = code;
		this.status = status;
	}
}

export interface HttpResponse {
	status: number;
	headers: Record<string, string | string[] | undefined>;
	body: Buffer;
	url: string;
	/** Set when the caller asked for a stream. The body is empty. */
	stream?: IncomingMessage;
}

export interface HttpRequestOptions {
	method?: string;
	headers?: Record<string, string>;
	body?: string | Buffer;
	timeoutMs?: number;
	maxBytes?: number;
	ca?: string | Buffer;
	allowLoopback?: boolean;
	allowPrivate?: boolean;
	/** Follow redirects. Every hop must stay HTTPS. Authorization is not forwarded across hosts. */
	followRedirects?: boolean;
	maxRedirects?: number;
	/** Do not send cookies. Metadata fetches also drop Authorization. */
	metadata?: boolean;
	stream?: boolean;
	signal?: AbortSignal;
}

const HOP_BLOCK = new Set(["authorization", "cookie", "dpop", "proxy-authorization"]);

export async function httpRequest(urlString: string, options: HttpRequestOptions = {}): Promise<HttpResponse> {
	return requestOnce(urlString, options, options.maxRedirects ?? 3);
}

async function requestOnce(urlString: string, options: HttpRequestOptions, redirectsLeft: number): Promise<HttpResponse> {
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		throw new HttpError("invalid URL", "invalid_url");
	}
	if (url.protocol !== "https:") throw new HttpError("refusing non-HTTPS URL", "https_required");
	if (url.username || url.password) throw new HttpError("refusing URL credentials", "url_credentials");
	await assertAddressAllowed(url.hostname, options);
	const method = options.method ?? "GET";
	const headers: Record<string, string> = {};
	for (const [key, value] of Object.entries(options.headers ?? {})) {
		if (options.metadata && HOP_BLOCK.has(key.toLowerCase())) continue;
		headers[key] = value;
	}
	if (options.body !== undefined && headers["Content-Length"] === undefined && headers["content-length"] === undefined) {
		headers["Content-Length"] = String(Buffer.byteLength(options.body));
	}
	const timeoutMs = options.timeoutMs ?? 5_000;
	const response = await new Promise<{ status: number; headers: IncomingMessage["headers"]; stream: IncomingMessage }>(
		(resolve, reject) => {
			const req = httpsRequest(
				{
					protocol: url.protocol,
					hostname: url.hostname,
					port: url.port || 443,
					path: `${url.pathname}${url.search}`,
					method,
					headers,
					ca: options.ca,
					servername: url.hostname,
					rejectUnauthorized: true,
					timeout: timeoutMs,
				},
				(res) => resolve({ status: res.statusCode ?? 0, headers: res.headers, stream: res }),
			);
			const fail = (error: Error) => {
				req.destroy();
				reject(error);
			};
			req.on("error", fail);
			req.on("timeout", () => fail(new HttpError("timeout", "timeout")));
			options.signal?.addEventListener("abort", () => fail(new HttpError("aborted", "aborted")), { once: true });
			if (options.body !== undefined) req.write(options.body);
			req.end();
		},
	);

	const location = headerOne(response.headers, "location");
	if (options.followRedirects && response.status >= 300 && response.status < 400 && location) {
		response.stream.resume();
		if (redirectsLeft <= 0) throw new HttpError("too many redirects", "redirects");
		const next = new URL(location, url).toString();
		if (!next.startsWith("https://")) throw new HttpError("redirect left HTTPS", "https_required");
		const nextHeaders = { ...headers };
		const nextHost = new URL(next).host;
		if (nextHost !== url.host) {
			for (const key of Object.keys(nextHeaders)) {
				if (HOP_BLOCK.has(key.toLowerCase())) delete nextHeaders[key];
			}
		}
		return requestOnce(next, { ...options, method: method === "POST" && response.status === 303 ? "GET" : method, headers: nextHeaders, body: method === "POST" && response.status === 303 ? undefined : options.body }, redirectsLeft - 1);
	}

	if (options.stream) {
		return { status: response.status, headers: response.headers, body: Buffer.alloc(0), url: url.toString(), stream: response.stream };
	}
	const body = await readLimited(response.stream, options.maxBytes ?? 100_000);
	return { status: response.status, headers: response.headers, body, url: url.toString() };
}

async function readLimited(stream: IncomingMessage, maxBytes: number): Promise<Buffer> {
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of stream) {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
		total += buf.length;
		if (total > maxBytes) {
			stream.destroy();
			throw new HttpError("response too large", "too_large");
		}
		chunks.push(buf);
	}
	return Buffer.concat(chunks);
}

export function headerOne(headers: IncomingMessage["headers"] | HttpResponse["headers"], name: string): string | undefined {
	const value = headers[name.toLowerCase()] ?? headers[name];
	if (Array.isArray(value)) return value[0];
	return value;
}

export function headerAll(headers: HttpResponse["headers"], name: string): string[] {
	const value = headers[name.toLowerCase()] ?? headers[name];
	if (value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

async function assertAddressAllowed(hostname: string, options: HttpRequestOptions): Promise<void> {
	const ips = isIP(hostname) ? [hostname] : (await lookup(hostname, { all: true })).map((entry) => entry.address);
	if (ips.length === 0) throw new HttpError("DNS returned no addresses", "dns");
	for (const ip of ips) {
		if (isLoopback(ip)) {
			if (!options.allowLoopback) throw new HttpError(`refusing loopback address ${ip}`, "loopback");
			continue;
		}
		if (isPrivateOrLinkLocal(ip) && !options.allowPrivate) {
			throw new HttpError(`refusing private address ${ip}`, "private_address");
		}
	}
}

export function isLoopback(ip: string): boolean {
	if (ip === "::1") return true;
	const mapped = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
	return mapped.startsWith("127.");
}

export function isPrivateOrLinkLocal(ip: string): boolean {
	const mapped = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
	if (mapped.includes(":")) {
		const lower = mapped.toLowerCase();
		return lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80:");
	}
	const parts = mapped.split(".").map((part) => Number(part));
	if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return true;
	const [a, b] = parts as [number, number, number, number];
	if (a === 10 || a === 0) return true;
	if (a === 172 && b >= 16 && b <= 31) return true;
	if (a === 192 && b === 168) return true;
	if (a === 169 && b === 254) return true;
	if (a === 100 && b >= 64 && b <= 127) return true;
	return false;
}

export interface CacheEntry {
	body: string;
	storedAt: number;
	expiresAt: number;
}

/**
 * Cache according to Cache-Control max-age, clamped to [minSec, maxSec].
 * Responses without an explicit freshness lifetime are not cached.
 */
export class HttpCache {
	private readonly entries = new Map<string, CacheEntry>();
	private readonly minSec: number;
	private readonly maxSec: number;
	private readonly now: () => number;
	constructor(minSec = 60, maxSec = 86_400, now: () => number = () => Date.now()) {
		this.minSec = minSec;
		this.maxSec = maxSec;
		this.now = now;
	}

	get(url: string): string | undefined {
		const entry = this.entries.get(url);
		if (!entry) return undefined;
		if (this.now() >= entry.expiresAt) {
			this.entries.delete(url);
			return undefined;
		}
		return entry.body;
	}

	store(url: string, body: string, cacheControl: string | undefined): void {
		const maxAge = parseMaxAge(cacheControl);
		if (maxAge === undefined) return;
		const lifetime = Math.min(this.maxSec, Math.max(this.minSec, maxAge)) * 1000;
		this.entries.set(url, { body, storedAt: this.now(), expiresAt: this.now() + lifetime });
	}
}

export function parseMaxAge(cacheControl: string | undefined): number | undefined {
	if (!cacheControl) return undefined;
	if (/no-store|no-cache/i.test(cacheControl)) return undefined;
	const match = /(?:^|,\s*)max-age=(\d+)/i.exec(cacheControl);
	if (!match) return undefined;
	return Number(match[1]);
}

export function parseRetryAfter(value: string | undefined, nowMs = Date.now()): number {
	if (!value) return 1;
	const seconds = Number(value);
	if (Number.isFinite(seconds) && seconds >= 0 && /^\d+(\.\d+)?$/.test(value.trim())) {
		return seconds;
	}
	const date = Date.parse(value);
	if (Number.isNaN(date)) return 1;
	return Math.max(0, (date - nowMs) / 1000);
}
