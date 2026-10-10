import {
	createPrivateKey,
	createPublicKey,
	createSign,
	createVerify,
	generateKeyPairSync,
	type JsonWebKey,
	type KeyObject,
} from "node:crypto";
import { base64url, base64urlDecode, sha256 } from "./codec.ts";

export type JwtAlg = "ES256" | "RS256";

export interface JwtHeader {
	alg: string;
	typ?: string;
	kid?: string;
	jwk?: JsonWebKey;
	[key: string]: unknown;
}

export interface VerifiedJwt {
	header: JwtHeader;
	payload: Record<string, unknown>;
}

const ALLOWED = new Set<JwtAlg>(["ES256", "RS256"]);

export function generateEs256(): { privateJwk: JsonWebKey; publicJwk: JsonWebKey; privateKey: KeyObject } {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const priv = privateKey.export({ format: "jwk" }) as JsonWebKey;
	const pub = publicKey.export({ format: "jwk" }) as JsonWebKey;
	return { privateJwk: priv, publicJwk: publicOnly(pub), privateKey };
}

export function generateRs256(): { privateJwk: JsonWebKey; publicJwk: JsonWebKey; privateKey: KeyObject } {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const priv = privateKey.export({ format: "jwk" }) as JsonWebKey;
	const pub = publicKey.export({ format: "jwk" }) as JsonWebKey;
	return { privateJwk: priv, publicJwk: publicOnly(pub), privateKey };
}

export function publicOnly(jwk: JsonWebKey): JsonWebKey {
	const copy: JsonWebKey = { kty: jwk.kty };
	if (jwk.kty === "EC") {
		copy.crv = jwk.crv;
		copy.x = jwk.x;
		copy.y = jwk.y;
	} else if (jwk.kty === "RSA") {
		copy.n = jwk.n;
		copy.e = jwk.e;
	} else {
		throw new Error("unsupported jwk kty");
	}
	if (jwk.kid) copy.kid = jwk.kid;
	return copy;
}

export function importPrivateJwk(jwk: JsonWebKey): KeyObject {
	return createPrivateKey({ key: jwk, format: "jwk" });
}

export function importPublicJwk(jwk: JsonWebKey): KeyObject {
	if (jwk.d || (jwk as { k?: string }).k) throw new Error("jwk must be a public key");
	return createPublicKey({ key: publicOnly(jwk), format: "jwk" });
}

/** RFC 7638 thumbprint for the public key. */
export function jwkThumbprint(jwk: JsonWebKey): string {
	const pub = publicOnly(jwk);
	let members: Record<string, string>;
	if (pub.kty === "EC") {
		members = { crv: req(pub.crv), kty: "EC", x: req(pub.x), y: req(pub.y) };
	} else if (pub.kty === "RSA") {
		members = { e: req(pub.e), kty: "RSA", n: req(pub.n) };
	} else {
		throw new Error("unsupported jwk");
	}
	const ordered: Record<string, string> = {};
	for (const key of Object.keys(members).sort()) ordered[key] = members[key]!;
	return base64url(sha256(JSON.stringify(ordered)));
}

function req(value: string | undefined): string {
	if (!value) throw new Error("incomplete jwk");
	return value;
}

export function signJwt(
	payload: Record<string, unknown>,
	privateKey: KeyObject,
	header: JwtHeader,
): string {
	if (!ALLOWED.has(header.alg as JwtAlg)) throw new Error(`refusing to sign with alg ${header.alg}`);
	const h = base64url(JSON.stringify(header));
	const p = base64url(JSON.stringify(payload));
	const input = `${h}.${p}`;
	const signature =
		header.alg === "ES256"
			? createSign("SHA256").update(input).sign({ key: privateKey, dsaEncoding: "ieee-p1363" })
			: createSign("SHA256").update(input).sign(privateKey);
	return `${input}.${base64url(signature)}`;
}

export interface VerifyOptions {
	audience?: string;
	issuer?: string;
	typ?: string;
	algorithms?: JwtAlg[];
	clockSkewSec?: number;
	nowSec?: number;
	/** Reject when exp - iat exceeds this, if both are present. */
	maxLifetimeSec?: number;
	requireStringAud?: boolean;
}

export function verifyJwt(token: string, key: KeyObject, options: VerifyOptions = {}): VerifiedJwt {
	const parts = token.split(".");
	if (parts.length !== 3) throw new Error("malformed jwt");
	const [h, p, s] = parts as [string, string, string];
	const header = JSON.parse(base64urlDecode(h).toString("utf8")) as JwtHeader;
	const alg = header.alg;
	if (alg === "none" || alg === "HS256" || !ALLOWED.has(alg as JwtAlg)) {
		throw new Error(`rejected alg ${alg}`);
	}
	if (options.algorithms && !options.algorithms.includes(alg as JwtAlg)) {
		throw new Error(`unexpected alg ${alg}`);
	}
	if (options.typ && header.typ !== options.typ) throw new Error(`unexpected typ ${header.typ}`);
	const input = `${h}.${p}`;
	const signature = base64urlDecode(s);
	const ok =
		alg === "ES256"
			? createVerify("SHA256").update(input).verify({ key, dsaEncoding: "ieee-p1363" }, signature)
			: createVerify("SHA256").update(input).verify(key, signature);
	if (!ok) throw new Error("bad signature");
	const payload = JSON.parse(base64urlDecode(p).toString("utf8")) as Record<string, unknown>;
	const now = options.nowSec ?? Math.floor(Date.now() / 1000);
	const skew = options.clockSkewSec ?? 30;
	if (options.issuer !== undefined && payload.iss !== options.issuer) throw new Error("issuer mismatch");
	if (options.audience !== undefined) {
		if (options.requireStringAud && typeof payload.aud !== "string") throw new Error("aud must be a string");
		const aud = payload.aud;
		const match = typeof aud === "string" ? aud === options.audience : Array.isArray(aud) && aud.includes(options.audience);
		if (!match) throw new Error("audience mismatch");
	}
	if (typeof payload.exp === "number" && payload.exp + skew < now) throw new Error("token expired");
	if (typeof payload.iat === "number" && payload.iat - skew > now) throw new Error("iat in the future");
	if (
		options.maxLifetimeSec !== undefined &&
		typeof payload.exp === "number" &&
		typeof payload.iat === "number" &&
		payload.exp - payload.iat > options.maxLifetimeSec
	) {
		throw new Error("assertion lifetime too long");
	}
	return { header, payload };
}

export function decodeJwtUnsafe(token: string): VerifiedJwt {
	const parts = token.split(".");
	if (parts.length !== 3) throw new Error("malformed jwt");
	return {
		header: JSON.parse(base64urlDecode(parts[0]!).toString("utf8")) as JwtHeader,
		payload: JSON.parse(base64urlDecode(parts[1]!).toString("utf8")) as Record<string, unknown>,
	};
}

/** RFC 9449 ath: base64url(SHA-256(ASCII access token)). */
export function accessTokenHash(accessToken: string): string {
	return base64url(sha256(Buffer.from(accessToken, "ascii")));
}
