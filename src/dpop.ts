import type { JsonWebKey, KeyObject } from "node:crypto";
import { randomId, sha256Base64Url } from "./codec.ts";
import { accessTokenHash, importPrivateJwk, publicOnly, signJwt } from "./jwt.ts";

export interface ProofOptions {
	privateJwk: JsonWebKey;
	method: string;
	url: string;
	accessToken?: string;
	nonce?: string;
	nowSec?: number;
}

/** htu is the URL without query or fragment, as RFC 9449 requires. */
export function htu(url: string): string {
	const parsed = new URL(url);
	return `${parsed.origin}${parsed.pathname}`;
}

export function signDpop(options: ProofOptions): string {
	const now = options.nowSec ?? Math.floor(Date.now() / 1000);
	const payload: Record<string, unknown> = {
		jti: randomId(16),
		htm: options.method.toUpperCase(),
		htu: htu(options.url),
		iat: now,
	};
	if (options.accessToken) payload.ath = accessTokenHash(options.accessToken);
	if (options.nonce) payload.nonce = options.nonce;
	const key: KeyObject = importPrivateJwk(options.privateJwk);
	return signJwt(payload, key, {
		typ: "dpop+jwt",
		alg: "ES256",
		jwk: publicOnly(options.privateJwk),
	});
}

export function signClientAssertion(options: {
	privateJwk: JsonWebKey;
	clientId: string;
	audience: string;
	kid?: string;
	nowSec?: number;
}): string {
	const now = options.nowSec ?? Math.floor(Date.now() / 1000);
	return signJwt(
		{
			iss: options.clientId,
			sub: options.clientId,
			aud: options.audience,
			iat: now,
			exp: now + 60,
			jti: randomId(16),
		},
		importPrivateJwk(options.privateJwk),
		{ alg: "ES256", kid: options.kid, typ: "JWT" },
	);
}

export function signSessionAssertion(options: {
	privateJwk: JsonWebKey;
	clientId: string;
	userId: string;
	tokenEndpoint: string;
	kid?: string;
	nowSec?: number;
}): string {
	const now = options.nowSec ?? Math.floor(Date.now() / 1000);
	return signJwt(
		{
			iss: options.clientId,
			sub: options.userId,
			aud: options.tokenEndpoint,
			iat: now,
			exp: now + 60,
			jti: randomId(16),
		},
		importPrivateJwk(options.privateJwk),
		{ alg: "ES256", kid: options.kid },
	);
}

export function signBrowserAssertion(options: {
	privateJwk: JsonWebKey;
	clientId: string;
	userId: string;
	endpoint: string;
	sessionId: string;
	returnTo: string;
	kid?: string;
	nowSec?: number;
}): string {
	const now = options.nowSec ?? Math.floor(Date.now() / 1000);
	return signJwt(
		{
			iss: options.clientId,
			sub: options.userId,
			aud: options.endpoint,
			session_id: options.sessionId,
			return_to: options.returnTo,
			iat: now,
			exp: now + 60,
			jti: randomId(16),
		},
		importPrivateJwk(options.privateJwk),
		{ alg: "ES256", typ: "poppy-browser+jwt", kid: options.kid },
	);
}

export function createPkce(): { verifier: string; challenge: string } {
	const verifier = randomId(32);
	return { verifier, challenge: sha256Base64Url(verifier) };
}
