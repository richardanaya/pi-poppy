import assert from "node:assert/strict";
import { mkdtemp, stat } from "node:fs/promises";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { releaseUse, reserveUse, standingCovers, userApproval, type StandingPermission } from "../src/approval.ts";
import { base64url, randomId } from "../src/codec.ts";
import { createPkce, htu, signDpop } from "../src/dpop.ts";
import { generateEs256, generateRs256, importPrivateJwk, signJwt, verifyJwt } from "../src/jwt.ts";
import { HttpCache, httpRequest, isPrivateOrLinkLocal } from "../src/net.ts";
import { containsSecret, redactValue } from "../src/redact.ts";
import { loggedHeaders, loggedText } from "../src/agent.ts";
import { FileStore, emptyState } from "../src/store.ts";
import { createTestMaterial } from "../src/tls.ts";
import type { Operation } from "../src/schema.ts";

test("S129 ES256 and RS256 verify, and none and HS256 are rejected", () => {
	for (const generated of [generateEs256(), generateRs256()]) {
		const now = Math.floor(Date.now() / 1000);
		const token = signJwt({ sub: "usr_1", iat: now, exp: now + 60 }, generated.privateKey, { alg: generated.publicJwk.kty === "RSA" ? "RS256" : "ES256", typ: "JWT" });
		const verified = verifyJwt(token, importPrivateJwk(generated.privateJwk));
		assert.equal(verified.payload.sub, "usr_1");
	}
	const header = base64url(JSON.stringify({ alg: "none", typ: "JWT" }));
	const payload = base64url(JSON.stringify({ sub: "usr_1" }));
	assert.throws(() => verifyJwt(`${header}.${payload}.`, generateEs256().privateKey), /rejected alg none/);
	const hs = base64url(JSON.stringify({ alg: "HS256" }));
	assert.throws(() => verifyJwt(`${hs}.${payload}.${base64url(Buffer.from("sig"))}`, generateEs256().privateKey), /rejected alg HS256/);
});

test("S130 S136 DPoP proofs use a 128-bit jti and an htu without query", () => {
	const key = generateEs256();
	const proof = signDpop({ privateJwk: key.privateJwk, method: "post", url: "https://shop.example/orders?access_token=no", accessToken: "st1_token" });
	const body = JSON.parse(Buffer.from(proof.split(".")[1]!, "base64url").toString("utf8")) as { jti: string; htu: string; ath: string; htm: string };
	assert.equal(htu("https://shop.example/orders?q=1#x"), "https://shop.example/orders");
	assert.equal(body.htu, "https://shop.example/orders");
	assert.equal(body.htm, "POST");
	assert.ok(body.ath);
	assert.ok(Buffer.from(body.jti, "base64url").length >= 16);
	assert.ok(Buffer.from(randomId(16), "base64url").length >= 16);
	const pkce = createPkce();
	assert.notEqual(pkce.verifier, pkce.challenge);
});

test("S116 S117 approval must use the company summary, and standing permissions cover every term", () => {
	const operation = op({ user_approval_required: false });
	assert.throws(() => userApproval({ accepted: false, companyName: "Shop", summary: operation.summary, operation }), /did not approve/);
	assert.throws(() => userApproval({ accepted: true, companyName: "Shop", summary: "a paraphrase", operation }), /company's summary/);
	const approval = userApproval({ accepted: true, companyName: "Shop", summary: operation.summary, operation });
	assert.equal(approval.summary, operation.summary);
	const permission: StandingPermission = { id: "prm_1", issuer: "https://shop.example", action: "exchange", currency: "USD", maxAmount: "80.00", maxUses: 1, uses: 0, reserved: 0 };
	assert.equal(standingCovers(permission, operation, "https://shop.example").ok, true);
	assert.equal(standingCovers(permission, op({ user_approval_required: true }), "https://shop.example").ok, false);
	assert.equal(standingCovers({ ...permission, issuer: "https://other.example" }, operation, "https://shop.example").ok, false);
	assert.equal(standingCovers({ ...permission, maxAmount: "10.00" }, operation, "https://shop.example").ok, false);
	reserveUse(permission);
	assert.equal(standingCovers(permission, operation, "https://shop.example").ok, false);
	releaseUse(permission);
	assert.equal(standingCovers(permission, operation, "https://shop.example").ok, true);
});

test("S128 S134 S133 cache bounds, private addresses, and redaction", () => {
	let now = 0;
	const cache = new HttpCache(60, 86_400, () => now);
	cache.store("https://shop.example/a", "doc", "max-age=10");
	now = 59_000;
	assert.equal(cache.get("https://shop.example/a"), "doc");
	now = 60_000;
	assert.equal(cache.get("https://shop.example/a"), undefined);
	cache.store("https://shop.example/b", "doc", "max-age=999999, no-store");
	assert.equal(cache.get("https://shop.example/b"), undefined);
	assert.equal(isPrivateOrLinkLocal("10.1.2.3"), true);
	assert.equal(isPrivateOrLinkLocal("8.8.8.8"), false);
	assert.equal(loggedHeaders({ Authorization: "DPoP st1_secret", accept: "application/json" }).Authorization, "[redacted]");
	assert.equal(loggedHeaders({ dpop: "proof" }).dpop, "[redacted]");
	assert.equal((redactValue({ password: "correct-horse", email: "ada@example.com" }) as { password: string }).password, "[redacted]");
	assert.match(loggedText("token st1_abcdefghij and pat_abcdefghij"), /redacted-token/);
	assert.equal(containsSecret('{"status":"failed"}', ["correct-horse"]), false);
	assert.equal(containsSecret('{"password":"correct-horse"}', ["correct-horse"]), true);
});

test("S135 S027 account tokens are stored mode 0600 and user ids are not personal data", async () => {
	const dir = await mkdtemp(join(tmpdir(), "poppy-store-"));
	const path = join(dir, "poppy.json");
	const store = new FileStore(path);
	const key = generateEs256();
	const state = emptyState({ clientName: "pi-poppy", signingKid: "k", signingPrivateJwk: key.privateJwk, signingPublicJwk: key.publicJwk });
	state.users.default = { "https://shop.example": { userId: "usr_not-an-email", dpopPrivateJwk: key.privateJwk, dpopKid: "d", accounts: [{ refreshToken: "pat_abcdefghijklmnop", scope: "poppy:read", issuer: "https://shop.example" }] } };
	await store.save(state);
	const info = await stat(path);
	assert.equal(info.mode & 0o777, 0o600);
	const loaded = await store.load();
	assert.equal(loaded?.users.default?.["https://shop.example"]?.userId.startsWith("usr_"), true);
	assert.equal(loaded?.users.default?.["https://shop.example"]?.userId.includes("@"), false);
});

test("S001 S004 S042 refusing non-HTTPS and URL credentials", async () => {
	await assert.rejects(httpRequest("http://127.0.0.1/poppy.json"), /HTTPS/);
	await assert.rejects(httpRequest("https://user:secret@127.0.0.1/"), /credentials/);
	await assert.rejects(httpRequest("https://10.1.2.3/"), /private/);
	await assert.rejects(httpRequest("https://127.0.0.1/"), /loopback/);
});

test("S132 metadata fetches drop Authorization, Cookie, and DPoP", async () => {
	const tls = createTestMaterial();
	const seen: Array<Record<string, string | undefined>> = [];
	const server = createServer({ cert: tls.certPem, key: tls.keyPem }, (req, res) => {
		seen.push({
			authorization: req.headers.authorization,
			cookie: req.headers.cookie,
			dpop: req.headers.dpop,
			accept: req.headers.accept,
		});
		res.writeHead(200, { "content-type": "application/json" });
		res.end("{}");
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
	try {
		const port = (server.address() as AddressInfo).port;
		const url = `https://127.0.0.1:${port}/.well-known/poppy.json`;
		const headers = { Authorization: "Bearer st1_secret", Cookie: "poppy_session=abc", DPoP: "proof", Accept: "application/json" };
		const stripped = await httpRequest(url, { headers, metadata: true, ca: tls.caPem, allowLoopback: true });
		assert.equal(stripped.status, 200);
		assert.equal(seen[0]?.authorization, undefined);
		assert.equal(seen[0]?.cookie, undefined);
		assert.equal(seen[0]?.dpop, undefined);
		assert.equal(seen[0]?.accept, "application/json");
		await httpRequest(url, { headers, ca: tls.caPem, allowLoopback: true });
		assert.equal(seen[1]?.authorization, "Bearer st1_secret");
		assert.equal(seen[1]?.cookie, "poppy_session=abc");
		assert.equal(seen[1]?.dpop, "proof");
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
});

function op(extra: Partial<Operation>): Operation {
	return {
		operation_id: "exc_1",
		revision: 1,
		state: "proposed",
		summary: "Exchange the jacket for $70.00 more.",
		terms: { action: "exchange", price_difference: { amount: "70.00", currency: "USD" } },
		expires_at: "2026-10-09T12:15:00Z",
		confirmation: null,
		result: null,
		user_approval_required: false,
		...extra,
	};
}
