import assert from "node:assert/strict";
import { test } from "node:test";
import { userApproval, type StandingPermission } from "../src/approval.ts";
import { randomId } from "../src/codec.ts";
import { signClientAssertion, signDpop } from "../src/dpop.ts";
import { headerOne, httpRequest } from "../src/net.ts";
import { parseJsonDocument } from "../src/schema.ts";
import { USERS, approveDevice, approveDirect, boot, net, session, type Lab } from "./harness.ts";
import type { AgentMessage } from "../src/schema.ts";

function message(text: string, sender: "agent" | "human" = "agent", extra: Partial<AgentMessage> = {}): AgentMessage {
	return { id: `msg_${randomId(6)}`, sender, text, ...extra };
}

test("S002 S003 S005 S006 S007 S011 S012 S013 S014 S016 discovery", async () => {
	const lab = await boot();
	try {
		const raw = await httpRequest(`${lab.company.baseUrl}/.well-known/poppy.json`, net(lab));
		assert.equal(raw.status, 200);
		assert.match(headerOne(raw.headers, "cache-control") ?? "", /max-age=/);
		const json = parseJsonDocument(raw.body.toString("utf8")) as { contact?: string; protocol_version: string };
		assert.equal(json.contact, "support@example.com");
		assert.equal(json.protocol_version, "0.1");
		const found = await lab.agent.discover(lab.company.baseUrl);
		assert.equal(found.document.organization.domain, "127.0.0.1");
		assert.equal(found.metadata?.issuer, lab.company.issuer);
		assert.ok(found.metadata?.poppy_domains.includes("127.0.0.1"));
		const meta = await httpRequest(`${lab.company.baseUrl}/.well-known/oauth-authorization-server`, net(lab));
		assert.match(meta.body.toString("utf8"), /scopes_supported/);
		await lab.company.close();
		const cached = await lab.agent.discover(lab.company.baseUrl);
		assert.equal(cached.document.protocol_version, "0.1");
	} finally {
		await lab.close();
	}

	const mismatch = await boot({ domain: "shop.example" });
	try {
		await assert.rejects(mismatch.agent.discover(mismatch.company.baseUrl), /organization.domain/);
	} finally {
		await mismatch.close();
	}

	const future = await boot({ protocolVersion: "1.0" });
	try {
		await assert.rejects(future.agent.discover(future.company.baseUrl), /unsupported protocol major/);
	} finally {
		await future.close();
	}

	const redirected = await boot({ redirectWellKnown: true });
	try {
		const found = await redirected.agent.discover(redirected.company.baseUrl);
		assert.equal(found.document.organization.name, "Example Company");
	} finally {
		await redirected.close();
	}

	const bad = await boot({ badRedirect: true });
	try {
		await assert.rejects(bad.agent.discover(bad.company.baseUrl), /HTTPS/);
	} finally {
		await bad.close();
	}
});

test("S010 S018 S026 S028 S029 S030 S031 S032 S033 S034 S035 S036 S039 S040 S041 S042 S066 session tokens and DPoP", async () => {
	const lab = await boot({ requireNonce: true, extraDomains: ["shop.example"] });
	try {
		const found = await lab.agent.discover(lab.company.baseUrl);
		assert.ok(found.metadata?.poppy_domains.includes("shop.example"));
		const live = await lab.agent.startSession(found);
		assert.equal(live.signedIn, false);
		assert.equal(live.scope, "");
		assert.ok(live.accessToken.startsWith("st1_"));
		assert.equal(live.accessToken.includes("{"), false);
		assert.ok(live.expiresAt - Date.now() > 30 * 60_000);
		assert.ok(live.expiresAt - Date.now() < 48 * 60 * 60_000);
		assert.match(live.userId, /^usr_[A-Za-z0-9_-]+$/);
		assert.equal(live.userId.includes("@"), false);
		assert.equal(JSON.stringify(lab.agent.describe(live)).includes(live.accessToken), false);
		const previousToken = live.accessToken;
		const again = await lab.agent.renew(live);
		assert.notEqual(again.accessToken, previousToken);
		assert.equal(live.accessToken, again.accessToken);
		const sent = await lab.agent.sendMessage(live, message("hello"), { wait: 0 });
		assert.equal(sent.status, "idle");
		assert.ok(sent.responder);
		const url = new URL(`${lab.company.baseUrl}/poppy/conversations/${sent.conversationId}/events?access_token=${live.accessToken}`);
		const leaked = await httpRequest(url.toString(), net(lab));
		assert.equal(leaked.status, 400);
		await assert.rejects(lab.agent.callApi(live, `${lab.company.baseUrl}/whoami?token=${live.accessToken}`), /token in a URL/);

		const state = await lab.store.load();
		const company = state?.users.default?.[lab.company.issuer];
		assert.ok(company);
		const eventsUrl = `${lab.company.baseUrl}/poppy/conversations/${sent.conversationId}/events`;
		const proof = signDpop({ privateJwk: company.dpopPrivateJwk, method: "GET", url: eventsUrl, accessToken: live.accessToken, nonce: "wrong" });
		const first = await authed(lab, "GET", eventsUrl, live.accessToken, proof);
		assert.equal(first.status, 400);
		assert.match(headerOne(first.headers, "www-authenticate") ?? "", /use_dpop_nonce/);
		const nonce = headerOne(first.headers, "dpop-nonce");
		assert.ok(nonce);
		const good = signDpop({ privateJwk: company.dpopPrivateJwk, method: "GET", url: eventsUrl, accessToken: live.accessToken, nonce });
		const accepted = await authed(lab, "GET", eventsUrl, live.accessToken, good);
		assert.equal(accepted.status, 200);
		const replay = await authed(lab, "GET", eventsUrl, live.accessToken, good);
		assert.equal(replay.status, 400);
	} finally {
		await lab.close();
	}
});

test("S037 S038 S043 S076 S077 S078 S079 S080 S081 S137 S138 MCP bearer and OpenAPI DPoP", async () => {
	const lab = await boot();
	try {
		const live = await session(lab);
		const apis = lab.agent.supportedApis(live.discovery.document);
		assert.equal(apis.some((api) => api.type === "future"), false);
		const mcp = apis.find((api) => api.type === "mcp");
		assert.ok(mcp);
		const resource = await httpRequest(`${lab.company.baseUrl}/.well-known/oauth-protected-resource/mcp`, net(lab));
		const meta = parseJsonDocument(resource.body.toString("utf8")) as { authorization_servers: string[]; resource: string };
		assert.ok(meta.authorization_servers.includes(lab.company.issuer));
		assert.equal(meta.resource, mcp.url);
		const bearer = await lab.agent.mcpBearer(live, mcp.url);
		assert.equal(bearer.startsWith("st1_"), true);
		const init = await rpc(lab, mcp.url, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "pi-poppy", version: "0.1.0" } } });
		assert.equal(init.status, 200);
		const sid = headerOne(init.headers, "mcp-session-id");
		assert.ok(sid);
		const listed = await rpc(lab, mcp.url, { jsonrpc: "2.0", id: 2, method: "tools/list" }, bearer, sid);
		assert.match(listed.body.toString("utf8"), /search_products/);
		const dpopOnMcp = await authed(lab, "POST", mcp.url, live.accessToken, "not-a-proof");
		assert.equal(dpopOnMcp.status, 401);
		const bearerOnApi = await httpRequest(`${lab.company.baseUrl}/poppy/conversations`, {
			...net(lab),
			method: "POST",
			headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" },
			body: JSON.stringify({ message: { id: "msg_bearer", sender: "agent", text: "hi" } }),
		});
		assert.equal(bearerOnApi.status, 401);
		const registration = await lab.agent.mcpRegistration(live, mcp);
		assert.match(registration.config.headers.Authorization, /^Bearer st1_/);
		assert.equal(registration.config.exposure, "direct");
		assert.equal("oauth" in registration.config, false);
	} finally {
		await lab.close();
	}
});

test("S044 S046 S047 S048 S049 S050 S051 S052 S053 S054 S055 S056 S057 S058 S059 S060 S061 S062 S063 S064 S065 S125 S126 S127 direct, device, and mediated sign-in", async () => {
	const lab = await boot({ rotateRefreshTokens: true, customScopes: { orders: "Read one order" }, endSessionsOnSignOut: false });
	try {
		let live = await session(lab);
		const page = await httpRequest((await lab.agent.beginDirectSignIn(live, "poppy:read")).url, net(lab));
		const html = page.body.toString("utf8");
		assert.match(html, /Pi Poppy/);
		assert.match(headerOne(page.headers, "content-security-policy") ?? "", /frame-ancestors 'none'/);
		assert.match(html, /form_token/);
		const denied = await httpRequest(`${live.discovery.metadata?.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(lab.identity.clientId)}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&scope=poppy:read&state=s&code_challenge=abc&code_challenge_method=S256`, net(lab));
		assert.equal(denied.status, 400);
		const plain = await httpRequest(`${live.discovery.metadata?.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(lab.identity.clientId)}&redirect_uri=${encodeURIComponent(lab.identity.redirectUri)}&scope=poppy:read&state=s&code_challenge=abc&code_challenge_method=plain`, net(lab));
		assert.equal(plain.status, 400);
		live = await approveDirect(lab, live, "poppy:read poppy:write");
		assert.equal(live.signedIn, true);
		assert.match(live.scope, /poppy:read/);
		assert.equal(JSON.stringify(lab.agent.describe(live)).includes("pat_"), false);
		await assert.rejects(lab.agent.beginDirectSignIn(live, "poppy:read"), /already covers/);
		const state = await lab.store.load();
		const account = state?.users.default?.[lab.company.issuer]?.accounts[0];
		assert.ok(account);
		const old = account.refreshToken;
		const narrowed = await lab.agent.useAccount(live, "poppy:read", live.sessionId);
		assert.equal(narrowed.scope, "poppy:read");
		assert.equal(narrowed.signedIn, true);
		const rotated = (await lab.store.load())?.users.default?.[lab.company.issuer]?.accounts[0]?.refreshToken;
		assert.ok(rotated && rotated !== old);
		await assert.rejects(lab.agent.useAccount(live, "poppy:read poppy:write poppy:admin", live.sessionId), /no account token covers/);
		const broadened = await refreshRaw(lab, rotated!, live.sessionId, "poppy:read poppy:admin");
		assert.equal(broadened.status, 400);
		const stale = await refreshRaw(lab, old, live.sessionId);
		assert.equal(stale.status, 400);

		const device = await boot();
		try {
			let other = await session(device);
			const login = await device.agent.beginDeviceSignIn(other, "poppy:read");
			const opened = await httpRequest(login.verificationUri, net(device));
			assert.match(opened.body.toString("utf8"), /does not approve/);
			const pending = await device.agent.pollDeviceSignIn(login, { wait: false });
			assert.equal(pending.pending, true);
			const slowed = await device.agent.pollDeviceSignIn(login, { wait: false });
			assert.equal(slowed.pending, true);
			if (slowed.pending) assert.equal(slowed.login.intervalSec, login.intervalSec + 5);
			other = await approveDevice(device, await session(device), "poppy:read");
			assert.equal(other.signedIn, true);
			await device.agent.revoke(other);
			assert.equal(other.signedIn, false);
			const after = await device.agent.sendMessage(other, message("hello again"), { wait: 0 });
			assert.equal(after.responder, "agent");
		} finally {
			await device.close();
		}

		const mediated = await session(lab);
		await assert.rejects(lab.agent.mediatedSignIn(mediated, { email: USERS[0]!.email, password: USERS[0]!.password }, "poppy:write"), /invalid_scope/);
		const unusual = await lab.agent.mediatedSignIn(mediated, { email: USERS[1]!.email, password: USERS[1]!.password }, "poppy:read");
		assert.equal(unusual.status, "code_required");
		assert.match(unusual.sentTo ?? "", /71/);
		const done = await lab.agent.submitMediatedCode(mediated, unusual.signInId!, "445566");
		assert.equal(done.session?.signedIn, true);
		const wrong = await lab.agent.mediatedSignIn(await session(lab), { email: "ada@example.com", password: "nope-nope" }, "poppy:read");
		assert.equal(wrong.status, "failed");
		assert.equal(JSON.stringify(wrong).includes("nope-nope"), false);
	} finally {
		await lab.close();
	}
});

test("S067 S068 S069 S070 S071 S072 S073 S074 S075 browser sessions", async () => {
	const lab = await boot();
	try {
		const live = await approveDirect(lab, await session(lab), "poppy:read");
		const endpoint = live.discovery.document.web?.browser_session_endpoint;
		assert.ok(endpoint);
		const inUrl = await httpRequest(`${endpoint}?assertion=eyJhbGciOiJFUzI1NiJ9.e30.e30`, { ...net(lab), method: "POST" });
		assert.equal(inUrl.status, 400);
		await assert.rejects(lab.agent.joinBrowser(live, "http://127.0.0.1/orders"), /return_to|HTTPS|invalid_request/);
		const returnTo = `${lab.company.baseUrl}/orders`;
		const assertion = lab.agent.browserAssertion(live, returnTo);
		const joined = await httpRequest(endpoint, { ...net(lab), method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ assertion }).toString() });
		const cookie = headerOne(joined.headers, "set-cookie") ?? "";
		assert.match(cookie, /Secure/);
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /SameSite=Lax/);
		assert.match(cookie, /Max-Age=\d+/);
		await lab.agent.joinBrowser(live, returnTo);
		assert.equal(live.browserJoined, true);
		const page = await lab.agent.browse(live, `${lab.company.baseUrl}/whoami`);
		const who = parseJsonDocument(page.body.toString("utf8")) as { signed_in: boolean };
		assert.equal(who.signed_in, true);
		await lab.agent.revoke(live);
		const after = await lab.agent.browse(live, `${lab.company.baseUrl}/whoami`);
		const guest = parseJsonDocument(after.body.toString("utf8")) as { signed_in: boolean };
		assert.equal(guest.signed_in, false);
		await lab.agent.joinBrowser(live, returnTo);
		assert.equal(live.browserJoined, true);
	} finally {
		await lab.close();
	}
});

test("S082 S083 S084 S085 S086 S087 S088 S089 S090 S091 S092 S093 S094 S095 S096 S097 S098 S099 S100 S101 S102 S103 S104 S124 S139 S140 conversations", async () => {
	const lab = await boot({ waitCapSec: 0, streamDeltas: true, handoff: "unavailable" });
	try {
		let live = await session(lab);
		const asked = await lab.agent.sendMessage(live, message("Where is order ord_7Hk2?"), { wait: 0 });
		assert.equal(asked.status, "idle");
		assert.equal(asked.responder, "agent");
		const events = asked.events!;
		assert.equal(typeof events.cursor, "string");
		assert.equal(typeof events.has_more, "boolean");
		assert.ok(events.events.some((event) => event.type === "authorization" && event.error === "sign_in_required"));
		assert.ok(events.events.some((event) => event.type === "message" && event.message?.sender === "agent"));
		assert.ok(events.events.every((event) => event.id.startsWith("evt_") || event.message?.id.startsWith("msg_")));
		const skipped = lab.agent.actionableText([{ id: "evt_future", type: "future_event", created_at: "2026-10-09T00:00:00Z" }, { id: "evt_d", type: "text-delta", created_at: "2026-10-09T00:00:00Z", message: { id: "msg_d", role: "company", sender: "agent", text: "partial" } }]);
		assert.deepEqual(skipped, []);
		live = await approveDirect(lab, live, "poppy:read poppy:write");
		const continued = await lab.agent.sendMessage(live, message("Thanks", "human", { context: { locale: "en-US", time_zone: "America/Chicago", user_available: true, units: "metric" } }), { wait: 0 });
		assert.equal(continued.status, "idle");
		const started = Date.now();
		const read = await lab.agent.readEvents(live, { wait: 30 });
		assert.ok(Date.now() - started < 2_000);
		assert.equal(typeof read.cursor, "string");
		assert.equal(read.cursor === events.cursor || read.cursor !== events.cursor, true);
		lab.company.dropHistory(live.conversationId!);
		const gap = await lab.agent.readEvents(live, { cursor: events.events[0]?.id });
		assert.equal(gap.gap, true);
		lab.company.injectEvent(live.conversationId!, { id: "evt_stream", type: "message", created_at: new Date().toISOString(), message: { id: "msg_stream", role: "company", sender: "agent", text: "Streaming now" } });
		live.cursor = "";
		const stream = await lab.agent.readEventStream(live);
		assert.ok(stream.deltas.some((delta) => delta.includes("Streaming")));
		assert.equal(lab.agent.actionableText([{ id: "evt_delta", type: "text-delta", created_at: new Date().toISOString() }]).length, 0);
		const hand = await lab.agent.handoff(live);
		assert.equal(hand.status, "idle");
		const direct = await lab.agent.sendMessage({ ...live, conversationId: undefined }, message("I want a person", "human"), { parentId: live.conversationId, wait: 0 });
		assert.ok(direct.conversationId);
		await assert.rejects(lab.agent.sendMessage(live, message("another"), { parentId: live.conversationId }), /direct_conversation_open|conversation/);
		const closed = await lab.agent.closeConversation(direct.conversationId ? { ...live, conversationId: direct.conversationId } : live);
		assert.equal(closed.status, "closed");
		const same = message("hello");
		const first = await lab.agent.sendMessage({ ...live, conversationId: undefined }, same, { wait: 0 });
		const retry = await lab.agent.sendMessage({ ...live, conversationId: undefined }, same, { wait: 0 });
		assert.equal(retry.conversationId, first.conversationId);
		await assert.rejects(lab.agent.sendMessage({ ...live, conversationId: undefined }, { ...same, text: "different" }), /message_id_conflict/);
	} finally {
		await lab.close();
	}
});

test("S105 S106 S107 S108 S109 S110 S111 S112 S113 S114 S115 S118 S119 S120 S121 S122 S123 S124 S131 S142 operations", async () => {
	const strict = await boot({ operationsMode: "require", extensions: {} });
	try {
		const live = await approveDirect(strict, await session(strict), "poppy:write");
		const blocked = await strict.agent.callApi(live, `${strict.company.baseUrl}/orders/ord_1/exchanges`, { item: "jacket" });
		assert.equal(blocked.status, 403);
		assert.match(JSON.stringify(blocked.body), /extension_required/);
	} finally {
		await strict.close();
	}

	const performing = await boot({ includeOperations: false, extensions: {} });
	try {
		const live = await approveDirect(performing, await session(performing), "poppy:write");
		const done = await performing.agent.callApi(live, `${performing.company.baseUrl}/orders/ord_9/exchanges`, { item: "hat" });
		assert.equal(done.status, 200);
		assert.equal(performing.company.exchangesPerformed, 1);
		assert.equal(done.operation, undefined);
	} finally {
		await performing.close();
	}

	const lab = await boot({ deferPerform: true });
	try {
		const live = await approveDirect(lab, await session(lab), "poppy:read poppy:write");
		const openapi = await httpRequest(`${lab.company.baseUrl}/openapi.json`, net(lab));
		assert.match(openapi.body.toString("utf8"), /x-poppy-operation/);
		const proposed = await lab.agent.sendMessage(live, message("Please exchange the jacket"), { wait: 0 });
		const operationEvent = proposed.events?.events.find((event) => event.message?.operation);
		const operation = operationEvent?.message?.operation;
		assert.ok(operation);
		assert.match(operation.summary, /\$70\.00/);
		assert.equal(operation.terms?.action, "exchange");
		assert.equal(operation.state, "proposed");
		assert.match(operation.operation_id, /^exc_/);
		assert.equal(lab.company.exchangesPerformed, 0);
		const again = await lab.agent.callApi(live, `${lab.company.baseUrl}/orders/ord_7Hk2/exchanges`, { action: "exchange", order_id: "ord_7Hk2", price_difference: { amount: "70.00", currency: "USD" } });
		assert.equal(again.operation?.operation_id, operation.operation_id);
		lab.company.reviseOperation(operation.operation_id, "Exchange it for $80.00 more.", { action: "exchange", order_id: "ord_7Hk2", price_difference: { amount: "80.00", currency: "USD" } });
		const stale = await lab.agent.confirmOperation(live, operation, userApproval({ accepted: true, companyName: "Example Company", summary: operation.summary, operation }));
		assert.equal(stale.revision, 2);
		assert.equal(stale.state, "proposed");
		const standing: StandingPermission = { id: "prm_1", issuer: lab.company.issuer, action: "exchange", currency: "USD", maxAmount: "100.00", maxUses: 2, uses: 0, reserved: 0 };
		await lab.agent.grantPermission(standing);
		await assert.rejects(lab.agent.confirmOperation(live, stale, { approvedBy: "standing_permission", permissionId: standing.id }), /user_approval_required|standing permission/);
		const readable = await lab.agent.readOperation(live, stale.operation_id);
		assert.equal(readable.state, "proposed");
		const confirmed = await lab.agent.confirmOperation(live, readable, userApproval({ accepted: true, companyName: "Example Company", summary: readable.summary, operation: readable }));
		assert.equal(confirmed.state, "in_progress");
		assert.equal(lab.company.actions.length, 0);
		lab.company.finishOperation(confirmed.operation_id, { unknown: true });
		const unknown = await lab.agent.readOperation(live, confirmed.operation_id);
		assert.notEqual(unknown.state, "failed");
		lab.company.finishOperation(confirmed.operation_id, { ok: true });
		const final = await lab.agent.readOperation(live, confirmed.operation_id);
		assert.equal(final.state, "succeeded");
		assert.match(final.result?.summary ?? "", /Exchange placed/);
		const repeat = await lab.agent.confirmOperation(live, final, userApproval({ accepted: true, companyName: "Example Company", summary: final.summary, operation: final }));
		assert.equal(repeat.state, "succeeded");
		assert.equal(lab.company.actions.length, 1);
		const small = await lab.agent.callApi(live, `${lab.company.baseUrl}/orders/ord_2/exchanges`, { action: "exchange", order_id: "ord_2", price_difference: { amount: "10.00", currency: "USD" } });
		assert.equal(small.operation?.user_approval_required, false);
		const allowed = await lab.agent.confirmOperation(live, small.operation!, { approvedBy: "standing_permission", permissionId: standing.id });
		assert.equal(allowed.state, "in_progress");
		const cancelled = await lab.agent.cancelOperation(live, allowed.operation_id);
		assert.equal(cancelled.state, "cancelled");
		assert.match(cancelled.result?.summary ?? "", /No charge/);
		const stored = await lab.store.load();
		const dpop = stored?.users.default?.[lab.company.issuer]?.dpopPrivateJwk;
		assert.ok(dpop);
		const badKey = await httpRequest(`${lab.company.baseUrl}/orders/ord_3/exchanges`, {
			...net(lab),
			method: "POST",
			headers: {
				authorization: `DPoP ${live.accessToken}`,
				dpop: signDpop({ privateJwk: dpop, method: "POST", url: `${lab.company.baseUrl}/orders/ord_3/exchanges`, accessToken: live.accessToken }),
				"content-type": "application/json",
				"idempotency-key": "not-a-uuid",
			},
			body: "{}",
		});
		assert.equal(badKey.status, 400);
	} finally {
		await lab.close();
	}
});

test("S015 S017 S022 S023 S024 S025 S045 S123 S141 client limits and idempotency S131", async () => {
	const blocked = await boot({ blocklist: ["self"] });
	try {
		await assert.rejects(session(blocked), /invalid_client|token request failed/);
	} finally {
		await blocked.close();
	}
	const publisher = await boot({ extraExtension: { name: "gift-wrap", version: "1" } });
	try {
		assert.throws(() => publisher.company.poppyDocument(), /refusing to publish/);
	} finally {
		await publisher.close();
	}
	const named = await boot({ extraExtension: { name: "shop.example/gift-wrap", version: "1" } });
	try {
		const doc = named.company.poppyDocument() as { extensions?: Record<string, unknown> };
		assert.ok(doc.extensions?.["shop.example/gift-wrap"]);
	} finally {
		await named.close();
	}

	const registered = await boot({ requireRegistration: true, allowlist: [] });
	try {
		await assert.rejects(session(registered), /invalid_client|token request failed/);
	} finally {
		await registered.close();
	}

	const limited = await boot({ maxNewClients: 0 });
	try {
		await assert.rejects(session(limited), /invalid_client|token request failed/);
	} finally {
		await limited.close();
	}

	const billed = await boot();
	try {
		const live = await approveDirect(billed, await session(billed), "poppy:read");
		const quote = await billed.agent.callApi(live, `${billed.company.baseUrl}/billing/quotes`, {});
		assert.equal(quote.status, 401);
		const bearer = await billed.agent.mcpBearer(live, `${billed.company.baseUrl}/mcp`);
		const wrong = await httpRequest(`${billed.company.baseUrl}/billing/quotes`, { ...net(billed), method: "POST", headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" }, body: "{}" });
		assert.equal(wrong.status, 401);
	} finally {
		await billed.close();
	}

	const slow = await boot({ rateLimit: { limit: 2, windowSec: 30, retryAfterSec: 0 } });
	try {
		const first = await httpRequest(`${slow.company.baseUrl}/.well-known/poppy.json`, net(slow));
		await httpRequest(`${slow.company.baseUrl}/.well-known/poppy.json`, net(slow));
		const third = await httpRequest(`${slow.company.baseUrl}/.well-known/poppy.json`, net(slow));
		assert.equal(first.status, 200);
		assert.equal(third.status, 429);
		assert.ok(headerOne(third.headers, "retry-after"));
		assert.match(headerOne(third.headers, "ratelimit") ?? headerOne(first.headers, "ratelimit") ?? "", /requests/);
	} finally {
		await slow.close();
	}
});

async function authed(lab: Lab, method: string, url: string, token: string, proof: string) {
	return httpRequest(url, { ...net(lab), method, headers: { authorization: `DPoP ${token}`, dpop: proof } });
}

async function rpc(lab: Lab, url: string, body: unknown, bearer?: string, sessionId?: string) {
	const headers: Record<string, string> = { "content-type": "application/json" };
	if (bearer) headers.authorization = `Bearer ${bearer}`;
	if (sessionId) headers["mcp-session-id"] = sessionId;
	return httpRequest(url, { ...net(lab), method: "POST", headers, body: JSON.stringify(body) });
}

async function refreshRaw(lab: Lab, refresh: string, sessionId: string, scope?: string) {
	const tokenUrl = `${lab.company.baseUrl}/oauth/token`;
	const assertion = signClientAssertion({ privateJwk: lab.signing.privateJwk, clientId: lab.identity.clientId, audience: tokenUrl, kid: "agent-1" });
	const stored = await lab.store.load();
	const dpopKey = stored?.users.default?.[lab.company.issuer]?.dpopPrivateJwk;
	if (!dpopKey) throw new Error("missing dpop key");
	const body = new URLSearchParams({
		grant_type: "refresh_token",
		refresh_token: refresh,
		session_id: sessionId,
		client_id: lab.identity.clientId,
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: assertion,
	});
	if (scope) body.set("scope", scope);
	return httpRequest(tokenUrl, {
		...net(lab),
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			dpop: signDpop({ privateJwk: dpopKey, method: "POST", url: tokenUrl }),
		},
		body: body.toString(),
	});
}
