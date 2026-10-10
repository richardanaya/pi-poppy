import assert from "node:assert/strict";
import { test } from "node:test";
import { parseJson } from "../src/json.ts";
import {
	SchemaError,
	domainsMatch,
	isKnownExtensionName,
	majorVersion,
	parseAgentMessage,
	parseClientMetadata,
	parseCompanyMessage,
	parseDeviceAuthorizationResponse,
	parseEvent,
	parseEventsResponse,
	parseJsonDocument,
	parseOAuthMetadata,
	parseOperation,
	parsePoppyDocument,
	parseTokenResponse,
	supportedMajor,
	validateScopeString,
} from "../src/schema.ts";

const https = "https://shop.example";

function poppy(extra: Record<string, unknown> = {}) {
	return {
		protocol_version: "0.1",
		organization: { name: "Shop", domain: "shop.example" },
		auth: {
			issuer: https,
			direct: { scopes: ["poppy:read", "poppy:write"] },
			device: { scopes: ["poppy:read"] },
			mediated: {
				endpoint: `${https}/poppy/sign-in`,
				fields: [{ name: "email", label: "Email", secret: false }, { name: "password", label: "Password", secret: true }],
				scopes: ["poppy:read"],
			},
			custom_scopes: { orders: "Read orders" },
		},
		agent: { protocols: [{ type: "poppy", endpoint: `${https}/poppy/conversations`, resource: `${https}/poppy` }] },
		web: { browser_session_endpoint: `${https}/poppy/browser-session` },
		apis: [
			{ type: "openapi", url: `${https}/openapi.json`, description: "Orders" },
			{ type: "mcp", url: `${https}/mcp`, description: "Catalog" },
			{ type: "future", url: `${https}/future`, description: "Later", resource: `${https}/future` },
		],
		extensions: {
			operations: { version: "1", endpoint: `${https}/poppy/operations`, resource: `${https}/ops` },
			"shop.example/gift-wrap": { version: "1", endpoint: `${https}/gift` },
			"not a name": { version: "1" },
		},
		contact: "ignored",
		...extra,
	};
}

test("S008 S009 poppy.json accepts the spec shape and ignores unknown fields", () => {
	const doc = parsePoppyDocument(poppy());
	assert.equal(doc.protocol_version, "0.1");
	assert.equal(doc.agent?.protocols[0]?.resource, `${https}/poppy`);
	assert.equal(doc.extensions?.operations?.resource, `${https}/ops`);
	assert.equal("contact" in doc, false);
	assert.ok(doc.extensions?.["not a name"]);
});

test("poppy.json rejects a bad version, missing auth, and a bad domain", () => {
	assert.throws(() => parsePoppyDocument(poppy({ protocol_version: "v1" })), SchemaError);
	const noAuth = poppy();
	delete (noAuth as { auth?: unknown }).auth;
	assert.throws(() => parsePoppyDocument(noAuth), /auth is required/);
	assert.throws(() => parsePoppyDocument(poppy({ organization: { name: "Shop", domain: "shop.example/path" } })), /domain/);
	assert.equal(supportedMajor("0.9"), true);
	assert.equal(supportedMajor("1.0"), false);
	assert.equal(majorVersion("0.1"), 0);
});

test("oauth metadata requires issuer, token, revocation, and poppy_domains", () => {
	const meta = parseOAuthMetadata({
		issuer: https,
		token_endpoint: `${https}/oauth/token`,
		revocation_endpoint: `${https}/oauth/revoke`,
		authorization_endpoint: `${https}/oauth/authorize`,
		device_authorization_endpoint: `${https}/oauth/device`,
		poppy_domains: ["shop.example"],
		scopes_supported: ["poppy:read"],
	});
	assert.equal(meta.poppy_domains[0], "shop.example");
	assert.equal("scopes_supported" in meta, false);
	assert.throws(() => parseOAuthMetadata({ issuer: "http://shop.example", token_endpoint: `${https}/t`, revocation_endpoint: `${https}/r`, poppy_domains: ["shop.example"] }), /HTTPS/);
});

test("S019 S020 S021 client metadata must match the fetched URL and stay on that domain", () => {
	const url = `${https}/agent.json`;
	const meta = parseClientMetadata({
		client_id: url,
		client_name: "Pi",
		logo_uri: `${https}/logo.png`,
		jwks_uri: `${https}/jwks.json`,
		redirect_uris: [`${https}/oauth/callback`],
		token_endpoint_auth_method: "private_key_jwt",
		extensions: { operations: { version: "1" } },
	}, url);
	assert.equal(meta.client_name, "Pi");
	assert.throws(() => parseClientMetadata({ ...meta, client_id: `${https}/other.json` }, url), /equal the URL/);
	assert.throws(() => parseClientMetadata({
		client_id: url,
		jwks_uri: "https://evil.example/jwks.json",
		redirect_uris: [`${https}/cb`],
	}, url), /same domain/);
});

test("token and device responses", () => {
	const token = parseTokenResponse({
		access_token: "st1_abc",
		token_type: "DPoP",
		expires_in: 3600,
		scope: "poppy:read",
		session_id: "ses_1",
		signed_in: true,
		refresh_token: "pat_1",
		refresh_token_expires_in: 100,
	});
	assert.equal(token.token_type, "DPoP");
	assert.throws(() => parseTokenResponse({ ...token, expires_in: 0 }), /greater than 0/);
	assert.throws(() => parseTokenResponse({ ...token, token_type: "MAC" }), /DPoP or Bearer/);
	const device = parseDeviceAuthorizationResponse({
		device_code: "d",
		user_code: "ABCD",
		verification_uri: `${https}/device`,
		verification_uri_complete: `${https}/device?user_code=ABCD`,
		expires_in: 600,
		interval: 5,
	});
	assert.equal(device.interval, 5);
});

test("agent messages, context, and company messages", () => {
	const message = parseAgentMessage({ id: "msg_1", sender: "human", text: "Where is my order?" });
	assert.equal(message.sender, "human");
	assert.throws(() => parseAgentMessage({ id: "msg_1", sender: "agent" }), /text, data, or context/);
	assert.throws(() => parseAgentMessage({ id: "bad id", sender: "agent", text: "hi" }), /URL-safe/);
	const context = parseAgentMessage({ id: "msg_2", sender: "agent", context: { locale: "en-US", time_zone: "America/Chicago", user_available: false, units: "metric" } });
	assert.equal(context.context?.units, "metric");
	assert.throws(() => parseAgentMessage({ id: "msg_3", sender: "agent", context: { locale: "english" } }), /RFC 5646/);
	assert.throws(() => parseAgentMessage({ id: "msg_4", sender: "agent", context: { time_zone: "Not A Zone" } }), /IANA/);
	const company = parseCompanyMessage({ id: "msg_c", role: "company", sender: "agent", text: "Done", operation: operation("proposed") });
	assert.equal(company.operation?.state, "proposed");
	assert.throws(() => parseCompanyMessage({ id: "msg_c", role: "bot", sender: "agent", text: "x" }), /role/);
});

test("operations and conversation events", () => {
	for (const state of ["proposed", "in_progress", "succeeded", "failed", "cancelled", "expired"] as const) {
		const parsed = parseOperation(operation(state));
		assert.equal(parsed.state, state);
	}
	assert.throws(() => parseOperation({ ...operation("proposed"), expires_at: undefined }), /expires_at/);
	assert.throws(() => parseOperation({ ...operation("succeeded"), result: null }), /result.summary/);
	const events = parseEventsResponse({
		conversation_id: "cnv_1",
		events: [
			{ id: "evt_1", type: "message", created_at: "2026-10-09T12:00:00Z", message: { id: "msg_1", role: "company", sender: "agent", text: "Hello" } },
			{ id: "evt_2", type: "state", created_at: "2026-10-09T12:00:01Z", status: "idle", responder: "agent" },
			{ id: "evt_3", type: "authorization", created_at: "2026-10-09T12:00:02Z", error: "sign_in_required", scope: "poppy:read" },
			{ id: "evt_4", type: "user_requested", created_at: "2026-10-09T12:00:03Z", reason: "Need a decision" },
			{ id: "evt_5", type: "direct_opened", created_at: "2026-10-09T12:00:04Z", conversation_id: "cnv_2" },
			{ id: "evt_6", type: "future_event", created_at: "2026-10-09T12:00:05Z" },
		],
		cursor: "evt_6",
		has_more: false,
		status: "idle",
		responder: "agent",
	});
	assert.equal(events.events[5]?.type, "future_event");
	assert.throws(() => parseEvent({ id: "evt_x", type: "state", created_at: "2026-10-09T12:00:00Z" }), /status and responder/);
	assert.throws(() => parseEventsResponse({ ...events, status: "nope" }), /unknown status/);
});

test("duplicate JSON keys and scope syntax are rejected", () => {
	assert.throws(() => parseJson('{"a":1,"a":2}'), /duplicate/);
	assert.throws(() => parseJsonDocument('{"a":1,"a":2}'), SchemaError);
	assert.deepEqual(validateScopeString("poppy:read orders", false), ["poppy:read", "orders"]);
	assert.throws(() => validateScopeString("poppy:read  orders", false), /invalid scope/);
	assert.equal(domainsMatch("www.shop.example", "shop.example"), true);
	assert.equal(domainsMatch("Shop.Example", "shop.example"), true);
	assert.equal(isKnownExtensionName("operations"), true);
	assert.equal(isKnownExtensionName("shop.example/gift-wrap"), true);
	assert.equal(isKnownExtensionName("gift-wrap"), false);
});

function operation(state: string): Record<string, unknown> {
	return {
		operation_id: "exc_1",
		revision: 1,
		state,
		summary: "Exchange the jacket.",
		terms: { action: "exchange", price_difference: { amount: "70.00", currency: "USD" } },
		expires_at: state === "proposed" ? "2026-10-09T12:15:00Z" : undefined,
		user_approval_required: true,
		url: `${https}/orders/ord_1/exchanges/exc_1`,
		confirmation: state === "proposed" || state === "expired" ? null : { revision: 1, approved_by: "user", confirmed_at: "2026-10-09T12:05:00Z" },
		result: state === "succeeded" || state === "failed" || state === "cancelled" ? { summary: "The exchange changed the order." } : null,
	};
}
