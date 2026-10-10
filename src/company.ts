import { createCipheriv, createDecipheriv, createHash, randomBytes, type JsonWebKey, type KeyObject } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { canonicalJson, isOpaqueId, randomId, safeEqual } from "./codec.ts";
import { accessTokenHash, importPublicJwk, jwkThumbprint, publicOnly, verifyJwt, type JwtHeader } from "./jwt.ts";
import { headerOne, httpRequest } from "./net.ts";
import { parseJson } from "./json.ts";
import {
	isKnownExtensionName,
	parseClientMetadata,
	type ClientMetadata,
	type ConversationEvent,
	type ConversationStatus,
	type Operation,
	type Responder,
	type UserContext,
} from "./schema.ts";

export interface CompanyUser {
	accountId: string;
	email: string;
	password: string;
	otp?: string;
	unusual?: boolean;
}

export interface CompanyOptions {
	cert: string;
	key: string;
	/** CA used when the company fetches a personal agent's client metadata. */
	ca?: string;
	allowLoopback?: boolean;
	domain?: string;
	extraDomains?: string[];
	users?: CompanyUser[];
	directScopes?: string[];
	deviceScopes?: string[];
	mediatedScopes?: string[];
	customScopes?: Record<string, string>;
	includeAgent?: boolean;
	includeWeb?: boolean;
	includeBrowser?: boolean;
	includeApis?: boolean;
	includeOperations?: boolean;
	/** What to do when the personal agent does not list the operations extension. */
	operationsMode?: "perform" | "require";
	requireNonce?: boolean;
	allowlist?: string[];
	blocklist?: string[];
	requireRegistration?: boolean;
	maxNewClients?: number;
	endSessionsOnSignOut?: boolean;
	rotateRefreshTokens?: boolean;
	sessionTokenTtlSec?: number;
	sessionTtlSec?: number;
	accountTtlSec?: number;
	rateLimit?: { limit: number; windowSec: number; retryAfterSec: number };
	mediatedMaxAttempts?: number;
	handoff?: "queue" | "unavailable";
	streamDeltas?: boolean;
	sseKeepaliveMs?: number;
	waitCapSec?: number;
	pageSize?: number;
	deferPerform?: boolean;
	deferReplyMs?: number;
	extraApiType?: string;
	/** Publish an extension name. Invalid names are rejected by the publisher. */
	extraExtension?: { name: string; version: string; endpoint?: string };
	protocolVersion?: string;
	/** 302 the well-known URL to /hosted/poppy.json. */
	redirectWellKnown?: boolean;
	/** Redirect the well-known URL to a non-HTTPS location. */
	badRedirect?: boolean;
}

interface SessionRecord {
	id: string;
	clientId: string;
	userId: string;
	accountId?: string;
	boundAccountId?: string;
	ended: boolean;
	expiresAt: number;
	createdAt: number;
}

interface AccountRecord {
	token: string;
	clientId: string;
	userId: string;
	accountId: string;
	scope: string;
	expiresAt: number;
	revoked: boolean;
}

interface TokenPayload {
	sid: string;
	cid: string;
	uid: string;
	scope: string;
	signedIn: boolean;
	accountId?: string;
	jkt?: string;
	resource?: string;
	typ: "dpop" | "bearer";
	exp: number;
}

interface AuthzRequest {
	formToken: string;
	clientId: string;
	redirectUri: string;
	scope: string[];
	state: string;
	challenge: string;
	method: string;
	expiresAt: number;
}

interface AuthCode {
	code: string;
	clientId: string;
	redirectUri: string;
	scope: string;
	accountId: string;
	userId: string;
	challenge: string;
	expiresAt: number;
	used: boolean;
}

interface DeviceRequest {
	deviceCode: string;
	userCode: string;
	clientId: string;
	scope: string[];
	expiresAt: number;
	interval: number;
	nextPollAt: number;
	status: "pending" | "approved" | "denied";
	accountId?: string;
	approvedScope?: string;
	formToken: string;
}

interface MediatedAttempt {
	id: string;
	sessionId: string;
	clientId: string;
	userId: string;
	accountId: string;
	scope: string;
	otp: string;
	expiresAt: number;
	tries: number;
	sentTo: string;
}

interface Conv {
	id: string;
	clientId: string;
	userId: string;
	accountId?: string;
	parentId?: string;
	directId?: string;
	isDirect: boolean;
	status: ConversationStatus;
	responder: Responder;
	events: ConversationEvent[];
	context: UserContext;
}

interface OpRecord {
	operation: Operation;
	revisions: Array<{ revision: number; summary: string; terms?: Record<string, unknown>; expiresAt: string }>;
	clientId: string;
	userId: string;
	sessionId: string;
	accountId?: string;
	performed: number;
	termsKey: string;
}

interface SeenClient {
	meta: ClientMetadata;
	keys: Map<string, KeyObject>;
	fetchedAt: number;
}

class CompanyError extends Error {
	readonly status: number;
	readonly code: string;
	readonly description: string;
	readonly extra: { headers?: Record<string, string>; body?: Record<string, unknown>; www?: string };
	constructor(
		status: number,
		code: string,
		description: string,
		extra: { headers?: Record<string, string>; body?: Record<string, unknown>; www?: string } = {},
	) {
		super(description);
		this.status = status;
		this.code = code;
		this.description = description;
		this.extra = extra;
	}
}

/**
 * Company side of Personal Agent Protocol draft 0.1: discovery, OAuth sessions,
 * mediated sign-in, browser sessions, conversations, operations, OpenAPI, and MCP.
 */
export class CompanyServer {
	baseUrl = "";
	private server: ReturnType<typeof createServer> | undefined;
	private readonly key = randomBytes(32);
	private readonly nonce = randomId(16);
	private readonly sessions = new Map<string, SessionRecord>();
	private readonly accounts = new Map<string, AccountRecord>();
	private readonly cookies = new Map<string, { sessionId: string; expiresAt: number }>();
	private readonly authz = new Map<string, AuthzRequest>();
	private readonly codes = new Map<string, AuthCode>();
	private readonly devices = new Map<string, DeviceRequest>();
	private readonly devicesByUserCode = new Map<string, DeviceRequest>();
	private readonly mediated = new Map<string, MediatedAttempt>();
	private readonly conversations = new Map<string, Conv>();
	private readonly messageIndex = new Map<string, { conversationId: string; canonical: string }>();
	private readonly operations = new Map<string, OpRecord>();
	private readonly clients = new Map<string, SeenClient>();
	private readonly seenJti = new Map<string, number>();
	private readonly expiredCursors = new Set<string>();
	private readonly hits: number[] = [];
	private readonly idempotency = new Map<string, { hash: string; status: number; body: string }>();
	private readonly mcpSessions = new Set<string>();
	private readonly waiters = new Map<string, Array<() => void>>();
	private newClients = new Set<string>();
	private mediatedFails = new Map<string, number>();
	readonly actions: string[] = [];
	exchangesPerformed = 0;

	private readonly options: CompanyOptions;
	constructor(options: CompanyOptions) {
		this.options = options;
	}

	get issuer(): string {
		return this.baseUrl;
	}

	get domain(): string {
		return this.options.domain ?? "127.0.0.1";
	}

	async start(): Promise<void> {
		this.server = createServer({ cert: this.options.cert, key: this.options.key }, (req, res) => {
			void this.dispatch(req, res);
		});
		await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", resolve));
		const port = (this.server.address() as AddressInfo).port;
		this.baseUrl = `https://127.0.0.1:${port}`;
	}

	async close(): Promise<void> {
		const server = this.server;
		this.server = undefined;
		if (!server) return;
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}

	poppyDocument(): Record<string, unknown> {
		const doc: Record<string, unknown> = {
			protocol_version: this.options.protocolVersion ?? "0.1",
			organization: { name: "Example Company", domain: this.domain },
			contact: "support@example.com",
		};
		const auth: Record<string, unknown> = { issuer: this.issuer };
		const direct = this.options.directScopes ?? ["poppy:read", "poppy:write"];
		const device = this.options.deviceScopes ?? ["poppy:read", "poppy:write"];
		const mediated = this.options.mediatedScopes ?? ["poppy:read"];
		if (direct.length) auth.direct = { scopes: direct };
		if (device.length) auth.device = { scopes: device };
		if (mediated.length) {
			auth.mediated = {
				endpoint: `${this.baseUrl}/poppy/sign-in`,
				fields: [
					{ name: "email", label: "Email", secret: false },
					{ name: "password", label: "Password", secret: true },
				],
				scopes: mediated,
			};
		}
		if (this.options.customScopes) auth.custom_scopes = this.options.customScopes;
		const agent = this.options.includeAgent !== false;
		const apis = this.options.includeApis !== false;
		const web = this.options.includeWeb !== false;
		if (agent || apis || (web && this.options.includeBrowser !== false)) doc.auth = auth;
		if (agent) {
			doc.agent = { protocols: [{ type: "poppy", endpoint: `${this.baseUrl}/poppy/conversations` }, ...(this.options.extraApiType ? [] : [])] };
		}
		if (apis) {
			const list: Record<string, unknown>[] = [
				{ type: "openapi", url: `${this.baseUrl}/openapi.json`, description: "Orders, returns, and exchanges" },
				{ type: "mcp", url: `${this.baseUrl}/mcp`, description: "Product search and sizing" },
				{ type: "openapi", url: `${this.baseUrl}/openapi.json`, description: "Billing quotes", resource: `${this.baseUrl}/billing` },
			];
			if (this.options.extraApiType) list.push({ type: this.options.extraApiType, url: `${this.baseUrl}/future`, description: "Future API" });
			doc.apis = list;
		}
		if (web) {
			doc.web = this.options.includeBrowser === false ? {} : { browser_session_endpoint: `${this.baseUrl}/poppy/browser-session` };
		}
		const extensions: Record<string, unknown> = {};
		if (this.options.includeOperations !== false) {
			extensions.operations = { version: "1", endpoint: `${this.baseUrl}/poppy/operations` };
		}
		if (this.options.extraExtension) {
			const extra = this.options.extraExtension;
			if (!isKnownExtensionName(extra.name)) throw new Error(`refusing to publish extension name ${extra.name}`);
			extensions[extra.name] = { version: extra.version, endpoint: extra.endpoint ?? `${this.baseUrl}/ext` };
		}
		if (Object.keys(extensions).length) doc.extensions = extensions;
		return doc;
	}

	finishOperation(operationId: string, outcome: { ok: boolean } | { unknown: true }): Operation {
		const record = this.operations.get(operationId);
		if (!record) throw new Error("missing operation");
		if (outcome && "unknown" in outcome) return record.operation;
		if (record.operation.state === "succeeded" || record.operation.state === "failed" || record.operation.state === "cancelled" || record.operation.state === "expired") {
			return record.operation;
		}
		if (!record.performed) {
			record.performed = 1;
			this.actions.push(operationId);
			this.exchangesPerformed += 1;
		}
		record.operation.state = outcome.ok ? "succeeded" : "failed";
		record.operation.result = {
			summary: outcome.ok
				? "Exchange placed. The insulated jacket ships today, and a return label for the original jacket was emailed."
				: "The exchange did not complete. No charge was made.",
			data: outcome.ok ? { exchange_id: operationId } : { exchange_id: operationId, charged: false },
		};
		return record.operation;
	}

	reviseOperation(operationId: string, summary: string, terms: Record<string, unknown>): Operation {
		const record = this.mustOp(operationId);
		if (record.operation.state !== "proposed") throw new Error("only proposed operations can be revised");
		const revision = record.operation.revision + 1;
		const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
		record.revisions.push({ revision, summary, terms, expiresAt });
		record.operation = {
			...record.operation,
			revision,
			summary,
			terms,
			expires_at: expiresAt,
			confirmation: null,
			result: null,
		};
		return record.operation;
	}

	injectEvent(conversationId: string, event: ConversationEvent): void {
		const conv = this.conversations.get(conversationId);
		if (!conv) throw new Error("missing conversation");
		conv.events.push(event);
		this.wake(conversationId);
	}

	joinHuman(conversationId: string): void {
		const conv = this.conversations.get(conversationId);
		if (!conv) throw new Error("missing conversation");
		this.setStatus(conv, conv.status === "queued" ? "idle" : conv.status, "human");
		this.addCompanyMessage(conv, "agent", "A person at the company has joined.");
		this.setStatus(conv, "idle", "human");
	}

	dropHistory(conversationId: string): void {
		const conv = this.conversations.get(conversationId);
		if (!conv) throw new Error("missing conversation");
		for (const event of conv.events) this.expiredCursors.add(`${conversationId}:${event.id}`);
		conv.events = [];
	}

	private async dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
		const url = new URL(req.url ?? "/", this.baseUrl);
		try {
			if (url.searchParams.has("access_token") || url.searchParams.has("token") || url.searchParams.has("refresh_token")) {
				throw new CompanyError(400, "invalid_request", "tokens must not be sent in a URL");
			}
			this.consumeRate(headerOne(req.headers, "x-client-hint"));
			const path = url.pathname;
			if (req.method === "GET" && path === "/.well-known/poppy.json") {
				if (this.options.badRedirect) {
					res.writeHead(302, { location: "http://127.0.0.1/poppy.json" });
					res.end();
					return;
				}
				if (this.options.redirectWellKnown) {
					res.writeHead(302, { location: `${this.baseUrl}/hosted/poppy.json`, "cache-control": "max-age=120" });
					res.end();
					return;
				}
				return this.send(res, 200, this.poppyDocument(), { "cache-control": "max-age=120" });
			}
			if (req.method === "GET" && path === "/hosted/poppy.json") return this.send(res, 200, this.poppyDocument(), { "cache-control": "max-age=120" });
			if (req.method === "GET" && path === "/.well-known/oauth-authorization-server") return this.send(res, 200, this.metadata(), { "cache-control": "max-age=120" });
			if (req.method === "GET" && path === "/.well-known/oauth-protected-resource/mcp") {
				return this.send(res, 200, {
					resource: `${this.baseUrl}/mcp`,
					authorization_servers: [this.issuer],
					bearer_methods_supported: ["header"],
				});
			}
			if (req.method === "POST" && path === "/oauth/token") return await this.token(req, res, url);
			if (req.method === "POST" && path === "/oauth/revoke") return await this.revoke(req, res, url);
			if (path === "/oauth/authorize") return await this.authorize(req, res, url);
			if (req.method === "POST" && path === "/oauth/device") return await this.deviceStart(req, res, url);
			if (path === "/device") return await this.devicePage(req, res, url);
			if (req.method === "POST" && path === "/poppy/sign-in") return await this.mediatedStart(req, res, url);
			const mediated = /^\/poppy\/sign-in\/([^/]+)$/.exec(path);
			if (req.method === "POST" && mediated) return await this.mediatedCode(req, res, url, mediated[1]!);
			if (req.method === "POST" && path === "/poppy/browser-session") return await this.browser(req, res, url);
			if (req.method === "POST" && path === "/poppy/conversations") return await this.openConversation(req, res, url);
			const messages = /^\/poppy\/conversations\/([^/]+)\/messages$/.exec(path);
			if (req.method === "POST" && messages) return await this.postMessage(req, res, url, messages[1]!);
			const events = /^\/poppy\/conversations\/([^/]+)\/events$/.exec(path);
			if (req.method === "GET" && events) return await this.readEvents(req, res, url, events[1]!);
			const handoff = /^\/poppy\/conversations\/([^/]+)\/handoff$/.exec(path);
			if (req.method === "POST" && handoff) return await this.handoff(req, res, url, handoff[1]!);
			const close = /^\/poppy\/conversations\/([^/]+)\/close$/.exec(path);
			if (req.method === "POST" && close) return await this.closeConversation(req, res, url, close[1]!);
			const opGet = /^\/poppy\/operations\/([^/]+)$/.exec(path);
			if (req.method === "GET" && opGet) return await this.readOperation(req, res, url, opGet[1]!);
			const opConfirm = /^\/poppy\/operations\/([^/]+)\/confirm$/.exec(path);
			if (req.method === "POST" && opConfirm) return await this.confirmOperation(req, res, url, opConfirm[1]!);
			const opCancel = /^\/poppy\/operations\/([^/]+)\/cancel$/.exec(path);
			if (req.method === "POST" && opCancel) return await this.cancelOperation(req, res, url, opCancel[1]!);
			if (req.method === "GET" && path === "/openapi.json") return this.send(res, 200, this.openApi());
			const exchange = /^\/orders\/([^/]+)\/exchanges$/.exec(path);
			if (req.method === "POST" && exchange) return await this.exchange(req, res, url, exchange[1]!);
			if (req.method === "POST" && path === "/billing/quotes") return await this.billing(req, res, url);
			if (path === "/mcp") return await this.mcp(req, res, url);
			if (req.method === "GET" && path === "/whoami") return this.whoami(req, res);
			const webConfirm = /^\/ops\/([^/]+)\/web-confirm$/.exec(path);
			if (req.method === "POST" && webConfirm) return await this.webConfirm(req, res, webConfirm[1]!);
			this.send(res, 404, { error: "not_found" });
		} catch (error) {
			if (res.headersSent) {
				res.end();
				return;
			}
			if (error instanceof CompanyError) {
				const headers: Record<string, string> = { ...(error.extra.headers ?? {}) };
				if (error.extra.www) headers["www-authenticate"] = error.extra.www;
				if (error.status === 429) headers["retry-after"] = String(this.options.rateLimit?.retryAfterSec ?? 1);
				this.send(res, error.status, { error: error.code, error_description: error.description, ...(error.extra.body ?? {}) }, headers);
				return;
			}
			this.send(res, 500, { error: "server_error", error_description: "internal error" });
		}
	}

	private metadata(): Record<string, unknown> {
		const direct = this.options.directScopes ?? ["poppy:read", "poppy:write"];
		const device = this.options.deviceScopes ?? ["poppy:read", "poppy:write"];
		const body: Record<string, unknown> = {
			issuer: this.issuer,
			token_endpoint: `${this.baseUrl}/oauth/token`,
			revocation_endpoint: `${this.baseUrl}/oauth/revoke`,
			poppy_domains: [this.domain, ...(this.options.extraDomains ?? [])],
			scopes_supported: ["poppy:read", "poppy:write"],
		};
		if (direct.length) body.authorization_endpoint = `${this.baseUrl}/oauth/authorize`;
		if (device.length) body.device_authorization_endpoint = `${this.baseUrl}/oauth/device`;
		return body;
	}

	private async token(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		const form = await this.form(req);
		const client = await this.authenticateClient(form, `${this.baseUrl}/oauth/token`);
		const proof = await this.optionalProof(req, url);
		const grant = form.get("grant_type") ?? "";
		if (grant === "urn:ietf:params:oauth:grant-type:jwt-bearer") {
			const assertion = form.get("assertion") ?? "";
			const verified = await this.verifyClientJwt(assertion, client, `${this.baseUrl}/oauth/token`, true);
			const sub = stringClaim(verified.payload.sub);
			if (verified.payload.iss !== client.meta.client_id) throw new CompanyError(400, "invalid_grant", "iss must be the client_id");
			const sessionId = form.get("session_id");
			const session = sessionId ? this.requireSession(sessionId, client.meta.client_id, sub) : this.createSession(client.meta.client_id, sub);
			const resource = form.get("resource") ?? undefined;
			if (!proof) {
				if (resource !== `${this.baseUrl}/mcp`) throw this.dpopError("invalid_dpop_proof", "DPoP proof required");
				const token = this.issue(session, { scope: "", signedIn: false, type: "bearer", resource });
				return this.send(res, 200, this.tokenBody(token, session, "", false), { "cache-control": "no-store" });
			}
			const token = this.issue(session, { scope: "", signedIn: false, jkt: proof.jkt, type: "dpop", resource });
			return this.send(res, 200, this.tokenBody(token, session, "", false), { "cache-control": "no-store" });
		}
		if (grant === "authorization_code") {
			if (!proof) throw this.dpopError("invalid_dpop_proof", "DPoP proof required");
			return this.exchangeCode(form, client, proof.jkt, res);
		}
		if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
			if (!proof) throw this.dpopError("invalid_dpop_proof", "DPoP proof required");
			return this.exchangeDevice(form, client, proof.jkt, res);
		}
		if (grant === "refresh_token") {
			return this.refresh(form, client, proof, res);
		}
		throw new CompanyError(400, "unsupported_grant_type", "unsupported grant_type");
	}

	private exchangeCode(form: URLSearchParams, client: SeenClient, jkt: string, res: ServerResponse): void {
		const code = this.codes.get(form.get("code") ?? "");
		if (!code || code.used || code.expiresAt < Date.now() || code.clientId !== client.meta.client_id) {
			throw new CompanyError(400, "invalid_grant", "authorization code is invalid");
		}
		if (code.redirectUri !== (form.get("redirect_uri") ?? "")) throw new CompanyError(400, "invalid_grant", "redirect_uri mismatch");
		const verifier = form.get("code_verifier") ?? "";
		const challenge = base64UrlSha(verifier);
		if (!safeEqual(challenge, code.challenge)) throw new CompanyError(400, "invalid_grant", "pkce verification failed");
		code.used = true;
		const session = this.sessions.get(form.get("session_id") ?? "");
		if (!session || session.ended || session.expiresAt < Date.now() || session.clientId !== client.meta.client_id) {
			throw new CompanyError(400, "invalid_session", "session has ended or belongs to someone else");
		}
		if (code.userId && code.userId !== session.userId) throw new CompanyError(400, "invalid_session", "session belongs to a different user");
		code.userId = session.userId;
		this.bindAccount(session, code.accountId);
		const account = this.saveAccount(client.meta.client_id, code.userId, code.accountId, code.scope);
		const token = this.issue(session, { scope: code.scope, signedIn: true, accountId: code.accountId, jkt, type: "dpop" });
		this.send(res, 200, this.tokenBody(token, session, code.scope, true, account), { "cache-control": "no-store" });
	}

	private exchangeDevice(form: URLSearchParams, client: SeenClient, jkt: string, res: ServerResponse): void {
		const device = this.devices.get(form.get("device_code") ?? "");
		if (!device || device.clientId !== client.meta.client_id) throw new CompanyError(400, "invalid_grant", "device code is invalid");
		if (device.expiresAt < Date.now()) throw new CompanyError(400, "expired_token", "device code expired");
		const now = Date.now();
		if (now < device.nextPollAt) {
			device.interval += 5;
			device.nextPollAt = now + device.interval * 1000;
			throw new CompanyError(400, "slow_down", "polling too frequently");
		}
		device.nextPollAt = now + device.interval * 1000;
		if (device.status === "pending") throw new CompanyError(400, "authorization_pending", "the user has not finished");
		if (device.status === "denied") throw new CompanyError(400, "access_denied", "the user declined");
		const session = this.sessions.get(form.get("session_id") ?? "");
		if (!session || session.ended || session.expiresAt < Date.now() || session.clientId !== client.meta.client_id) {
			throw new CompanyError(400, "invalid_session", "session has ended or belongs to someone else");
		}
		this.bindAccount(session, device.accountId!);
		const scope = device.approvedScope ?? device.scope.join(" ");
		const account = this.saveAccount(client.meta.client_id, session.userId, device.accountId!, scope);
		const token = this.issue(session, { scope, signedIn: true, accountId: device.accountId, jkt, type: "dpop" });
		this.devices.delete(device.deviceCode);
		this.devicesByUserCode.delete(device.userCode);
		this.send(res, 200, this.tokenBody(token, session, scope, true, account), { "cache-control": "no-store" });
	}

	private refresh(form: URLSearchParams, client: SeenClient, proof: { jkt: string } | undefined, res: ServerResponse): void {
		const account = this.accounts.get(form.get("refresh_token") ?? "");
		if (!account || account.revoked || account.expiresAt < Date.now() || account.clientId !== client.meta.client_id) {
			throw new CompanyError(400, "invalid_grant", "account token is invalid");
		}
		const resource = form.get("resource") ?? undefined;
		const requested = form.get("scope");
		const scope = requested === null ? account.scope : this.narrow(account.scope, requested);
		let session: SessionRecord;
		const sessionId = form.get("session_id");
		if (sessionId) {
			session = this.requireSession(sessionId, client.meta.client_id, account.userId);
			if (session.boundAccountId && session.boundAccountId !== account.accountId) {
				throw new CompanyError(400, "account_mismatch", "session is signed in to a different account");
			}
			session.accountId = account.accountId;
			session.boundAccountId = account.accountId;
		} else {
			session = this.createSession(client.meta.client_id, account.userId);
			session.accountId = account.accountId;
			session.boundAccountId = account.accountId;
		}
		const mcp = resource === `${this.baseUrl}/mcp`;
		if (!proof) {
			if (!mcp) throw this.dpopError("invalid_dpop_proof", "Bearer tokens are issued only for MCP");
			const token = this.issue(session, { scope, signedIn: true, accountId: account.accountId, type: "bearer", resource });
			return this.send(res, 200, this.tokenBody(token, session, scope, true), { "cache-control": "no-store" });
		}
		const token = this.issue(session, { scope, signedIn: true, accountId: account.accountId, jkt: proof.jkt, type: "dpop", resource });
		let next = account;
		if (this.options.rotateRefreshTokens) {
			account.revoked = true;
			next = this.saveAccount(account.clientId, account.userId, account.accountId, account.scope);
		}
		this.send(res, 200, this.tokenBody(token, session, scope, true, this.options.rotateRefreshTokens ? next : undefined), { "cache-control": "no-store" });
	}

	private async revoke(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		const form = await this.form(req);
		const client = await this.authenticateClient(form, `${this.baseUrl}/oauth/revoke`);
		void url;
		const account = this.accounts.get(form.get("token") ?? "");
		if (account && account.clientId === client.meta.client_id) {
			account.revoked = true;
			for (const session of this.sessions.values()) {
				if (session.accountId === account.accountId && session.clientId === account.clientId) {
					session.accountId = undefined;
					if (this.options.endSessionsOnSignOut) session.ended = true;
				}
			}
		}
		this.send(res, 200, {}, { "cache-control": "no-store" });
	}

	private async authorize(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		if (req.method === "GET") {
			const client = await this.loadClient(url.searchParams.get("client_id") ?? "");
			const redirect = url.searchParams.get("redirect_uri") ?? "";
			if (!client.meta.redirect_uris.includes(redirect)) throw new CompanyError(400, "invalid_request", "redirect_uri is not registered");
			if (url.searchParams.get("code_challenge_method") !== "S256") throw new CompanyError(400, "invalid_request", "PKCE S256 is required");
			const scope = (url.searchParams.get("scope") ?? "").split(" ").filter(Boolean);
			this.assertScopes(scope, this.options.directScopes ?? ["poppy:read", "poppy:write"]);
			const request: AuthzRequest = {
				formToken: randomId(16),
				clientId: client.meta.client_id,
				redirectUri: redirect,
				scope,
				state: url.searchParams.get("state") ?? "",
				challenge: url.searchParams.get("code_challenge") ?? "",
				method: "S256",
				expiresAt: Date.now() + 10 * 60_000,
			};
			this.authz.set(request.formToken, request);
			const checks = scope.map((item) => `<label><input type="checkbox" name="scope" value="${escapeHtml(item)}" checked> ${escapeHtml(item)}</label>`).join("");
			const html = `<!doctype html><title>Approve</title><p>${escapeHtml(client.meta.client_name ?? "Personal agent")} (${escapeHtml(new URL(client.meta.client_id).hostname)})</p><form method="post" action="/oauth/authorize"><input type="hidden" name="form_token" value="${request.formToken}"><label>Email <input name="email"></label><label>Password <input type="password" name="password"></label>${checks}<button name="decision" value="approve">Approve</button><button name="decision" value="deny">Decline</button></form>`;
			res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "frame-ancestors 'none'", "cache-control": "no-store" });
			res.end(html);
			return;
		}
		const form = await this.form(req);
		const request = this.authz.get(form.get("form_token") ?? "");
		if (!request || request.expiresAt < Date.now()) throw new CompanyError(400, "invalid_request", "authorization request expired");
		this.authz.delete(request.formToken);
		const iss = encodeURIComponent(this.issuer);
		const state = encodeURIComponent(request.state);
		if (form.get("decision") !== "approve") {
			res.writeHead(302, { location: `${request.redirectUri}?error=access_denied&state=${state}&iss=${iss}`, "cache-control": "no-store" });
			res.end();
			return;
		}
		const user = this.checkPassword(form.get("email") ?? "", form.get("password") ?? "");
		if (!user) throw new CompanyError(400, "access_denied", "sign-in failed");
		const selected = form.getAll("scope");
		const granted = request.scope.filter((item) => selected.includes(item));
		this.assertScopes(granted, this.options.directScopes ?? ["poppy:read", "poppy:write"]);
		if (granted.some((item) => !request.scope.includes(item))) throw new CompanyError(400, "invalid_scope", "scope was not requested");
		const code = randomId(16);
		this.codes.set(code, {
			code,
			clientId: request.clientId,
			redirectUri: request.redirectUri,
			scope: granted.join(" "),
			accountId: user.accountId,
			userId: "",
			challenge: request.challenge,
			expiresAt: Date.now() + 60_000,
			used: false,
		});
		res.writeHead(302, { location: `${request.redirectUri}?code=${encodeURIComponent(code)}&state=${state}&iss=${iss}`, "cache-control": "no-store" });
		res.end();
	}

	private async deviceStart(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		void url;
		const form = await this.form(req);
		const client = await this.authenticateClient(form, `${this.baseUrl}/oauth/device`);
		const scope = (form.get("scope") ?? "").split(" ").filter(Boolean);
		this.assertScopes(scope, this.options.deviceScopes ?? ["poppy:read", "poppy:write"]);
		const device: DeviceRequest = {
			deviceCode: randomId(16),
			userCode: randomId(4).slice(0, 8).toUpperCase(),
			clientId: client.meta.client_id,
			scope,
			expiresAt: Date.now() + 10 * 60_000,
			interval: 5,
			nextPollAt: 0,
			status: "pending",
			formToken: randomId(16),
		};
		this.devices.set(device.deviceCode, device);
		this.devicesByUserCode.set(device.userCode, device);
		this.send(res, 200, {
			device_code: device.deviceCode,
			user_code: device.userCode,
			verification_uri: `${this.baseUrl}/device`,
			verification_uri_complete: `${this.baseUrl}/device?user_code=${encodeURIComponent(device.userCode)}`,
			expires_in: 600,
			interval: device.interval,
		}, { "cache-control": "no-store" });
	}

	private async devicePage(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		if (req.method === "GET") {
			const code = url.searchParams.get("user_code") ?? "";
			const html = `<!doctype html><title>Device</title><p>Enter the code shown by your personal agent. Opening this page does not approve access.</p><form method="post"><input name="user_code" value="${escapeHtml(code)}"><label>Email <input name="email"></label><label>Password <input type="password" name="password"></label><button name="decision" value="approve">Approve</button><button name="decision" value="deny">Decline</button></form>`;
			res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "frame-ancestors 'none'", "cache-control": "no-store" });
			res.end(html);
			return;
		}
		const form = await this.form(req);
		const device = this.devicesByUserCode.get(form.get("user_code") ?? "");
		if (!device || device.expiresAt < Date.now()) throw new CompanyError(400, "expired_token", "device request expired");
		if (form.get("decision") !== "approve") {
			device.status = "denied";
			this.send(res, 200, { status: "denied" });
			return;
		}
		const user = this.checkPassword(form.get("email") ?? "", form.get("password") ?? "");
		if (!user) {
			device.status = "denied";
			this.send(res, 200, { status: "denied" });
			return;
		}
		device.status = "approved";
		device.accountId = user.accountId;
		device.approvedScope = device.scope.join(" ");
		this.send(res, 200, { status: "approved" });
	}

	private async mediatedStart(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		const auth = await this.dpopAuth(req, url, false);
		const body = await this.jsonBody(req);
		const scope = typeof body.scope === "string" ? body.scope : "";
		const parts = scope.split(" ").filter(Boolean);
		this.assertScopes(parts, this.options.mediatedScopes ?? ["poppy:read"]);
		const credentials = body.credentials;
		if (!credentials || typeof credentials !== "object") throw new CompanyError(400, "invalid_request", "credentials required");
		const email = String((credentials as { email?: unknown }).email ?? "");
		const password = String((credentials as { password?: unknown }).password ?? "");
		const key = `${auth.session.clientId}:${auth.session.userId}:${email}`;
		const fails = this.mediatedFails.get(key) ?? 0;
		if (fails >= (this.options.mediatedMaxAttempts ?? 5)) throw new CompanyError(429, "rate_limited", "too many sign-in attempts");
		const user = (this.options.users ?? []).find((item) => safeEqual(item.email, email) && safeEqual(item.password, password));
		if (!user) {
			this.mediatedFails.set(key, fails + 1);
			this.send(res, 200, { status: "failed" });
			return;
		}
		if (user.unusual) {
			const attempt: MediatedAttempt = {
				id: `sgn_${randomId(8)}`,
				sessionId: auth.session.id,
				clientId: auth.session.clientId,
				userId: auth.session.userId,
				accountId: user.accountId,
				scope,
				otp: user.otp ?? "000000",
				expiresAt: Date.now() + 5 * 60_000,
				tries: 0,
				sentTo: "Text to the phone number ending in 71",
			};
			this.mediated.set(attempt.id, attempt);
			this.send(res, 200, { status: "code_required", sign_in_id: attempt.id, code: { sent_to: attempt.sentTo }, expires_at: new Date(attempt.expiresAt).toISOString() });
			return;
		}
		this.completeMediated(res, auth.session, user.accountId, scope, auth.token.jkt ?? "");
	}

	private async mediatedCode(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, false);
		const attempt = this.mediated.get(id);
		if (!attempt || attempt.sessionId !== auth.session.id) throw new CompanyError(400, "invalid_grant", "sign-in not found");
		if (attempt.expiresAt < Date.now()) {
			this.send(res, 200, { status: "expired" });
			return;
		}
		const body = await this.jsonBody(req);
		if ("credentials" in body) throw new CompanyError(400, "invalid_request", "submit only the code");
		const code = typeof body.code === "string" ? body.code : "";
		if (!safeEqual(code, attempt.otp)) {
			attempt.tries += 1;
			if (attempt.tries >= (this.options.mediatedMaxAttempts ?? 5)) {
				this.send(res, 200, { status: "failed" });
				return;
			}
			this.send(res, 200, { status: "code_required", sign_in_id: attempt.id, code: { sent_to: attempt.sentTo }, expires_at: new Date(attempt.expiresAt).toISOString() });
			return;
		}
		this.mediated.delete(id);
		this.completeMediated(res, auth.session, attempt.accountId, attempt.scope, auth.token.jkt ?? "");
	}

	private completeMediated(res: ServerResponse, session: SessionRecord, accountId: string, scope: string, jkt: string): void {
		this.bindAccount(session, accountId);
		const account = this.saveAccount(session.clientId, session.userId, accountId, scope);
		const token = this.issue(session, { scope, signedIn: true, accountId, jkt, type: "dpop" });
		this.send(res, 200, { status: "complete", ...this.tokenBody(token, session, scope, true, account) }, { "cache-control": "no-store" });
	}

	private recentJkt = new Map<string, string>();

	private async browser(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		if (url.searchParams.has("assertion")) throw new CompanyError(400, "invalid_request", "assertion must be in the body");
		const form = await this.form(req);
		const assertion = form.get("assertion") ?? "";
		let header: JwtHeader;
		try {
			header = JSON.parse(Buffer.from(assertion.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
		} catch {
			throw new CompanyError(400, "invalid_request", "malformed assertion");
		}
		if (header.typ !== "poppy-browser+jwt") throw new CompanyError(400, "invalid_request", "typ must be poppy-browser+jwt");
		const client = await this.loadClient(String(JSON.parse(Buffer.from(assertion.split(".")[1] ?? "", "base64url").toString("utf8")).iss ?? ""));
		const key = this.keyFor(client, header.kid);
		const verified = verifyJwt(assertion, key, {
			audience: `${this.baseUrl}/poppy/browser-session`,
			typ: "poppy-browser+jwt",
			maxLifetimeSec: 60,
			requireStringAud: true,
		});
		this.rememberJti(`browser:${stringClaim(verified.payload.jti)}`, numberClaim(verified.payload.exp) * 1000, "invalid_request");
		const session = this.requireSession(stringClaim(verified.payload.session_id), client.meta.client_id, stringClaim(verified.payload.sub));
		const returnTo = stringClaim(verified.payload.return_to);
		this.assertReturnTo(returnTo);
		const cookie = randomId(18);
		const maxAge = Math.max(1, Math.floor((session.expiresAt - Date.now()) / 1000));
		this.cookies.set(cookie, { sessionId: session.id, expiresAt: session.expiresAt });
		res.writeHead(303, {
			location: returnTo,
			"set-cookie": `poppy_session=${cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`,
			"cache-control": "no-store",
		});
		res.end();
	}

	private whoami(req: IncomingMessage, res: ServerResponse): void {
		const session = this.sessionFromCookie(req);
		if (!session) return this.send(res, 200, { guest: true, signed_in: false });
		this.send(res, 200, { guest: false, signed_in: Boolean(session.accountId), scope: session.accountId ? this.accountScope(session) : "", session_id: session.id });
	}

	private async openConversation(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		const auth = await this.dpopAuth(req, url, true);
		const body = await this.jsonBody(req);
		const message = this.userMessage(body.message, auth);
		const parentId = typeof body.parent_conversation_id === "string" ? body.parent_conversation_id : undefined;
		let conv: Conv;
		const existing = this.messageIndex.get(`${auth.session.userId}:${message.id}`);
		if (existing) {
			if (existing.canonical !== canonicalJson(message)) throw new CompanyError(409, "message_id_conflict", "message id was used with different content");
			conv = this.conversations.get(existing.conversationId)!;
		} else {
			if (parentId) this.assertDirectParent(parentId, auth);
			conv = {
				id: `cnv_${randomId(8)}`,
				clientId: auth.session.clientId,
				userId: auth.session.userId,
				parentId,
				isDirect: Boolean(parentId),
				status: "working",
				responder: "agent",
				events: [],
				context: {},
			};
			this.conversations.set(conv.id, conv);
			if (parentId) {
				const parent = this.conversations.get(parentId)!;
				parent.directId = conv.id;
				this.pushEvent(parent, { id: `evt_${randomId(6)}`, type: "direct_opened", created_at: nowIso(), conversation_id: conv.id });
			}
			this.acceptMessage(conv, message, auth);
			await this.autoReply(conv, message, auth);
		}
		const payload: Record<string, unknown> = { conversation_id: conv.id, status: conv.status, responder: conv.responder };
		if (url.searchParams.has("wait")) Object.assign(payload, await this.collect(conv, url, req));
		this.send(res, 201, payload);
	}

	private async postMessage(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, true);
		const conv = this.accessConversation(id, auth);
		if (conv.status === "closed") throw new CompanyError(409, "conversation_closed", "conversation is closed");
		if (conv.directId) throw new CompanyError(409, "direct_conversation_open", "a direct conversation is open", { body: { conversation_id: conv.directId } });
		const body = await this.jsonBody(req);
		const message = this.userMessage(body.message, auth);
		const existing = this.messageIndex.get(`${auth.session.userId}:${message.id}`);
		if (existing) {
			if (existing.canonical !== canonicalJson(message)) throw new CompanyError(409, "message_id_conflict", "message id was used with different content");
		} else {
			this.acceptMessage(conv, message, auth);
			await this.autoReply(conv, message, auth);
		}
		const payload: Record<string, unknown> = { conversation_id: conv.id, status: conv.status, responder: conv.responder };
		if (url.searchParams.has("wait")) Object.assign(payload, await this.collect(conv, url, req));
		this.send(res, 202, payload);
	}

	private async readEvents(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, true);
		const conv = this.accessConversation(id, auth);
		const accept = headerOne(req.headers, "accept") ?? "";
		if (accept.includes("text/event-stream")) return this.streamEvents(req, res, conv, url);
		const view = await this.collect(conv, url, req);
		this.send(res, 200, { conversation_id: conv.id, ...view, status: conv.status, responder: conv.responder });
	}

	private async streamEvents(req: IncomingMessage, res: ServerResponse, conv: Conv, url: URL): Promise<void> {
		const cursor = headerOne(req.headers, "last-event-id") ?? url.searchParams.get("cursor") ?? undefined;
		res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
		const writeNew = (from: string | undefined) => {
			try {
				const page = this.page(conv, from);
				for (const event of page.events) {
					if (this.options.streamDeltas && event.type === "message" && event.message?.text) {
						res.write(`event: text-delta\ndata: ${JSON.stringify({ message_id: event.message.id, text: event.message.text })}\n\n`);
					}
					res.write(`id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`);
				}
				return page.cursor;
			} catch {
				return from;
			}
		};
		let last = writeNew(cursor || undefined);
		const keepalive = setInterval(() => {
			res.write(`: keepalive\n\n`);
		}, this.options.sseKeepaliveMs ?? 15_000);
		const onWake = () => {
			last = writeNew(last || undefined);
		};
		const list = this.waiters.get(conv.id) ?? [];
		list.push(onWake);
		this.waiters.set(conv.id, list);
		await new Promise<void>((resolve) => {
			req.on("close", resolve);
			res.on("close", resolve);
		});
		clearInterval(keepalive);
	}

	private async handoff(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, true);
		const conv = this.accessConversation(id, auth);
		if (conv.status === "closed") throw new CompanyError(409, "conversation_closed", "conversation is closed");
		if (conv.directId) throw new CompanyError(409, "direct_conversation_open", "a direct conversation is open", { body: { conversation_id: conv.directId } });
		const body = await this.jsonBody(req);
		if (Object.keys(body).length !== 0) throw new CompanyError(400, "invalid_request", "handoff body must be an empty object");
		this.setStatus(conv, "queued", "agent");
		if ((this.options.handoff ?? "queue") === "unavailable") {
			this.setStatus(conv, "idle", "agent");
			this.addCompanyMessage(conv, "agent", "No one is available right now.");
		}
		this.send(res, 202, { conversation_id: conv.id, status: conv.status, responder: conv.responder });
	}

	private async closeConversation(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, true);
		const conv = this.accessConversation(id, auth);
		const body = await this.jsonBody(req);
		if (Object.keys(body).length !== 0) throw new CompanyError(400, "invalid_request", "close body must be an empty object");
		this.closeConv(conv);
		this.send(res, 200, { conversation_id: conv.id, status: conv.status, responder: conv.responder });
	}

	private async readOperation(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, false);
		const record = this.accessOperation(id, auth);
		this.expireIfNeeded(record);
		const headers: Record<string, string> = {};
		if (record.operation.state === "in_progress") headers["retry-after"] = "1";
		this.send(res, 200, record.operation, headers);
	}

	private async confirmOperation(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, false);
		const record = this.accessOperation(id, auth);
		const body = await this.jsonBody(req);
		const revision = body.revision;
		const approved = body.approved_by;
		if (typeof revision !== "number" || (approved !== "user" && approved !== "standing_permission")) {
			throw new CompanyError(400, "invalid_request", "revision and approved_by are required");
		}
		this.expireIfNeeded(record);
		if (!auth.effective.signedIn || !hasScope(auth.effective.scope, "poppy:write")) {
			throw this.scopeError(auth.token.typ, auth.effective.signedIn, "poppy:write");
		}
		if (record.operation.state !== "proposed") return this.send(res, 200, record.operation);
		if (revision !== record.operation.revision) {
			throw new CompanyError(409, "terms_changed", "revision is not the latest", { body: { operation: record.operation } });
		}
		if (record.operation.user_approval_required && approved !== "user") {
			throw new CompanyError(403, "user_approval_required", "this revision needs the user's approval");
		}
		record.operation.state = "in_progress";
		record.operation.confirmation = { revision, approved_by: approved, confirmed_at: new Date().toISOString() };
		if (!this.options.deferPerform) this.finishOperation(id, { ok: true });
		const headers: Record<string, string> = {};
		if (record.operation.state === "in_progress") headers["retry-after"] = "1";
		this.send(res, 200, record.operation, headers);
	}

	private async cancelOperation(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, false);
		const record = this.accessOperation(id, auth);
		if (record.operation.state === "proposed") {
			record.operation.state = "cancelled";
			record.operation.result = { summary: "Declined before confirmation. Nothing was done." };
		} else if (record.operation.state === "in_progress") {
			record.operation.state = "cancelled";
			record.operation.result = { summary: "Stopped after confirmation. No charge was made." };
			if (!record.performed) record.performed = 1;
		}
		this.send(res, 200, record.operation);
	}

	private async exchange(req: IncomingMessage, res: ServerResponse, url: URL, orderId: string): Promise<void> {
		const auth = await this.dpopAuth(req, url, false);
		const body = await this.jsonBody(req);
		const idem = headerOne(req.headers, "idempotency-key");
		if (idem) {
			if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idem)) {
				throw new CompanyError(400, "invalid_request", "Idempotency-Key must be a UUID v4");
			}
			const prior = this.idempotency.get(`${auth.session.id}:${idem}`);
			const hash = canonicalJson(body);
			if (prior) {
				if (prior.hash !== hash) throw new CompanyError(409, "idempotency_conflict", "this key was used with a different body");
				res.writeHead(prior.status, { "content-type": "application/json", "cache-control": "no-store" });
				res.end(prior.body);
				return;
			}
		}
		const client = await this.loadClient(auth.session.clientId);
		const supports = Boolean(client.meta.extensions?.operations);
		if (!auth.effective.signedIn || !hasScope(auth.effective.scope, "poppy:write")) {
			throw this.scopeError(auth.token.typ, auth.effective.signedIn, "poppy:write");
		}
		if (this.options.includeOperations !== false && supports) {
			const operation = this.propose({
				auth,
				summary: `Exchange an item on order ${orderId}.`,
				terms: { action: "exchange", order_id: orderId, ...(body as Record<string, unknown>) },
			});
			const payload = JSON.stringify({ operation });
			if (idem) this.idempotency.set(`${auth.session.id}:${idem}`, { hash: canonicalJson(body), status: 202, body: payload });
			res.writeHead(202, { "content-type": "application/json", "cache-control": "no-store" });
			res.end(payload);
			return;
		}
		if ((this.options.operationsMode ?? "perform") === "require") {
			throw new CompanyError(403, "extension_required", "operations extension is required", { body: { extension: "operations" } });
		}
		this.exchangesPerformed += 1;
		const payload = JSON.stringify({ performed: true, order_id: orderId });
		if (idem) this.idempotency.set(`${auth.session.id}:${idem}`, { hash: canonicalJson(body), status: 200, body: payload });
		res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
		res.end(payload);
	}

	private async billing(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
		const auth = await this.dpopAuth(req, url, false, `${this.baseUrl}/billing`);
		this.send(res, 200, { quote: true, scope: auth.effective.scope, signed_in: auth.effective.signedIn });
	}

	private async webConfirm(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
		const session = this.sessionFromCookie(req);
		if (!session?.accountId) throw new CompanyError(401, "invalid_token", "browser session is signed out");
		const record = this.operations.get(id);
		if (!record || record.sessionId !== session.id && record.accountId !== session.accountId) {
			throw new CompanyError(404, "operation_not_found", "operation not found");
		}
		if (record.operation.state === "proposed") {
			record.operation.state = "in_progress";
			record.operation.confirmation = { revision: record.operation.revision, approved_by: "user", confirmed_at: new Date().toISOString() };
			this.finishOperation(id, { ok: true });
		}
		this.send(res, 200, record.operation);
	}

	private async mcp(req: IncomingMessage, res: ServerResponse, _url: URL): Promise<void> {
		if (req.method === "GET") {
			res.writeHead(405, { allow: "POST" });
			res.end();
			return;
		}
		const header = headerOne(req.headers, "authorization") ?? "";
		if (header.startsWith("DPoP ")) throw this.scopeError("bearer", false, undefined, 401, "invalid_token", "MCP requires a Bearer session token");
		let auth: Awaited<ReturnType<CompanyServer["dpopAuth"]>> | undefined;
		const rpc = await this.jsonBody(req);
		if (rpc.method !== "initialize") {
			auth = await this.bearerAuth(header, `${this.baseUrl}/mcp`);
			const sid = headerOne(req.headers, "mcp-session-id");
			if (!sid || !this.mcpSessions.has(sid)) throw new CompanyError(400, "invalid_request", "Mcp-Session-Id required");
		}
		if (rpc.method === "initialize") {
			const id = randomId(12);
			this.mcpSessions.add(id);
			res.writeHead(200, { "content-type": "application/json", "mcp-session-id": id, "cache-control": "no-store" });
			res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "poppy-company", version: "0.1.0" } } }));
			return;
		}
		if (rpc.method === "notifications/initialized") {
			res.writeHead(202);
			res.end();
			return;
		}
		if (rpc.method === "tools/list") {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { tools: [
				{ name: "search_products", description: "Search the catalog", inputSchema: { type: "object", properties: { query: { type: "string" } } } },
				{ name: "propose_exchange", description: "Propose an exchange. Returns an operation until it is confirmed.", inputSchema: { type: "object", properties: { order_id: { type: "string" } }, required: ["order_id"] } },
			] } }));
			return;
		}
		if (rpc.method === "tools/call") {
			const name = (rpc.params as { name?: string })?.name;
			const args = ((rpc.params as { arguments?: Record<string, unknown> })?.arguments ?? {});
			if (name === "search_products") {
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { content: [{ type: "text", text: "Stormline Jacket" }], structuredContent: { products: ["stormline"] } } }));
				return;
			}
			if (name === "propose_exchange") {
				if (!auth!.effective.signedIn || !hasScope(auth!.effective.scope, "poppy:write")) {
					throw this.scopeError("bearer", auth!.effective.signedIn ? true : false, "poppy:write");
				}
				const client = await this.loadClient(auth!.session.clientId);
				if (!client.meta.extensions?.operations) {
					throw new CompanyError(403, "extension_required", "operations extension is required", { body: { extension: "operations" }, www: `Bearer error="extension_required", extension="operations"` });
				}
				const operation = this.propose({
					auth: auth!,
					summary: `Exchange an item on order ${String(args.order_id ?? "")}.`,
					terms: { action: "exchange", order_id: args.order_id },
				});
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: {
					content: [{ type: "text", text: `Proposed: ${operation.summary} Not done until confirmed.` }],
					structuredContent: { operation },
				} }));
				return;
			}
		}
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, error: { code: -32601, message: "method not found" } }));
	}

	private propose(input: { auth: Authed; summary: string; terms: Record<string, unknown> }): Operation {
		const termsKey = canonicalJson(input.terms);
		const existing = [...this.operations.values()].find((record) => {
			const open = record.operation.state === "proposed" && (record.accountId ? record.accountId === input.auth.session.accountId : record.sessionId === input.auth.session.id);
			return record.termsKey === termsKey && open;
		});
		if (existing) return existing.operation;
		const id = `exc_${randomId(6)}`;
		const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
		const operation: Operation = {
			operation_id: id,
			revision: 1,
			state: "proposed",
			summary: input.summary,
			terms: input.terms,
			expires_at: expiresAt,
			user_approval_required: priceNeedsUser(input.terms),
			url: `${this.baseUrl}/orders/${String(input.terms.order_id ?? "order")}/exchanges/${id}`,
			confirmation: null,
			result: null,
		};
		const record: OpRecord = {
			operation,
			revisions: [{ revision: 1, summary: input.summary, terms: input.terms, expiresAt }],
			clientId: input.auth.session.clientId,
			userId: input.auth.session.userId,
			sessionId: input.auth.session.id,
			accountId: input.auth.session.accountId,
			performed: 0,
			termsKey,
		};
		this.operations.set(id, record);
		return operation;
	}

	private async autoReply(conv: Conv, message: { text?: string; sender: string }, auth: Authed): Promise<void> {
		const text = message.text ?? "";
		const needsAccount = /order|account|return/i.test(text);
		if (needsAccount && !hasScope(auth.effective.scope, "poppy:read")) {
			this.pushEvent(conv, {
				id: `evt_${randomId(6)}`,
				type: "authorization",
				created_at: nowIso(),
				error: auth.effective.signedIn ? "insufficient_scope" : "sign_in_required",
				scope: "poppy:read",
			});
			this.addCompanyMessage(conv, "agent", "I need you to sign in before I can see that order.");
			this.setStatus(conv, "idle", conv.responder);
			return;
		}
		if (/exchange/i.test(text) && auth.effective.signedIn && hasScope(auth.effective.scope, "poppy:write")) {
			const client = await this.loadClient(auth.session.clientId);
			if (client.meta.extensions?.operations && this.options.includeOperations !== false) {
				const operation = this.propose({ auth, summary: "Exchange the Stormline Jacket (M) on order ord_7Hk2 for the insulated jacket, for $70.00 more.", terms: { action: "exchange", order_id: "ord_7Hk2", price_difference: { amount: "70.00", currency: "USD" } } });
				this.addCompanyMessage(conv, "agent", "I can exchange it. Confirm whenever you're ready.", operation);
				conv.accountId = auth.session.accountId;
				this.setStatus(conv, "idle", conv.responder);
				return;
			}
		}
		if (this.options.deferReplyMs) {
			this.setStatus(conv, "working", "agent");
			await new Promise((resolve) => setTimeout(resolve, this.options.deferReplyMs));
		}
		this.addCompanyMessage(conv, "agent", "I can help with that.");
		this.setStatus(conv, "idle", conv.responder);
	}

	private acceptMessage(conv: Conv, message: { id: string; sender: "agent" | "human"; text?: string; data?: Record<string, unknown>; context?: UserContext }, auth: Authed): void {
		if (message.context) conv.context = { ...conv.context, ...message.context };
		this.messageIndex.set(`${auth.session.userId}:${message.id}`, { conversationId: conv.id, canonical: canonicalJson(message) });
		if (auth.effective.signedIn && auth.session.accountId) conv.accountId = auth.session.accountId;
		this.pushEvent(conv, {
			id: `evt_${randomId(6)}`,
			type: "message",
			created_at: nowIso(),
			message: { id: message.id, role: "user", sender: message.sender, text: message.text, data: message.data },
		});
	}

	private addCompanyMessage(conv: Conv, sender: "agent" | "human", text: string, operation?: Operation): void {
		const id = `msg_${randomId(6)}`;
		this.pushEvent(conv, {
			id: `evt_${randomId(6)}`,
			type: "message",
			created_at: nowIso(),
			message: { id, role: "company", sender, text, ...(operation ? { operation } : {}) },
		});
	}

	private setStatus(conv: Conv, status: ConversationStatus, responder: Responder): void {
		if (conv.status === status && conv.responder === responder) return;
		conv.status = status;
		conv.responder = responder;
		this.pushEvent(conv, { id: `evt_${randomId(6)}`, type: "state", created_at: nowIso(), status, responder });
	}

	private closeConv(conv: Conv): void {
		if (conv.directId) {
			const child = this.conversations.get(conv.directId);
			if (child && child.status !== "closed") this.closeConv(child);
		}
		if (conv.status !== "closed") this.setStatus(conv, "closed", conv.responder);
		if (conv.parentId) {
			const parent = this.conversations.get(conv.parentId);
			if (parent && parent.directId === conv.id) {
				parent.directId = undefined;
				this.pushEvent(parent, { id: `evt_${randomId(6)}`, type: "direct_closed", created_at: nowIso(), conversation_id: conv.id });
			}
		}
	}

	private pushEvent(conv: Conv, event: ConversationEvent): void {
		conv.events.push(event);
		this.wake(conv.id);
	}

	private wake(id: string): void {
		const list = this.waiters.get(id) ?? [];
		this.waiters.set(id, []);
		for (const fn of list) fn();
	}

	private async collect(conv: Conv, url: URL, req: IncomingMessage): Promise<{ events: ConversationEvent[]; cursor: string; has_more: boolean }> {
		const cursor = headerOne(req.headers, "last-event-id") ?? (url.searchParams.get("cursor") || undefined);
		let page = this.page(conv, cursor);
		const wait = Number(url.searchParams.get("wait") ?? "0");
		const cap = this.options.waitCapSec ?? 60;
		const seconds = Math.min(Math.max(wait, 0), cap);
		if (page.events.length === 0 && seconds > 0) {
			await new Promise<void>((resolve) => {
				const timer = setTimeout(resolve, seconds * 1000);
				const list = this.waiters.get(conv.id) ?? [];
				list.push(() => {
					clearTimeout(timer);
					resolve();
				});
				this.waiters.set(conv.id, list);
			});
			page = this.page(conv, cursor);
		}
		return page;
	}

	private page(conv: Conv, cursor: string | undefined): { events: ConversationEvent[]; cursor: string; has_more: boolean } {
		let start = 0;
		if (cursor) {
			if (this.expiredCursors.has(`${conv.id}:${cursor}`)) throw new CompanyError(410, "cursor_expired", "the company no longer has events at this cursor");
			const index = conv.events.findIndex((event) => event.id === cursor);
			if (index < 0) throw new CompanyError(400, "invalid_cursor", "cursor is unknown");
			start = index + 1;
		}
		const visible = conv.events.slice(start);
		const size = this.options.pageSize ?? 50;
		const events = visible.slice(0, size);
		const has_more = visible.length > events.length;
		const next = events.at(-1)?.id ?? cursor ?? "";
		return { events, cursor: next, has_more };
	}

	private userMessage(input: unknown, _auth: Authed): { id: string; sender: "agent" | "human"; text?: string; data?: Record<string, unknown>; context?: UserContext } {
		if (!input || typeof input !== "object") throw new CompanyError(400, "invalid_request", "message is required");
		const message = input as Record<string, unknown>;
		const id = message.id;
		const sender = message.sender;
		if (typeof id !== "string" || !isOpaqueId(id)) throw new CompanyError(400, "invalid_request", "message id is invalid");
		if (sender !== "agent" && sender !== "human") throw new CompanyError(400, "invalid_request", "sender is invalid");
		const out: { id: string; sender: "agent" | "human"; text?: string; data?: Record<string, unknown>; context?: UserContext } = { id, sender };
		if (typeof message.text === "string") out.text = message.text;
		if (message.data && typeof message.data === "object") out.data = message.data as Record<string, unknown>;
		if (message.context && typeof message.context === "object") out.context = message.context as UserContext;
		if (out.text === undefined && out.data === undefined && out.context === undefined) {
			throw new CompanyError(400, "invalid_request", "message needs text, data, or context");
		}
		return out;
	}

	private assertDirectParent(parentId: string, auth: Authed): void {
		const parent = this.conversations.get(parentId);
		if (!parent || parent.clientId !== auth.session.clientId || parent.userId !== auth.session.userId) {
			throw new CompanyError(404, "conversation_not_found", "conversation not found");
		}
		if (parent.status === "closed") throw new CompanyError(409, "conversation_closed", "parent conversation is closed");
		if (parent.isDirect) throw new CompanyError(409, "direct_conversation_open", "a direct conversation cannot be a parent");
		if (parent.directId) throw new CompanyError(409, "direct_conversation_open", "a direct conversation is already open", { body: { conversation_id: parent.directId } });
	}

	private accessConversation(id: string, auth: Authed): Conv {
		const conv = this.conversations.get(id);
		if (!conv || conv.clientId !== auth.session.clientId || conv.userId !== auth.session.userId) {
			throw new CompanyError(404, "conversation_not_found", "conversation not found");
		}
		if (conv.accountId && (!auth.effective.signedIn || auth.effective.accountId !== conv.accountId)) {
			throw this.scopeError(auth.token.typ, false, undefined, 403, "sign_in_required", "this conversation needs the account it already used");
		}
		return conv;
	}

	private accessOperation(id: string, auth: Authed): OpRecord {
		const record = this.operations.get(id);
		if (!record) throw new CompanyError(404, "operation_not_found", "operation not found");
		if (record.clientId !== auth.session.clientId || record.userId !== auth.session.userId) {
			throw new CompanyError(404, "operation_not_found", "operation not found");
		}
		if (record.accountId) {
			if (!auth.effective.signedIn || auth.effective.accountId !== record.accountId) {
				throw new CompanyError(404, "operation_not_found", "operation not found");
			}
		} else if (record.sessionId !== auth.session.id) {
			throw new CompanyError(404, "operation_not_found", "operation not found");
		}
		return record;
	}

	private mustOp(id: string): OpRecord {
		const record = this.operations.get(id);
		if (!record) throw new Error("missing operation");
		return record;
	}

	private expireIfNeeded(record: OpRecord): void {
		if (record.operation.state === "proposed" && record.operation.expires_at && Date.parse(record.operation.expires_at) <= Date.now()) {
			record.operation.state = "expired";
			record.operation.result = { summary: "Not confirmed before it expired. Nothing was done." };
		}
	}

	private openApi(): Record<string, unknown> {
		return {
			openapi: "3.1.0",
			info: { title: "Example Company", version: "1.0.0" },
			paths: {
				"/orders/{order_id}/exchanges": {
					post: {
						operationId: "createExchange",
						summary: "Exchange an item. Returns an operation when the personal agent supports operations.",
						"x-poppy-operation": true,
						parameters: [{ name: "order_id", in: "path", required: true, schema: { type: "string" } }],
						requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
						responses: { "202": { description: "Operation proposed" }, "200": { description: "Performed" } },
					},
				},
			},
		};
	}

	private async dpopAuth(req: IncomingMessage, url: URL, isConversation: boolean, resource?: string): Promise<Authed> {
		void isConversation;
		const header = headerOne(req.headers, "authorization") ?? "";
		if (header.startsWith("Bearer ")) throw this.dpopError("invalid_token", "DPoP is required outside MCP");
		if (!header.startsWith("DPoP ")) throw this.dpopError("invalid_token", "missing session token");
		const access = header.slice(5).trim();
		const token = this.openToken(access);
		if (token.typ !== "dpop" || !token.jkt) throw this.dpopError("invalid_token", "not a DPoP token");
		if (token.exp * 1000 < Date.now()) throw this.dpopError("invalid_token", "session token expired");
		const proof = await this.requireProof(req, url, access, token.jkt);
		void proof;
		const session = this.sessions.get(token.sid);
		if (!session || session.ended) throw this.dpopError("invalid_token", "session has ended");
		if (resource && token.resource !== resource) throw this.dpopError("invalid_token", "token was not issued for this resource");
		if (!resource && token.resource && token.resource !== `${this.baseUrl}${url.pathname}`) {
			const apiResource = this.resourceForPath(url.pathname);
			if (apiResource && token.resource !== apiResource) throw this.dpopError("invalid_token", "token resource mismatch");
		}
		const effective = this.effective(session, token);
		return { session, token, effective, access };
	}

	private async bearerAuth(header: string, resource: string): Promise<Authed> {
		if (!header.startsWith("Bearer ")) throw this.scopeError("bearer", false, undefined, 401, "invalid_token", "missing bearer token");
		const access = header.slice(7).trim();
		const token = this.openToken(access);
		if (token.typ !== "bearer" || token.resource !== resource) {
			throw this.scopeError("bearer", false, undefined, 401, "invalid_token", "bearer token is not valid for this MCP server");
		}
		if (token.exp * 1000 < Date.now()) throw this.scopeError("bearer", false, undefined, 401, "invalid_token", "token expired");
		const session = this.sessions.get(token.sid);
		if (!session || session.ended) throw this.scopeError("bearer", false, undefined, 401, "invalid_token", "session ended");
		return { session, token, effective: this.effective(session, token), access };
	}

	private resourceForPath(path: string): string | undefined {
		if (path.startsWith("/billing")) return `${this.baseUrl}/billing`;
		return undefined;
	}

	private effective(session: SessionRecord, token: TokenPayload): { signedIn: boolean; scope: string; accountId?: string } {
		if (!token.signedIn || !session.accountId || session.accountId !== token.accountId) {
			return { signedIn: false, scope: "", accountId: undefined };
		}
		return { signedIn: true, scope: token.scope, accountId: session.accountId };
	}

	private async optionalProof(req: IncomingMessage, url: URL): Promise<{ jkt: string } | undefined> {
		if (!headerOne(req.headers, "dpop")) return undefined;
		return this.requireProof(req, url, undefined, undefined);
	}

	private async requireProof(req: IncomingMessage, url: URL, access: string | undefined, expectedJkt: string | undefined): Promise<{ jkt: string }> {
		const compact = headerOne(req.headers, "dpop");
		if (!compact) throw this.dpopError("invalid_dpop_proof", "missing DPoP proof");
		let header: JwtHeader;
		try {
			header = JSON.parse(Buffer.from(compact.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
		} catch {
			throw this.dpopError("invalid_dpop_proof", "malformed proof");
		}
		if (header.typ !== "dpop+jwt") throw this.dpopError("invalid_dpop_proof", "typ must be dpop+jwt");
		if (header.alg !== "ES256" && header.alg !== "RS256") throw this.dpopError("invalid_dpop_proof", "alg is not allowed");
		if (!header.jwk) throw this.dpopError("invalid_dpop_proof", "jwk required");
		let key: KeyObject;
		try {
			key = importPublicJwk(header.jwk as JsonWebKey);
		} catch {
			throw this.dpopError("invalid_dpop_proof", "jwk must be a public key");
		}
		let verified;
		try {
			verified = verifyJwt(compact, key, { maxLifetimeSec: 120 });
		} catch (error) {
			throw this.dpopError("invalid_dpop_proof", error instanceof Error ? error.message : "bad proof");
		}
		const jkt = jwkThumbprint(publicOnly(header.jwk as JsonWebKey));
		if (expectedJkt && jkt !== expectedJkt) throw this.dpopError("invalid_dpop_proof", "proof key does not match the token");
		if (verified.payload.htm !== req.method) throw this.dpopError("invalid_dpop_proof", "htm mismatch");
		const expectedHtu = `${this.baseUrl}${url.pathname}`;
		if (verified.payload.htu !== expectedHtu) throw this.dpopError("invalid_dpop_proof", "htu mismatch");
		const iat = numberClaim(verified.payload.iat);
		const now = Math.floor(Date.now() / 1000);
		if (Math.abs(now - iat) > 90) throw this.dpopError("invalid_dpop_proof", "iat outside the acceptance window");
		if (access) {
			if (verified.payload.ath !== accessTokenHash(access)) throw this.dpopError("invalid_dpop_proof", "ath mismatch");
		}
		if (this.options.requireNonce && verified.payload.nonce !== this.nonce) {
			throw this.dpopError("use_dpop_nonce", "nonce required", { "dpop-nonce": this.nonce });
		}
		this.rememberJti(`dpop:${stringClaim(verified.payload.jti)}`, Date.now() + 90_000, "invalid_dpop_proof");
		return { jkt };
	}

	private dpopError(code: string, description: string, headers?: Record<string, string>): CompanyError {
		const www = `DPoP error="${code}"`;
		return new CompanyError(code === "invalid_token" ? 401 : 400, code, description, { www, headers });
	}

	private scopeError(typ: "dpop" | "bearer", signedIn: boolean, scope?: string, status = 403, code = signedIn ? "insufficient_scope" : "sign_in_required", description = code): CompanyError {
		const scheme = typ === "bearer" ? "Bearer" : "DPoP";
		const scopeAttr = scope ? `, scope="${scope}"` : "";
		return new CompanyError(status, code, description, { www: `${scheme} error="${code}"${scopeAttr}` });
	}

	private async authenticateClient(form: URLSearchParams, audience: string): Promise<SeenClient> {
		const clientId = form.get("client_id") ?? "";
		if (form.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
			throw new CompanyError(401, "invalid_client", "client assertion required");
		}
		const client = await this.loadClient(clientId);
		await this.verifyClientJwt(form.get("client_assertion") ?? "", client, audience, false);
		return client;
	}

	private async verifyClientJwt(token: string, client: SeenClient, audience: string, userAssertion: boolean) {
		let header: JwtHeader;
		try {
			header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
		} catch {
			throw new CompanyError(userAssertion ? 400 : 401, userAssertion ? "invalid_grant" : "invalid_client", "malformed assertion");
		}
		if (header.jwk) throw new CompanyError(401, "invalid_client", "assertion must not embed a key");
		let key = this.keyFor(client, header.kid);
		let verified;
		try {
			verified = verifyJwt(token, key, { audience, issuer: userAssertion ? client.meta.client_id : undefined, requireStringAud: true, maxLifetimeSec: 120 });
		} catch {
			if (header.kid) {
				await this.refetchKeys(client);
				key = this.keyFor(client, header.kid);
				try {
					verified = verifyJwt(token, key, { audience, issuer: userAssertion ? client.meta.client_id : undefined, requireStringAud: true, maxLifetimeSec: 120 });
				} catch {
					throw new CompanyError(userAssertion ? 400 : 401, userAssertion ? "invalid_grant" : "invalid_client", "assertion rejected");
				}
			} else {
				throw new CompanyError(userAssertion ? 400 : 401, userAssertion ? "invalid_grant" : "invalid_client", "assertion rejected");
			}
		}
		if (!userAssertion && verified.payload.iss !== client.meta.client_id) {
			throw new CompanyError(401, "invalid_client", "client assertion iss mismatch");
		}
		if (!userAssertion && verified.payload.sub !== client.meta.client_id) {
			throw new CompanyError(401, "invalid_client", "client assertion sub mismatch");
		}
		this.rememberJti(`assert:${stringClaim(verified.payload.jti)}`, numberClaim(verified.payload.exp) * 1000, userAssertion ? "invalid_grant" : "invalid_client");
		return verified;
	}

	private keyFor(client: SeenClient, kid: string | undefined): KeyObject {
		if (kid && client.keys.has(kid)) return client.keys.get(kid)!;
		if (!kid && client.keys.size === 1) return [...client.keys.values()][0]!;
		throw new CompanyError(401, "invalid_client", "unknown signing key");
	}

	private async refetchKeys(client: SeenClient): Promise<void> {
		const fresh = await this.loadClient(client.meta.client_id, true);
		client.keys = fresh.keys;
	}

	private async loadClient(clientId: string, force = false): Promise<SeenClient> {
		if (this.options.blocklist?.includes(clientId)) throw new CompanyError(401, "invalid_client", "client is blocked");
		if (this.options.requireRegistration && !this.options.allowlist?.includes(clientId)) {
			throw new CompanyError(401, "invalid_client", "client is not registered");
		}
		if (this.options.allowlist && !this.options.allowlist.includes(clientId)) {
			throw new CompanyError(401, "invalid_client", "client is not allowed");
		}
		const cached = this.clients.get(clientId);
		if (cached && !force && Date.now() - cached.fetchedAt < 60_000) return cached;
		if (!this.newClients.has(clientId)) {
			if (this.options.maxNewClients !== undefined && this.newClients.size >= this.options.maxNewClients) {
				throw new CompanyError(401, "invalid_client", "not accepting new clients");
			}
			this.newClients.add(clientId);
		}
		let response;
		try {
			response = await httpRequest(clientId, {
				method: "GET",
				metadata: true,
				followRedirects: false,
				timeoutMs: 5_000,
				maxBytes: 100_000,
				ca: this.options.ca,
				allowLoopback: this.options.allowLoopback,
			});
		} catch {
			throw new CompanyError(401, "invalid_client", "client metadata could not be fetched");
		}
		if (response.status !== 200) throw new CompanyError(401, "invalid_client", "client metadata could not be fetched");
		let meta: ClientMetadata;
		try {
			meta = parseClientMetadata(parseJson(response.body.toString("utf8")), clientId);
		} catch {
			throw new CompanyError(401, "invalid_client", "client metadata is invalid");
		}
		const jwksRes = await httpRequest(meta.jwks_uri, {
			method: "GET",
			metadata: true,
			followRedirects: false,
			timeoutMs: 5_000,
			maxBytes: 100_000,
			ca: this.options.ca,
			allowLoopback: this.options.allowLoopback,
		});
		if (jwksRes.status !== 200) throw new CompanyError(401, "invalid_client", "jwks could not be fetched");
		const jwks = parseJson(jwksRes.body.toString("utf8")) as { keys?: JsonWebKey[] };
		const keys = new Map<string, KeyObject>();
		for (const jwk of jwks.keys ?? []) {
			const key = importPublicJwk(jwk);
			const kid = typeof jwk.kid === "string" ? jwk.kid : `k${keys.size}`;
			keys.set(kid, key);
		}
		if (keys.size === 0) throw new CompanyError(401, "invalid_client", "jwks is empty");
		const seen: SeenClient = { meta, keys, fetchedAt: Date.now() };
		this.clients.set(clientId, seen);
		return seen;
	}

	private createSession(clientId: string, userId: string): SessionRecord {
		const session: SessionRecord = {
			id: `ses_${randomId(8)}`,
			clientId,
			userId,
			ended: false,
			createdAt: Date.now(),
			expiresAt: Date.now() + (this.options.sessionTtlSec ?? 12 * 60 * 60) * 1000,
		};
		this.sessions.set(session.id, session);
		return session;
	}

	private requireSession(id: string, clientId: string, userId: string): SessionRecord {
		const session = this.sessions.get(id);
		if (!session || session.ended || session.expiresAt < Date.now() || session.clientId !== clientId || session.userId !== userId) {
			throw new CompanyError(400, "invalid_session", "session has ended or belongs to someone else");
		}
		return session;
	}

	private bindAccount(session: SessionRecord, accountId: string): void {
		if (session.boundAccountId && session.boundAccountId !== accountId) {
			throw new CompanyError(400, "account_mismatch", "session is signed in to a different account");
		}
		session.accountId = accountId;
		session.boundAccountId = accountId;
	}

	private saveAccount(clientId: string, userId: string, accountId: string, scope: string): AccountRecord {
		const record: AccountRecord = {
			token: `pat_${randomId(24)}`,
			clientId,
			userId,
			accountId,
			scope,
			expiresAt: Date.now() + (this.options.accountTtlSec ?? 30 * 24 * 60 * 60) * 1000,
			revoked: false,
		};
		this.accounts.set(record.token, record);
		return record;
	}

	private issue(session: SessionRecord, input: { scope: string; signedIn: boolean; accountId?: string; jkt?: string; type: "dpop" | "bearer"; resource?: string }): string {
		const ttl = this.options.sessionTokenTtlSec ?? 3600;
		if (!(ttl > 0)) throw new Error("expires_in must be > 0");
		const payload: TokenPayload = {
			sid: session.id,
			cid: session.clientId,
			uid: session.userId,
			scope: input.scope,
			signedIn: input.signedIn,
			accountId: input.accountId,
			jkt: input.jkt,
			resource: input.resource,
			typ: input.type,
			exp: Math.floor(Date.now() / 1000) + ttl,
		};
		if (input.jkt) this.recentJkt.set(session.id, input.jkt);
		return this.seal(payload);
	}

	private tokenBody(access: string, session: SessionRecord, scope: string, signedIn: boolean, account?: AccountRecord): Record<string, unknown> {
		const payload = this.openToken(access);
		const body: Record<string, unknown> = {
			access_token: access,
			token_type: payload.typ === "bearer" ? "Bearer" : "DPoP",
			expires_in: this.options.sessionTokenTtlSec ?? 3600,
			scope,
			session_id: session.id,
			signed_in: signedIn,
		};
		if (account) {
			body.refresh_token = account.token;
			body.refresh_token_expires_in = this.options.accountTtlSec ?? 30 * 24 * 60 * 60;
		}
		return body;
	}

	private seal(payload: TokenPayload): string {
		const iv = randomBytes(12);
		const cipher = createCipheriv("aes-256-gcm", this.key, iv);
		const data = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
		const tag = cipher.getAuthTag();
		return `st1_${Buffer.concat([iv, tag, data]).toString("base64url")}`;
	}

	private openToken(token: string): TokenPayload {
		if (!token.startsWith("st1_")) throw this.dpopError("invalid_token", "malformed token");
		try {
			const raw = Buffer.from(token.slice(4), "base64url");
			const iv = raw.subarray(0, 12);
			const tag = raw.subarray(12, 28);
			const data = raw.subarray(28);
			const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
			decipher.setAuthTag(tag);
			const json = Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
			return JSON.parse(json) as TokenPayload;
		} catch {
			throw this.dpopError("invalid_token", "token could not be read");
		}
	}

	private rememberJti(id: string, untilMs: number, code: string): void {
		const seen = this.seenJti.get(id);
		if (seen && seen > Date.now()) {
			throw new CompanyError(code === "invalid_client" ? 401 : 400, code, "replayed jti");
		}
		this.seenJti.set(id, untilMs);
	}

	private assertScopes(requested: string[], allowed: string[]): void {
		if (requested.length === 0) throw new CompanyError(400, "invalid_scope", "scope is required");
		for (const scope of requested) {
			if (!allowed.includes(scope)) throw new CompanyError(400, "invalid_scope", `scope ${scope} is not available`);
			if (!/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) throw new CompanyError(400, "invalid_scope", "invalid scope syntax");
		}
	}

	private narrow(granted: string, requested: string): string {
		const have = granted.split(" ").filter(Boolean);
		const want = requested.split(" ").filter(Boolean);
		for (const scope of want) {
			if (!have.includes(scope)) throw new CompanyError(400, "invalid_scope", "cannot increase scope");
		}
		return want.join(" ");
	}

	private checkPassword(email: string, password: string): CompanyUser | undefined {
		return (this.options.users ?? []).find((user) => safeEqual(user.email, email) && safeEqual(user.password, password));
	}

	private accountScope(session: SessionRecord): string {
		for (const account of this.accounts.values()) {
			if (account.accountId === session.accountId && account.clientId === session.clientId && !account.revoked) return account.scope;
		}
		return "";
	}

	private sessionFromCookie(req: IncomingMessage): SessionRecord | undefined {
		const raw = headerOne(req.headers, "cookie") ?? "";
		const match = /(?:^|;\s*)poppy_session=([^;]+)/.exec(raw);
		if (!match) return undefined;
		const cookie = this.cookies.get(decodeURIComponent(match[1]!));
		if (!cookie || cookie.expiresAt < Date.now()) return undefined;
		const session = this.sessions.get(cookie.sessionId);
		if (!session || session.ended || session.expiresAt < Date.now()) return undefined;
		return session;
	}

	private assertReturnTo(value: string): void {
		let url: URL;
		try {
			url = new URL(value);
		} catch {
			throw new CompanyError(400, "invalid_request", "return_to is invalid");
		}
		if (url.protocol !== "https:") throw new CompanyError(400, "invalid_request", "return_to must be HTTPS");
		const host = url.hostname;
		const domain = this.domain;
		if (host !== domain && !host.endsWith(`.${domain}`)) throw new CompanyError(400, "invalid_request", "return_to is off-domain");
	}

	private consumeRate(hint: string | undefined): void {
		const rule = this.options.rateLimit;
		if (!rule) return;
		const now = Date.now();
		while (this.hits.length && this.hits[0]! < now - rule.windowSec * 1000) this.hits.shift();
		if (this.hits.length >= rule.limit) throw new CompanyError(429, "rate_limited", "too many requests");
		this.hits.push(now);
		void hint;
	}

	private async form(req: IncomingMessage): Promise<URLSearchParams> {
		const body = (await readBody(req)).toString("utf8");
		return new URLSearchParams(body);
	}

	private async jsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
		const text = (await readBody(req)).toString("utf8");
		try {
			const value = parseJson(text);
			if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("object");
			return value as Record<string, unknown>;
		} catch {
			throw new CompanyError(400, "invalid_request", "JSON object required");
		}
	}

	private send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
		const payload = JSON.stringify(body);
		res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": headers["cache-control"] ?? "no-store", ...rateHeaders(this.options), ...headers });
		res.end(payload);
	}
}

interface Authed {
	session: SessionRecord;
	token: TokenPayload;
	effective: { signedIn: boolean; scope: string; accountId?: string };
	access: string;
}

function hasScope(scope: string, needed: string): boolean {
	return scope.split(" ").includes(needed);
}

function priceNeedsUser(terms: Record<string, unknown>): boolean {
	const price = terms.price_difference;
	if (!price || typeof price !== "object") return false;
	const amount = Number((price as { amount?: unknown }).amount);
	return Number.isFinite(amount) && amount >= 50;
}

function stringClaim(value: unknown): string {
	if (typeof value !== "string" || value.length === 0) throw new CompanyError(400, "invalid_grant", "missing string claim");
	return value;
}

function numberClaim(value: unknown): number {
	if (typeof value !== "number") throw new CompanyError(400, "invalid_grant", "missing numeric claim");
	return value;
}

function nowIso(): string {
	return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);
}

function base64UrlSha(value: string): string {
	return createHash("sha256").update(value).digest("base64url");
}

function rateHeaders(options: CompanyOptions): Record<string, string> {
	if (!options.rateLimit) return {};
	return {
		"ratelimit-policy": `"requests";q=${options.rateLimit.limit};w=${options.rateLimit.windowSec}`,
		ratelimit: `"requests";r=${Math.max(options.rateLimit.limit - 1, 0)};t=${options.rateLimit.windowSec}`,
	};
}

function readBody(req: IncomingMessage, max = 1_000_000): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let total = 0;
		req.on("data", (chunk: Buffer) => {
			total += chunk.length;
			if (total > max) {
				reject(new CompanyError(413, "invalid_request", "body too large"));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}
