import { randomUUID, type JsonWebKey } from "node:crypto";
import { commitUse, releaseUse, reserveUse, standingCovers, type Approval, type StandingPermission } from "./approval.ts";
import { randomId } from "./codec.ts";
import { createPkce, signBrowserAssertion, signClientAssertion, signDpop, signSessionAssertion } from "./dpop.ts";
import { publicOnly } from "./jwt.ts";
import { headerOne, HttpCache, httpRequest, parseRetryAfter, type HttpResponse } from "./net.ts";
import { containsSecret, redactHeaders, redactText } from "./redact.ts";
import {
	domainsMatch,
	majorVersion,
	parseAgentMessage,
	parseDeviceAuthorizationResponse,
	parseEventsResponse,
	parseJsonDocument,
	parseOAuthMetadata,
	parseOperation,
	parsePoppyDocument,
	parseTokenResponse,
	supportedMajor,
	validateScopeString,
	type AgentMessage,
	type ConversationEvent,
	type EventsResponse,
	type OAuthServerMetadata,
	type Operation,
	type PoppyApi,
	type PoppyDocument,
	type TokenResponse,
} from "./schema.ts";
import { emptyState, type SecretState, type Store, type StoredAccount, type StoredCompany } from "./store.ts";

export interface AgentOptions {
	clientId: string;
	clientName: string;
	redirectUris: string[];
	signingPrivateJwk: JsonWebKey;
	signingKid: string;
	store: Store;
	ca?: string;
	allowLoopback?: boolean;
	userKey?: string;
	supportedMajor?: number;
}

export interface DiscoveredCompany {
	requestedHost: string;
	poppyUrl: string;
	document: PoppyDocument;
	metadata?: OAuthServerMetadata;
}

export interface LiveSession {
	discovery: DiscoveredCompany;
	sessionId: string;
	userId: string;
	accessToken: string;
	tokenType: "DPoP" | "Bearer";
	scope: string;
	signedIn: boolean;
	expiresAt: number;
	resource?: string;
	/** Bearer tokens are kept per MCP resource and never used anywhere else. */
	bearers: Map<string, { accessToken: string; expiresAt: number; scope: string }>;
	cookies: Map<string, string>;
	browserJoined: boolean;
	cursor: string;
	seenEvents: Set<string>;
	conversationId?: string;
}

export interface DeviceLogin {
	deviceCode: string;
	userCode: string;
	verificationUri: string;
	verificationUriComplete?: string;
	expiresAt: number;
	intervalSec: number;
	sessionId: string;
	scope: string;
}

interface PendingDirect {
	state: string;
	verifier: string;
	sessionId: string;
	issuer: string;
	redirectUri: string;
}

/**
 * Personal Agent side of Personal Agent Protocol draft 0.1.
 * Tokens stay in this object and the secret store. Public views omit them.
 */
export class PersonalAgent {
	private state: SecretState | undefined;
	private readonly cache = new HttpCache();
	private readonly nonces = new Map<string, string>();
	private readonly pending = new Map<string, PendingDirect>();
	private readonly sessions = new Map<string, LiveSession>();
	readonly actedOnDelta = false;

	private readonly options: AgentOptions;
	constructor(options: AgentOptions) {
		this.options = options;
	}

	async discover(input: string): Promise<DiscoveredCompany> {
		const base = input.includes("://") ? new URL(input) : new URL(`https://${input}`);
		const requestedHost = base.hostname;
		const poppyUrl = `${base.origin}/.well-known/poppy.json`;
		const response = await this.metadataGet(poppyUrl);
		const document = parsePoppyDocument(parseJsonDocument(response.body.toString("utf8")));
		if (!supportedMajor(document.protocol_version, this.options.supportedMajor ?? 0)) {
			throw new Error(`unsupported protocol major version ${majorVersion(document.protocol_version)}`);
		}
		if (!domainsMatch(requestedHost, document.organization.domain)) {
			throw new Error("organization.domain does not match the requested host");
		}
		let metadata: OAuthServerMetadata | undefined;
		if (document.auth) {
			metadata = await this.fetchMetadata(document.auth.issuer);
			if (metadata.issuer !== document.auth.issuer) throw new Error("oauth issuer mismatch");
			if (!metadata.poppy_domains.includes(document.organization.domain)) {
				throw new Error("poppy_domains does not include organization.domain");
			}
			if (document.auth.direct && !metadata.authorization_endpoint) throw new Error("authorization_endpoint required");
			if (document.auth.device && !metadata.device_authorization_endpoint) throw new Error("device_authorization_endpoint required");
		}
		return { requestedHost, poppyUrl, document, metadata };
	}

	/** APIs whose type this agent implements. Unrecognized types are skipped. */
	supportedApis(document: PoppyDocument): PoppyApi[] {
		return (document.apis ?? []).filter((api) => api.type === "openapi" || api.type === "mcp");
	}

	conversationEndpoint(document: PoppyDocument): string | undefined {
		return document.agent?.protocols.find((protocol) => protocol.type === "poppy")?.endpoint;
	}

	async startSession(discovery: DiscoveredCompany): Promise<LiveSession> {
		const meta = this.requireMeta(discovery);
		const company = await this.company(meta.issuer);
		const assertion = signSessionAssertion({
			privateJwk: this.options.signingPrivateJwk,
			clientId: this.options.clientId,
			userId: company.userId,
			tokenEndpoint: meta.token_endpoint,
			kid: this.options.signingKid,
		});
		const token = await this.tokenCall(discovery, {
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion,
		}, company);
		return this.remember(discovery, company.userId, token);
	}

	async renew(session: LiveSession): Promise<LiveSession> {
		if (session.signedIn) return this.useAccount(session, session.scope, session.sessionId);
		const meta = this.requireMeta(session.discovery);
		const company = await this.company(meta.issuer);
		const assertion = signSessionAssertion({
			privateJwk: this.options.signingPrivateJwk,
			clientId: this.options.clientId,
			userId: company.userId,
			tokenEndpoint: meta.token_endpoint,
			kid: this.options.signingKid,
		});
		const token = await this.tokenCall(session.discovery, {
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion,
			session_id: session.sessionId,
		}, company);
		return this.remember(session.discovery, company.userId, token, session);
	}

	async accountCovers(issuer: string, scopes: string[]): Promise<boolean> {
		const company = await this.company(issuer);
		return company.accounts.some((account) => scopes.every((scope) => account.scope.split(" ").includes(scope)));
	}

	async beginDirectSignIn(session: LiveSession, scope: string): Promise<{ url: string; state: string }> {
		validateScopeString(scope, false);
		const meta = this.requireMeta(session.discovery);
		if (!meta.authorization_endpoint) throw new Error("company does not offer direct sign-in");
		if (await this.accountCovers(meta.issuer, scope.split(" "))) {
			throw new Error("an account token already covers this scope");
		}
		const redirectUri = this.options.redirectUris[0];
		if (!redirectUri) throw new Error("redirect URI is not configured");
		const pkce = createPkce();
		const state = randomId(16);
		this.pending.set(state, { state, verifier: pkce.verifier, sessionId: session.sessionId, issuer: meta.issuer, redirectUri });
		const url = new URL(meta.authorization_endpoint);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("client_id", this.options.clientId);
		url.searchParams.set("redirect_uri", redirectUri);
		url.searchParams.set("scope", scope);
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", pkce.challenge);
		url.searchParams.set("code_challenge_method", "S256");
		return { url: url.toString(), state };
	}

	async completeDirectSignIn(callbackUrl: string): Promise<LiveSession> {
		const url = new URL(callbackUrl);
		const state = url.searchParams.get("state") ?? "";
		const pending = this.pending.get(state);
		if (!pending) throw new Error("unknown or reused state");
		this.pending.delete(state);
		if (url.searchParams.get("error")) throw new Error(url.searchParams.get("error") ?? "access_denied");
		const session = this.sessions.get(pending.sessionId);
		if (!session) throw new Error("session is gone");
		const iss = url.searchParams.get("iss");
		if (iss !== session.discovery.document.auth?.issuer) throw new Error("iss does not match the company that started sign-in");
		const company = await this.company(pending.issuer);
		const previous = company.accounts.map((account) => account.refreshToken);
		const token = await this.tokenCall(session.discovery, {
			grant_type: "authorization_code",
			code: url.searchParams.get("code") ?? "",
			redirect_uri: pending.redirectUri,
			code_verifier: pending.verifier,
			session_id: session.sessionId,
		}, company);
		const live = this.remember(session.discovery, company.userId, token, session);
		await this.revokeReplaced(session.discovery, previous, token.refresh_token);
		return live;
	}

	async beginDeviceSignIn(session: LiveSession, scope: string): Promise<DeviceLogin> {
		validateScopeString(scope, false);
		const meta = this.requireMeta(session.discovery);
		if (!meta.device_authorization_endpoint) throw new Error("company does not offer device sign-in");
		const response = await this.formPost(session.discovery, meta.device_authorization_endpoint, {
			scope,
			client_id: this.options.clientId,
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: signClientAssertion({
				privateJwk: this.options.signingPrivateJwk,
				clientId: this.options.clientId,
				audience: meta.device_authorization_endpoint,
				kid: this.options.signingKid,
			}),
		}, false);
		const device = parseDeviceAuthorizationResponse(parseJsonDocument(response.body.toString("utf8")));
		return {
			deviceCode: device.device_code,
			userCode: device.user_code,
			verificationUri: device.verification_uri,
			verificationUriComplete: device.verification_uri_complete,
			expiresAt: Date.now() + device.expires_in * 1000,
			intervalSec: device.interval,
			sessionId: session.sessionId,
			scope,
		};
	}

	async pollDeviceSignIn(login: DeviceLogin, options: { wait?: boolean } = {}): Promise<{ pending: true; login: DeviceLogin } | { pending: false; session: LiveSession }> {
		const session = this.sessions.get(login.sessionId);
		if (!session) throw new Error("session is gone");
		if (options.wait !== false && login.intervalSec > 0) await sleep(login.intervalSec * 1000);
		const company = await this.company(this.requireMeta(session.discovery).issuer);
		const previous = company.accounts.map((account) => account.refreshToken);
		const response = await this.tokenCallRaw(session.discovery, {
			grant_type: "urn:ietf:params:oauth:grant-type:device_code",
			device_code: login.deviceCode,
			session_id: session.sessionId,
		}, company, true);
		if (response.status !== 200) {
			const error = jsonError(response);
			if (error === "authorization_pending") return { pending: true, login };
			if (error === "slow_down") return { pending: true, login: { ...login, intervalSec: login.intervalSec + 5 } };
			throw new Error(error || "device sign-in failed");
		}
		const token = parseTokenResponse(parseJsonDocument(response.body.toString("utf8")));
		await this.storeToken(this.requireMeta(session.discovery).issuer, token);
		const live = this.remember(session.discovery, company.userId, token, session);
		await this.revokeReplaced(session.discovery, previous, token.refresh_token);
		return { pending: false, session: live };
	}

	async mediatedSignIn(session: LiveSession, credentials: Record<string, string>, scope: string): Promise<{ status: string; signInId?: string; session?: LiveSession; sentTo?: string }> {
		validateScopeString(scope, false);
		const endpoint = session.discovery.document.auth?.mediated?.endpoint;
		if (!endpoint) throw new Error("company does not offer mediated sign-in");
		const fields = session.discovery.document.auth?.mediated?.fields ?? [];
		for (const field of fields) {
			if (!(field.name in credentials)) throw new Error(`missing credential ${field.name}`);
		}
		const response = await this.authed(session, endpoint, "POST", { json: { scope, credentials } });
		if (response.status >= 400) throw new Error(jsonError(response) || `mediated sign-in failed ${response.status}`);
		return this.mediatedResult(session, response, credentials);
	}

	async submitMediatedCode(session: LiveSession, signInId: string, code: string): Promise<{ status: string; session?: LiveSession }> {
		const endpoint = session.discovery.document.auth?.mediated?.endpoint;
		if (!endpoint) throw new Error("company does not offer mediated sign-in");
		const response = await this.authed(session, `${endpoint}/${encodeURIComponent(signInId)}`, "POST", { json: { code } });
		if (response.status >= 400) throw new Error(jsonError(response) || `mediated sign-in failed ${response.status}`);
		return this.mediatedResult(session, response, { code });
	}

	async useAccount(session: LiveSession | undefined, scope: string, sessionId?: string, resource?: string): Promise<LiveSession> {
		const discovery = session?.discovery;
		if (!discovery?.metadata) throw new Error("discovery required");
		const company = await this.company(discovery.metadata.issuer);
		const account = this.pickAccount(company, scope);
		if (!account) throw new Error("no account token covers that scope");
		const form: Record<string, string> = {
			grant_type: "refresh_token",
			refresh_token: account.refreshToken,
			scope,
		};
		if (sessionId) form.session_id = sessionId;
		if (resource) form.resource = resource;
		const proof = !resource || resource !== `${new URL(discovery.metadata.issuer).origin}/mcp` && !resource.endsWith("/mcp");
		const response = await this.tokenCallRaw(discovery, form, company, proof);
		if (response.status !== 200) {
			if (jsonError(response) === "invalid_grant") {
				company.accounts = company.accounts.filter((item) => item.refreshToken !== account.refreshToken);
				await this.saveCompany(discovery.metadata.issuer, company);
			}
			throw new Error(jsonError(response) || "refresh failed");
		}
		const token = parseTokenResponse(parseJsonDocument(response.body.toString("utf8")));
		if (token.refresh_token) {
			account.refreshToken = token.refresh_token;
			await this.saveCompany(discovery.metadata.issuer, company);
		}
		const live = session ?? this.blank(discovery, company.userId);
		return this.remember(discovery, company.userId, token, live, resource);
	}

	async mcpBearer(session: LiveSession, apiUrl: string): Promise<string> {
		const meta = this.requireMeta(session.discovery);
		const company = await this.company(meta.issuer);
		if (session.signedIn) {
			const account = company.accounts[0];
			if (!account) throw new Error("signed-in MCP token needs an account token");
			const response = await this.tokenCallRaw(session.discovery, {
				grant_type: "refresh_token",
				refresh_token: account.refreshToken,
				session_id: session.sessionId,
				resource: apiUrl,
				scope: session.scope,
			}, company, false);
			const token = parseTokenResponse(parseJsonDocument(response.body.toString("utf8")));
			if (token.refresh_token) {
				account.refreshToken = token.refresh_token;
				await this.saveCompany(meta.issuer, company);
			}
			session.bearers.set(apiUrl, { accessToken: token.access_token, expiresAt: Date.now() + token.expires_in * 1000, scope: token.scope });
			return token.access_token;
		}
		const assertion = signSessionAssertion({
			privateJwk: this.options.signingPrivateJwk,
			clientId: this.options.clientId,
			userId: company.userId,
			tokenEndpoint: meta.token_endpoint,
			kid: this.options.signingKid,
		});
		const response = await this.tokenCallRaw(session.discovery, {
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion,
			session_id: session.sessionId,
			resource: apiUrl,
		}, company, false);
		const token = parseTokenResponse(parseJsonDocument(response.body.toString("utf8")));
		session.bearers.set(apiUrl, { accessToken: token.access_token, expiresAt: Date.now() + token.expires_in * 1000, scope: token.scope });
		return token.access_token;
	}

	/**
	 * Config for pi 1.0.1 `registerMcpServer`. The built-in MCP client sends this
	 * Bearer token. pi-poppy does not open its own MCP connection.
	 */
	async mcpRegistration(session: LiveSession, api: PoppyApi): Promise<{ name: string; config: { url: string; headers: { Authorization: string }; description: string; exposure: "direct" } }> {
		if (api.type !== "mcp") throw new Error("not an MCP API");
		const bearer = await this.mcpBearer(session, api.url);
		return {
			name: mcpServerName(session.discovery.document.organization.domain, api.url),
			config: {
				url: api.url,
				headers: { Authorization: `Bearer ${bearer}` },
				description: api.description,
				exposure: "direct",
			},
		};
	}

	async permissions(): Promise<StandingPermission[]> {
		return [...(await this.load()).permissions];
	}

	async grantPermission(permission: StandingPermission): Promise<void> {
		const state = await this.load();
		state.permissions = state.permissions.filter((item) => item.id !== permission.id);
		state.permissions.push(permission);
		await this.persist(state);
	}

	async revoke(session: LiveSession): Promise<void> {
		const meta = this.requireMeta(session.discovery);
		const company = await this.company(meta.issuer);
		const account = company.accounts[0];
		if (!account) return;
		await this.formPost(session.discovery, meta.revocation_endpoint, {
			token: account.refreshToken,
			token_type_hint: "refresh_token",
			client_id: this.options.clientId,
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: signClientAssertion({
				privateJwk: this.options.signingPrivateJwk,
				clientId: this.options.clientId,
				audience: meta.revocation_endpoint,
				kid: this.options.signingKid,
			}),
		}, false);
		company.accounts = [];
		await this.saveCompany(meta.issuer, company);
		session.signedIn = false;
		session.scope = "";
	}

	async sendMessage(session: LiveSession, message: AgentMessage, options: { wait?: number; cursor?: string; parentId?: string } = {}): Promise<{ conversationId: string; status: string; responder: string; events?: EventsResponse }> {
		const endpoint = this.conversationEndpoint(session.discovery.document);
		if (!endpoint) throw new Error("company has no poppy conversation endpoint");
		parseAgentMessage(message);
		const target = options.parentId || !session.conversationId ? endpoint : `${endpoint}/${session.conversationId}/messages`;
		const postUrl = new URL(target);
		if (options.wait !== undefined) postUrl.searchParams.set("wait", String(options.wait));
		if (options.cursor) postUrl.searchParams.set("cursor", options.cursor);
		const body: Record<string, unknown> = { message };
		if (options.parentId) body.parent_conversation_id = options.parentId;
		const response = await this.authed(session, postUrl.toString(), "POST", { json: body });
		const payload = parseJsonDocument(response.body.toString("utf8")) as Record<string, unknown>;
		if (response.status >= 400) throw new Error(String(payload.error ?? response.status));
		session.conversationId = String(payload.conversation_id);
		const events = payload.events ? parseEventsResponse(payload) : undefined;
		if (events) this.absorb(session, events);
		return { conversationId: session.conversationId, status: String(payload.status), responder: String(payload.responder), events };
	}

	async readEvents(session: LiveSession, options: { wait?: number; cursor?: string } = {}): Promise<EventsResponse & { gap?: boolean }> {
		const endpoint = this.requireConversation(session);
		const url = new URL(`${endpoint}/events`);
		const cursor = options.cursor ?? session.cursor;
		if (cursor) url.searchParams.set("cursor", cursor);
		if (options.wait !== undefined) url.searchParams.set("wait", String(options.wait));
		const response = await this.authed(session, url.toString(), "GET");
		if (response.status === 410) return { conversation_id: session.conversationId ?? "", events: [], cursor: "", has_more: false, status: "idle", responder: "agent", gap: true };
		if (response.status >= 400) throw new Error(jsonError(response) || `read failed ${response.status}`);
		const events = parseEventsResponse(parseJsonDocument(response.body.toString("utf8")));
		this.absorb(session, events);
		return events;
	}

	/**
	 * Read a short SSE burst. `text-delta` pieces are returned separately and are not events to act on.
	 * The stream is closed by the agent; companies may also close it.
	 */
	async readEventStream(session: LiveSession, options: { cursor?: string } = {}): Promise<{ deltas: string[]; events: ConversationEvent[] }> {
		const endpoint = this.requireConversation(session);
		const url = new URL(`${endpoint}/events`);
		const cursor = options.cursor ?? (session.cursor || undefined);
		if (cursor) url.searchParams.set("cursor", cursor);
		const company = await this.company(this.requireMeta(session.discovery).issuer);
		const proof = signDpop({
			privateJwk: company.dpopPrivateJwk,
			method: "GET",
			url: url.toString(),
			accessToken: session.accessToken,
			nonce: this.nonces.get(url.origin),
		});
		const response = await httpRequest(url.toString(), {
			method: "GET",
			headers: { authorization: `DPoP ${session.accessToken}`, dpop: proof, accept: "text/event-stream" },
			stream: true,
			ca: this.options.ca,
			allowLoopback: this.options.allowLoopback,
			timeoutMs: 2_000,
			maxBytes: 1_000_000,
		});
		if (!response.stream) throw new Error("stream was not opened");
		const chunks: Buffer[] = [];
		await new Promise<void>((resolve) => {
			const timer = setTimeout(() => {
				response.stream?.destroy();
				resolve();
			}, 300);
			response.stream?.on("data", (chunk: Buffer) => {
				chunks.push(chunk);
				if (Buffer.concat(chunks).includes("\n\n")) {
					clearTimeout(timer);
					response.stream?.destroy();
					resolve();
				}
			});
			response.stream?.on("end", () => {
				clearTimeout(timer);
				resolve();
			});
			response.stream?.on("error", () => {
				clearTimeout(timer);
				resolve();
			});
		});
		return parseSse(Buffer.concat(chunks).toString("utf8"));
	}

	/**
	 * Text the agent may act on. Pieces from `text-delta` events are ignored.
	 * Unknown event types are skipped.
	 */
	actionableText(events: EventsResponse["events"]): string[] {
		const lines: string[] = [];
		for (const event of events) {
			if (event.type === "text-delta") continue;
			if (event.type !== "message") continue;
			if (event.message?.text) lines.push(event.message.text);
		}
		return lines;
	}

	async handoff(session: LiveSession): Promise<{ status: string; responder: string }> {
		const response = await this.authed(session, `${this.requireConversation(session)}/handoff`, "POST", { json: {} });
		const body = parseJsonDocument(response.body.toString("utf8")) as { status: string; responder: string; error?: string };
		if (response.status >= 400) throw new Error(body.error ?? "handoff failed");
		return body;
	}

	async closeConversation(session: LiveSession): Promise<{ status: string; responder: string }> {
		const response = await this.authed(session, `${this.requireConversation(session)}/close`, "POST", { json: {} });
		const body = parseJsonDocument(response.body.toString("utf8")) as { status: string; responder: string; error?: string };
		if (response.status >= 400) throw new Error(body.error ?? "close failed");
		return body;
	}

	async readOperation(session: LiveSession, operationId: string): Promise<Operation> {
		const endpoint = session.discovery.document.extensions?.operations?.endpoint;
		if (!endpoint) throw new Error("company does not support operations");
		const response = await this.authed(session, `${endpoint}/${encodeURIComponent(operationId)}`, "GET");
		if (response.status >= 400) throw new Error(jsonError(response) || "read operation failed");
		return parseOperation(parseJsonDocument(response.body.toString("utf8")));
	}

	async confirmOperation(session: LiveSession, operation: Operation, approval: Approval): Promise<Operation> {
		if (approval.approvedBy === "user") {
			if (approval.companyName !== session.discovery.document.organization.name) throw new Error("company name was not shown");
			if (approval.summary !== operation.summary) throw new Error("approval must use the company's summary");
		}
		const endpoint = session.discovery.document.extensions?.operations?.endpoint;
		if (!endpoint) throw new Error("company does not support operations");
		let permission: StandingPermission | undefined;
		if (approval.approvedBy === "standing_permission") {
			const state = await this.load();
			permission = state.permissions.find((item) => item.id === approval.permissionId);
			if (!permission) throw new Error("standing permission not found");
			const check = standingCovers(permission, operation, this.requireMeta(session.discovery).issuer);
			if (!check.ok) throw new Error(check.reason);
			reserveUse(permission);
			await this.persist(state);
		}
		try {
			const response = await this.authed(session, `${endpoint}/${encodeURIComponent(operation.operation_id)}/confirm`, "POST", {
				json: { revision: operation.revision, approved_by: approval.approvedBy },
			});
			if (response.status >= 400) {
				if (permission) {
					releaseUse(permission);
					await this.persist(await this.load());
				}
				const retry = headerOne(response.headers, "retry-after");
				if (response.status === 409) {
					const body = parseJsonDocument(response.body.toString("utf8")) as { operation?: unknown };
					if (body.operation) return parseOperation(body.operation);
				}
				throw new Error(jsonError(response) || `confirm failed ${response.status}${retry ? ` retry-after ${retry}` : ""}`);
			}
			if (permission) {
				commitUse(permission);
				const state = await this.load();
				const stored = state.permissions.find((item) => item.id === permission!.id);
				if (stored) {
					stored.uses = permission.uses;
					stored.reserved = permission.reserved;
				}
				await this.persist(state);
			}
			const operationBody = parseOperation(parseJsonDocument(response.body.toString("utf8")));
			if (operationBody.state === "in_progress") {
				const retry = parseRetryAfter(headerOne(response.headers, "retry-after"));
				await sleep(retry * 1000);
				return this.readOperation(session, operation.operation_id);
			}
			return operationBody;
		} catch (error) {
			if (permission) {
				releaseUse(permission);
				await this.persist(await this.load());
			}
			throw error;
		}
	}

	async cancelOperation(session: LiveSession, operationId: string): Promise<Operation> {
		const endpoint = session.discovery.document.extensions?.operations?.endpoint;
		if (!endpoint) throw new Error("company does not support operations");
		const response = await this.authed(session, `${endpoint}/${encodeURIComponent(operationId)}/cancel`, "POST", { json: {} });
		if (response.status >= 400) throw new Error(jsonError(response) || "cancel failed");
		return parseOperation(parseJsonDocument(response.body.toString("utf8")));
	}

	async callApi(session: LiveSession, url: string, body?: unknown): Promise<{ status: number; body: unknown; operation?: Operation }> {
		if (url.includes(session.accessToken)) throw new Error("refusing to put a token in a URL");
		const headers: Record<string, string> = {};
		if (body !== undefined) headers["idempotency-key"] = randomUUID();
		const response = await this.authed(session, url, body === undefined ? "GET" : "POST", { json: body, headers });
		const parsed = response.body.length ? parseJsonDocument(response.body.toString("utf8")) : {};
		const operation = parsed && typeof parsed === "object" && "operation" in parsed ? parseOperation((parsed as { operation: unknown }).operation) : undefined;
		return { status: response.status, body: parsed, operation };
	}

	browserAssertion(session: LiveSession, returnTo: string): string {
		const endpoint = session.discovery.document.web?.browser_session_endpoint;
		if (!endpoint) throw new Error("company has no browser session endpoint");
		const company = session.userId;
		return signBrowserAssertion({
			privateJwk: this.options.signingPrivateJwk,
			clientId: this.options.clientId,
			userId: company,
			endpoint,
			sessionId: session.sessionId,
			returnTo,
			kid: this.options.signingKid,
		});
	}

	browserForm(session: LiveSession, returnTo: string): string {
		const endpoint = session.discovery.document.web?.browser_session_endpoint;
		if (!endpoint) throw new Error("company has no browser session endpoint");
		const assertion = this.browserAssertion(session, returnTo);
		return `<!doctype html><title>Join session</title><form method="post" action="${endpoint}"><input type="hidden" name="assertion" value="${assertion}"></form><script>document.forms[0].submit()</script>`;
	}

	/** Post the browser assertion from the agent's own cookie jar, never the user's browser. */
	async joinBrowser(session: LiveSession, returnTo: string): Promise<void> {
		const endpoint = session.discovery.document.web?.browser_session_endpoint;
		if (!endpoint) return;
		const assertion = this.browserAssertion(session, returnTo);
		if (endpoint.includes("assertion=")) throw new Error("refusing to put the assertion in a URL");
		const response = await httpRequest(endpoint, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ assertion }).toString(),
			ca: this.options.ca,
			allowLoopback: this.options.allowLoopback,
			timeoutMs: 10_000,
			maxBytes: 100_000,
		});
		const setCookie = headerOne(response.headers, "set-cookie");
		if (setCookie) {
			const pair = setCookie.split(";")[0] ?? "";
			const [name, value] = pair.split("=");
			if (name && value) session.cookies.set(name, value);
		}
		if (response.status >= 400) throw new Error(jsonError(response) || `browser join failed ${response.status}`);
		session.browserJoined = response.status === 303 || response.status === 200;
	}

	async browse(session: LiveSession, url: string): Promise<HttpResponse> {
		if (session.discovery.document.web?.browser_session_endpoint && !session.browserJoined) {
			await this.joinBrowser(session, url);
		}
		const cookie = [...session.cookies.entries()].map(([key, value]) => `${key}=${value}`).join("; ");
		return httpRequest(url, {
			method: "GET",
			headers: cookie ? { cookie } : {},
			ca: this.options.ca,
			allowLoopback: this.options.allowLoopback,
			timeoutMs: 10_000,
			maxBytes: 1_000_000,
		});
	}

	/** Fields safe to show a model. Account tokens and access tokens are absent. */
	describe(session: LiveSession): Record<string, unknown> {
		return {
			domain: session.discovery.document.organization.domain,
			company: session.discovery.document.organization.name,
			sessionId: session.sessionId,
			signedIn: session.signedIn,
			scope: session.scope,
			conversationId: session.conversationId,
			browserJoined: session.browserJoined,
		};
	}

	session(id: string): LiveSession | undefined {
		return this.sessions.get(id);
	}

	private async mediatedResult(session: LiveSession, response: HttpResponse, secrets: Record<string, string>): Promise<{ status: string; signInId?: string; session?: LiveSession; sentTo?: string }> {
		const text = response.body.toString("utf8");
		if (containsSecret(text, Object.values(secrets).filter((value) => value.length > 3))) {
			throw new Error("company returned a credential");
		}
		const body = parseJsonDocument(text) as { status?: string; sign_in_id?: string; code?: { sent_to?: string }; access_token?: string };
		if (body.status === "complete") {
			const token = parseTokenResponse(body);
			const issuer = this.requireMeta(session.discovery).issuer;
			const company = await this.company(issuer);
			const previous = company.accounts.map((account) => account.refreshToken);
			await this.storeToken(issuer, token);
			const live = this.remember(session.discovery, company.userId, token, session);
			await this.revokeReplaced(session.discovery, previous, token.refresh_token);
			return { status: "complete", session: live };
		}
		return { status: body.status ?? "failed", signInId: body.sign_in_id, sentTo: body.code?.sent_to };
	}

	private async authed(session: LiveSession, url: string, method: string, options: { json?: unknown; headers?: Record<string, string> } = {}): Promise<HttpResponse> {
		if (url.includes(session.accessToken)) throw new Error("refusing to put a token in a URL");
		const send = async () => {
			const company = await this.company(this.requireMeta(session.discovery).issuer);
			const proof = signDpop({
				privateJwk: company.dpopPrivateJwk,
				method,
				url,
				accessToken: session.accessToken,
				nonce: this.nonces.get(new URL(url).origin),
			});
			const headers: Record<string, string> = {
				authorization: `DPoP ${session.accessToken}`,
				dpop: proof,
				...(options.headers ?? {}),
			};
			let body: string | undefined;
			if (options.json !== undefined) {
				headers["content-type"] = "application/json";
				body = JSON.stringify(options.json);
			}
			return httpRequest(url, {
				method,
				headers,
				body,
				ca: this.options.ca,
				allowLoopback: this.options.allowLoopback,
				timeoutMs: 15_000,
				maxBytes: 1_000_000,
			});
		};
		let response = await send();
		const www = headerOne(response.headers, "www-authenticate") ?? "";
		if (www.includes("use_dpop_nonce")) {
			const nonce = headerOne(response.headers, "dpop-nonce");
			if (nonce) this.nonces.set(new URL(url).origin, nonce);
			response = await send();
		}
		if (response.status === 429) {
			await sleep(parseRetryAfter(headerOne(response.headers, "retry-after")) * 1000);
			response = await send();
		}
		if (response.status === 401 && (headerOne(response.headers, "www-authenticate") ?? "").includes("invalid_token")) {
			await this.renew(session);
			response = await send();
		}
		return response;
	}

	private async tokenCall(discovery: DiscoveredCompany, form: Record<string, string>, company: StoredCompany): Promise<TokenResponse> {
		const response = await this.tokenCallRaw(discovery, form, company, true);
		if (response.status !== 200) throw new Error(jsonError(response) || `token request failed ${response.status}`);
		const token = parseTokenResponse(parseJsonDocument(response.body.toString("utf8")));
		await this.storeToken(this.requireMeta(discovery).issuer, token);
		return token;
	}

	private async tokenCallRaw(discovery: DiscoveredCompany, form: Record<string, string>, company: StoredCompany, withProof: boolean): Promise<HttpResponse> {
		const meta = this.requireMeta(discovery);
		const fields: Record<string, string> = {
			...form,
			client_id: this.options.clientId,
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: signClientAssertion({
				privateJwk: this.options.signingPrivateJwk,
				clientId: this.options.clientId,
				audience: meta.token_endpoint,
				kid: this.options.signingKid,
			}),
		};
		return this.formPost(discovery, meta.token_endpoint, fields, withProof, company);
	}

	private async formPost(discovery: DiscoveredCompany, url: string, fields: Record<string, string>, withProof: boolean, company?: StoredCompany): Promise<HttpResponse> {
		const send = async () => {
			const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
			const posted = { ...fields };
			if (posted.client_assertion) {
				posted.client_assertion = signClientAssertion({
					privateJwk: this.options.signingPrivateJwk,
					clientId: this.options.clientId,
					audience: url,
					kid: this.options.signingKid,
				});
			}
			if (withProof) {
				const record = company ?? (await this.company(this.requireMeta(discovery).issuer));
				headers.dpop = signDpop({
					privateJwk: record.dpopPrivateJwk,
					method: "POST",
					url,
					nonce: this.nonces.get(new URL(url).origin),
				});
			}
			const serialized = new URLSearchParams(posted).toString();
			if (serialized.includes("access_token=")) throw new Error("refusing to put a token in a URL");
			return httpRequest(url, {
				method: "POST",
				headers,
				body: serialized,
				ca: this.options.ca,
				allowLoopback: this.options.allowLoopback,
				timeoutMs: 10_000,
				maxBytes: 100_000,
			});
		};
		let response = await send();
		if ((headerOne(response.headers, "www-authenticate") ?? "").includes("use_dpop_nonce")) {
			const nonce = headerOne(response.headers, "dpop-nonce");
			if (nonce) this.nonces.set(new URL(url).origin, nonce);
			response = await send();
		}
		if (response.status === 429) {
			await sleep(parseRetryAfter(headerOne(response.headers, "retry-after")) * 1000);
			response = await send();
		}
		return response;
	}

	private async metadataGet(url: string): Promise<HttpResponse> {
		const cached = this.cache.get(url);
		if (cached) return { status: 200, headers: {}, body: Buffer.from(cached), url };
		const response = await httpRequest(url, {
			method: "GET",
			metadata: true,
			followRedirects: true,
			maxRedirects: 3,
			timeoutMs: 5_000,
			maxBytes: 100_000,
			ca: this.options.ca,
			allowLoopback: this.options.allowLoopback,
		});
		if (response.status !== 200) throw new Error(`metadata fetch failed ${response.status}`);
		this.cache.store(url, response.body.toString("utf8"), headerOne(response.headers, "cache-control"));
		return response;
	}

	private async fetchMetadata(issuer: string): Promise<OAuthServerMetadata> {
		const url = `${issuer.replace(/\/$/, "")}/.well-known/oauth-authorization-server`;
		const response = await this.metadataGet(url);
		return parseOAuthMetadata(parseJsonDocument(response.body.toString("utf8")));
	}

	private remember(discovery: DiscoveredCompany, userId: string, token: TokenResponse, existing?: LiveSession, resource?: string): LiveSession {
		const session = existing ?? this.blank(discovery, userId);
		session.sessionId = token.session_id;
		session.userId = userId;
		session.scope = token.scope;
		session.signedIn = token.signed_in;
		if (token.token_type === "Bearer" && resource) {
			session.bearers.set(resource, { accessToken: token.access_token, expiresAt: Date.now() + token.expires_in * 1000, scope: token.scope });
		} else {
			session.accessToken = token.access_token;
			session.tokenType = token.token_type;
			session.expiresAt = Date.now() + token.expires_in * 1000;
			session.resource = resource;
		}
		this.sessions.set(session.sessionId, session);
		return session;
	}

	private blank(discovery: DiscoveredCompany, userId: string): LiveSession {
		return {
			discovery,
			sessionId: "",
			userId,
			accessToken: "",
			tokenType: "DPoP",
			scope: "",
			signedIn: false,
			expiresAt: 0,
			bearers: new Map(),
			cookies: new Map(),
			browserJoined: false,
			cursor: "",
			seenEvents: new Set(),
		};
	}

	private absorb(session: LiveSession, events: EventsResponse): void {
		for (const event of events.events) {
			if (session.seenEvents.has(event.id)) continue;
			session.seenEvents.add(event.id);
		}
		if (events.cursor) session.cursor = events.cursor;
	}

	private async company(issuer: string): Promise<StoredCompany> {
		const state = await this.load();
		const user = (state.users[this.options.userKey ?? "default"] ??= {});
		let company = user[issuer];
		if (!company) {
			const { generateEs256 } = await import("./jwt.ts");
			const key = generateEs256();
			company = {
				userId: `usr_${randomId(16)}`,
				dpopPrivateJwk: key.privateJwk,
				dpopKid: `dpop-${randomId(6)}`,
				accounts: [],
			};
			user[issuer] = company;
			await this.persist(state);
		}
		return company;
	}

	private async saveCompany(issuer: string, company: StoredCompany): Promise<void> {
		const state = await this.load();
		const user = (state.users[this.options.userKey ?? "default"] ??= {});
		user[issuer] = company;
		await this.persist(state);
	}

	private async storeToken(issuer: string, token: TokenResponse): Promise<void> {
		if (!token.refresh_token) return;
		const company = await this.company(issuer);
		const existing = company.accounts.find((account) => account.refreshToken === token.refresh_token);
		if (existing) existing.scope = token.scope;
		else company.accounts.push({ refreshToken: token.refresh_token, scope: token.scope, issuer });
		await this.saveCompany(issuer, company);
	}

	private async revokeReplaced(discovery: DiscoveredCompany, previous: string[], current: string | undefined): Promise<void> {
		const meta = this.requireMeta(discovery);
		const company = await this.company(meta.issuer);
		for (const token of previous) {
			if (token === current) continue;
			await this.formPost(discovery, meta.revocation_endpoint, {
				token,
				token_type_hint: "refresh_token",
				client_id: this.options.clientId,
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: signClientAssertion({
					privateJwk: this.options.signingPrivateJwk,
					clientId: this.options.clientId,
					audience: meta.revocation_endpoint,
					kid: this.options.signingKid,
				}),
			}, false);
		}
		if (current) company.accounts = company.accounts.filter((account) => account.refreshToken === current || !previous.includes(account.refreshToken));
		await this.saveCompany(meta.issuer, company);
	}

	private pickAccount(company: StoredCompany, scope: string): StoredAccount | undefined {
		const needed = scope.split(" ").filter(Boolean);
		return company.accounts.find((account) => needed.every((item) => account.scope.split(" ").includes(item)));
	}

	private requireMeta(discovery: DiscoveredCompany): OAuthServerMetadata {
		if (!discovery.metadata) throw new Error("company has no oauth metadata");
		return discovery.metadata;
	}

	private requireConversation(session: LiveSession): string {
		const endpoint = this.conversationEndpoint(session.discovery.document);
		if (!endpoint || !session.conversationId) throw new Error("no conversation");
		return `${endpoint}/${session.conversationId}`;
	}

	private async load(): Promise<SecretState> {
		if (!this.state) {
			this.state = (await this.options.store.load()) ?? emptyState({
				clientName: this.options.clientName,
				signingKid: this.options.signingKid,
				signingPrivateJwk: this.options.signingPrivateJwk,
				signingPublicJwk: publicOnly(this.options.signingPrivateJwk),
			});
		}
		return this.state;
	}

	private async persist(state: SecretState): Promise<void> {
		this.state = state;
		await this.options.store.save(state);
	}
}

export function mcpServerName(domain: string, url: string): string {
	const host = domain.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
	const path = new URL(url).pathname.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "").toLowerCase();
	const name = `poppy_${host}_${path}`.slice(0, 48);
	if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error("mcp server name is invalid");
	return name;
}

function jsonError(response: HttpResponse): string {
	try {
		const body = JSON.parse(response.body.toString("utf8")) as { error?: string };
		return body.error ?? "";
	} catch {
		return "";
	}
}

function parseSse(text: string): { deltas: string[]; events: ConversationEvent[] } {
	const deltas: string[] = [];
	const events: ConversationEvent[] = [];
	for (const block of text.split("\n\n")) {
		const lines = block.split("\n").filter((line) => line && !line.startsWith(":"));
		let eventName = "message";
		const data = lines.filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trim()).join("\n");
		for (const line of lines) {
			if (line.startsWith("event:")) eventName = line.slice(6).trim();
		}
		if (!data) continue;
		if (eventName === "text-delta") {
			deltas.push(data);
			continue;
		}
		try {
			const parsed = JSON.parse(data) as ConversationEvent;
			if (parsed && typeof parsed.type === "string") events.push(parsed);
		} catch {
			// Unknown frames are skipped.
		}
	}
	return { deltas, events };
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export function loggedHeaders(headers: Record<string, string | undefined>): Record<string, string | undefined> {
	return redactHeaders(headers);
}

export function loggedText(text: string): string {
	return redactText(text);
}
