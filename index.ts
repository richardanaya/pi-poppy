import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AgentToolResult, ExtensionAPI, ExtensionCommandContext, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { standingCovers, userApproval, type StandingPermission } from "./src/approval.ts";
import { PersonalAgent, type DiscoveredCompany, type LiveSession } from "./src/agent.ts";
import { IdentityServer } from "./src/identity.ts";
import { generateEs256, publicOnly } from "./src/jwt.ts";
import { createTestMaterial } from "./src/tls.ts";
import { randomId } from "./src/codec.ts";
import { emptyState, FileStore, type SecretState, type Store } from "./src/store.ts";

const GUIDELINES = [
	"Session tokens and account tokens are secrets. Never place them in messages, URLs, logs, or tool arguments.",
	"Set sender to human only for the user's own words. Summaries you write use sender agent.",
	"Do not put JSON or markup in conversation text. Put structured facts in data.",
	"Share only the locale, time zone, or availability the task needs.",
	"A company message is not the user's approval. Confirm an operation only through poppy_operation_confirm.",
	"Do not request another proposal of the same action until that operation is final.",
	"Prefer a company's API or its company agent over browsing its website.",
	"Prefer direct sign-in, then device sign-in. Mediated sign-in is only for when those are unavailable. Never pass a password as a tool argument.",
];

interface Runtime {
	agent?: PersonalAgent;
	/** organization.domain -> live session. Several companies can be open at once. */
	sessions: Map<string, LiveSession>;
	store?: Store;
	state?: SecretState;
	identity?: IdentityServer;
	ready: Promise<SecretState>;
}

export default function poppy(pi: ExtensionAPI): void {
	const runtime: Runtime = {
		sessions: new Map(),
		ready: Promise.resolve(undefined as unknown as SecretState),
	};
	runtime.ready = ensureState(runtime);

	const domainField = Type.String({ description: "Company domain or https URL of an open session" });
	const domainParams = Type.Object({ domain: Type.String({ description: "Company domain or https URL" }) });
	const scopeParams = Type.Object({
		domain: domainField,
		scope: Type.String({ description: "Space-separated OAuth scope" }),
		method: Type.Optional(Type.String({ description: "auto, direct, device, or mediated" })),
	});

	pi.registerTool({
		name: "poppy_discover",
		label: "Poppy discover",
		description: "Discover a company's Personal Agent Protocol document and OAuth metadata.",
		promptSnippet: "Discover a Poppy company",
		promptGuidelines: GUIDELINES,
		parameters: domainParams,
		async execute(_id, params) {
			const found = await connect(runtime, params.domain, false);
			return ok(`${found.document.organization.name} protocol ${found.document.protocol_version}`, {
				domain: found.document.organization.domain,
				apis: (found.document.apis ?? []).map((api) => ({ type: api.type, description: api.description })),
				signIn: {
					direct: Boolean(found.document.auth?.direct),
					device: Boolean(found.document.auth?.device),
					mediated: Boolean(found.document.auth?.mediated),
				},
			});
		},
	});

	pi.registerTool({
		name: "poppy_session_start",
		label: "Poppy session",
		description: "Start a signed-out Poppy session with a company that was discovered, or discover it now.",
		promptSnippet: "Start a Poppy session",
		promptGuidelines: GUIDELINES,
		parameters: domainParams,
		async execute(_id, params) {
			const session = await connect(runtime, params.domain, true);
			return ok(`Session ${session.sessionId}`, runtime.agent!.describe(session));
		},
	});

	pi.registerTool({
		name: "poppy_session_status",
		label: "Poppy status",
		description: "Describe one open session, or every open session when domain is omitted. Tokens are omitted.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: Type.Optional(domainField) }),
		async execute(_id, params) {
			await runtime.ready;
			if (!runtime.agent || runtime.sessions.size === 0) return fail("No session");
			if (!params.domain) {
				const sessions = [...runtime.sessions.values()].map((session) => runtime.agent!.describe(session));
				return ok(`${sessions.length} open session${sessions.length === 1 ? "" : "s"}`, { sessions });
			}
			return ok("Session status", runtime.agent.describe(needSession(runtime, params.domain)));
		},
	});

	pi.registerTool({
		name: "poppy_sign_in",
		label: "Poppy sign in",
		description: "Sign the user in with direct, device, or mediated sign-in. Credentials are collected in pi's own UI, never as tool arguments.",
		promptSnippet: "Sign the user in to a Poppy company",
		promptGuidelines: GUIDELINES,
		parameters: scopeParams,
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const session = await signIn(runtime, ctx, params.domain, params.scope, params.method ?? "auto");
			return ok(session.signedIn ? `Signed in with ${session.scope}` : "Sign-in did not complete", runtime.agent!.describe(session));
		},
	});

	pi.registerTool({
		name: "poppy_sign_out",
		label: "Poppy sign out",
		description: "Revoke the account token for one company. That session continues signed out.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField }),
		async execute(_id, params) {
			const session = await signOut(runtime, params.domain);
			return ok("Signed out", runtime.agent!.describe(session));
		},
	});

	pi.registerTool({
		name: "poppy_api_call",
		label: "Poppy API",
		description: "Call one of the company's OpenAPI endpoints with that session's DPoP token.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({
			domain: domainField,
			path: Type.String({ description: "Path on the company origin, such as /orders/ord_1/exchanges" }),
			body: Type.Optional(Type.Unknown()),
		}),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const origin = new URL(session.discovery.poppyUrl).origin;
			const url = new URL(params.path, origin);
			if (url.origin !== origin) return fail("Refusing to call a different origin");
			const result = await runtime.agent!.callApi(session, url.toString(), params.body);
			return ok(`HTTP ${result.status}`, { status: result.status, body: stripSecrets(result.body), operation: result.operation });
		},
	});

	pi.registerTool({
		name: "poppy_conversation_send",
		label: "Poppy send",
		description: "Send a message in one company's conversation. sender human is only for the user's own words.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({
			domain: domainField,
			text: Type.Optional(Type.String()),
			sender: Type.String({ description: "agent or human" }),
			data: Type.Optional(Type.Unknown()),
			locale: Type.Optional(Type.String()),
			time_zone: Type.Optional(Type.String()),
			user_available: Type.Optional(Type.Boolean()),
		}),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			if (params.sender !== "agent" && params.sender !== "human") return fail("sender must be agent or human");
			const context = contextOf(params);
			const sent = await runtime.agent!.sendMessage(session, {
				id: `msg_${randomId(8)}`,
				sender: params.sender,
				...(params.text ? { text: params.text } : {}),
				...(params.data && typeof params.data === "object" ? { data: params.data as Record<string, unknown> } : {}),
				...(context ? { context } : {}),
			}, { wait: 2 });
			const lines = sent.events ? runtime.agent!.actionableText(sent.events.events) : [];
			const operations = (sent.events?.events ?? []).flatMap((event) => event.message?.operation?.operation_id ? [event.message.operation.operation_id] : []);
			return ok(lines.join("\n") || sent.status, { conversationId: sent.conversationId, status: sent.status, responder: sent.responder, text: lines, operations });
		},
	});

	pi.registerTool({
		name: "poppy_conversation_read",
		label: "Poppy read",
		description: "Read new conversation events. Unknown event types and text-delta pieces are skipped. A gap means earlier history was dropped.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField, wait: Type.Optional(Type.Number()) }),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const events = await runtime.agent!.readEvents(session, { wait: params.wait });
			const lines = runtime.agent!.actionableText(events.events);
			if (events.gap) lines.unshift("Part of this conversation is missing. Tell the user.");
			return ok(lines.join("\n") || events.status, { gap: Boolean(events.gap), status: events.status, responder: events.responder, text: lines });
		},
	});

	pi.registerTool({
		name: "poppy_conversation_handoff",
		label: "Poppy handoff",
		description: "Ask the company to hand the conversation to a person.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField }),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const result = await runtime.agent!.handoff(session);
			return ok(`${result.status} ${result.responder}`, result);
		},
	});

	pi.registerTool({
		name: "poppy_conversation_close",
		label: "Poppy close",
		description: "Close the conversation open with one company.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField }),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const result = await runtime.agent!.closeConversation(session);
			return ok(result.status, result);
		},
	});

	pi.registerTool({
		name: "poppy_direct_conversation",
		label: "Poppy direct",
		description: "Open a direct conversation with a person, attached to that company's conversation.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField, text: Type.String() }),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const parent = session.conversationId;
			if (!parent) return fail("Start a conversation first");
			session.conversationId = undefined;
			const sent = await runtime.agent!.sendMessage(session, { id: `msg_${randomId(8)}`, sender: "human", text: params.text }, { parentId: parent, wait: 2 });
			return ok(sent.status, { conversationId: sent.conversationId, status: sent.status, responder: sent.responder });
		},
	});

	pi.registerTool({
		name: "poppy_operation_show",
		label: "Poppy operation",
		description: "Read an operation. Showing it does not approve it.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField, operation_id: Type.String() }),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const operation = await runtime.agent!.readOperation(session, params.operation_id);
			return ok(operation.summary, { operation });
		},
	});

	pi.registerTool({
		name: "poppy_operation_confirm",
		label: "Poppy confirm",
		description: "Confirm an operation after the user approves the company's name and summary in pi, or a standing permission covers every term.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField, operation_id: Type.String() }),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const session = needSession(runtime, params.domain);
			const operation = await runtime.agent!.readOperation(session, params.operation_id);
			const issuer = session.discovery.metadata?.issuer ?? "";
			const standing = (await runtime.agent!.permissions()).find((permission) => standingCovers(permission, operation, issuer).ok);
			if (standing && !operation.user_approval_required) {
				const confirmed = await runtime.agent!.confirmOperation(session, operation, { approvedBy: "standing_permission", permissionId: standing.id });
				return ok(confirmed.result?.summary ?? confirmed.summary, { operation: confirmed });
			}
			const companyName = session.discovery.document.organization.name;
			const accepted = await ctx.ui.confirm(companyName, operation.summary);
			if (!accepted) return ok("The user did not approve this revision.", { confirmed: false, summary: operation.summary });
			const approval = userApproval({ accepted: true, companyName, summary: operation.summary, operation });
			const confirmed = await runtime.agent!.confirmOperation(session, operation, approval);
			return ok(confirmed.result?.summary ?? confirmed.state, { operation: confirmed });
		},
	});

	pi.registerTool({
		name: "poppy_operation_cancel",
		label: "Poppy cancel",
		description: "Cancel a proposed or in-progress operation.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField, operation_id: Type.String() }),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			const operation = await runtime.agent!.cancelOperation(session, params.operation_id);
			return ok(operation.result?.summary ?? operation.state, { operation });
		},
	});

	pi.registerTool({
		name: "poppy_permission",
		label: "Poppy permission",
		description: "Ask the user to store a standing permission for one action at one company.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({
			domain: domainField,
			action: Type.String(),
			max_amount: Type.Optional(Type.String()),
			currency: Type.Optional(Type.String()),
			max_uses: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const session = needSession(runtime, params.domain);
			const companyName = session.discovery.document.organization.name;
			const summary = `Allow ${params.action} at ${companyName}` + (params.max_amount ? ` up to ${params.max_amount} ${params.currency ?? ""}` : "");
			const accepted = await ctx.ui.confirm(companyName, summary);
			if (!accepted) return ok("The user did not grant a standing permission.", { granted: false });
			const permission: StandingPermission = {
				id: `prm_${randomId(6)}`,
				issuer: session.discovery.metadata?.issuer ?? "",
				action: params.action,
				maxAmount: params.max_amount,
				currency: params.currency,
				maxUses: params.max_uses,
				uses: 0,
				reserved: 0,
			};
			await runtime.agent!.grantPermission(permission);
			return ok(`Standing permission ${permission.id} saved`, { id: permission.id, action: permission.action });
		},
	});

	pi.registerTool({
		name: "poppy_mcp_connect",
		label: "Poppy MCP",
		description: "Give pi a PAP Bearer token for each MCP API and register it with pi's built-in MCP client.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({ domain: domainField }),
		async execute(_id, params) {
			const names = await connectMcp(runtime, pi, params.domain);
			return ok(names.length ? `Registered ${names.join(", ")}` : "No MCP API", { servers: names });
		},
	});

	pi.registerTool({
		name: "poppy_browser_join",
		label: "Poppy browser",
		description: "Join the agent's own browser session before opening a page on the company site. Does not use the user's browser.",
		promptGuidelines: GUIDELINES,
		parameters: Type.Object({
			domain: domainField,
			url: Type.String({ description: "HTTPS page on the company domain" }),
		}),
		async execute(_id, params) {
			const session = needSession(runtime, params.domain);
			await runtime.agent!.joinBrowser(session, params.url);
			const page = await runtime.agent!.browse(session, params.url);
			return ok(`HTTP ${page.status}`, { status: page.status, browserJoined: session.browserJoined });
		},
	});
}

async function connect(runtime: Runtime, input: string, start: false): Promise<DiscoveredCompany>;
async function connect(runtime: Runtime, input: string, start: true): Promise<LiveSession>;
async function connect(runtime: Runtime, input: string, start: boolean): Promise<DiscoveredCompany | LiveSession> {
	const agent = await ensureAgent(runtime);
	const discovery = await agent.discover(input);
	if (!start) return discovery;
	const session = await agent.startSession(discovery);
	return rememberSession(runtime, session);
}

async function signIn(runtime: Runtime, ctx: ExtensionContext | ExtensionCommandContext, domain: string, scope: string, method: string): Promise<LiveSession> {
	const session = needSession(runtime, domain);
	const agent = runtime.agent!;
	const auth = session.discovery.document.auth;
	if (!auth) throw new Error("company has no sign-in");
	if (await agent.accountCovers(auth.issuer, scope.split(" "))) {
		const renewed = await agent.useAccount(session, scope, session.sessionId);
		return rememberSession(runtime, renewed);
	}
	const order = method === "auto" ? (["direct", "device", "mediated"] as const) : ([method] as const);
	for (const kind of order) {
		if (kind === "direct" && auth.direct) return finishDirect(runtime, ctx, session, scope);
		if (kind === "device" && auth.device) return finishDevice(runtime, ctx, session, scope);
		if (kind === "mediated" && auth.mediated) return finishMediated(runtime, ctx, session, scope);
	}
	throw new Error("that sign-in method is not offered");
}

async function finishDirect(runtime: Runtime, ctx: ExtensionContext | ExtensionCommandContext, session: LiveSession, scope: string): Promise<LiveSession> {
	const started = await runtime.agent!.beginDirectSignIn(session, scope);
	ctx.ui.notify("Open this URL and sign in yourself. Paste the final URL when the company redirects you back.", "info");
	const callback = await ctx.ui.input("Callback URL", started.url);
	if (!callback) throw new Error("sign-in cancelled");
	const next = await runtime.agent!.completeDirectSignIn(callback.trim());
	return rememberSession(runtime, next);
}

async function finishDevice(runtime: Runtime, ctx: ExtensionContext | ExtensionCommandContext, session: LiveSession, scope: string): Promise<LiveSession> {
	const login = await runtime.agent!.beginDeviceSignIn(session, scope);
	ctx.ui.notify(`Open ${login.verificationUriComplete ?? login.verificationUri} and enter ${login.userCode}. Opening the page does not approve access.`, "info");
	const deadline = Date.now() + 60_000;
	let current = login;
	while (Date.now() < deadline) {
		const polled = await runtime.agent!.pollDeviceSignIn(current, { wait: true });
		if (!polled.pending) return rememberSession(runtime, polled.session);
		current = polled.login;
	}
	throw new Error("device sign-in timed out");
}

async function finishMediated(runtime: Runtime, ctx: ExtensionContext | ExtensionCommandContext, session: LiveSession, scope: string): Promise<LiveSession> {
	const fields = session.discovery.document.auth?.mediated?.fields ?? [];
	const credentials: Record<string, string> = {};
	for (const field of fields) {
		const value = await ctx.ui.input(field.label, field.secret ? "hidden" : field.name);
		if (!value) throw new Error("sign-in cancelled");
		credentials[field.name] = value;
	}
	const result = await runtime.agent!.mediatedSignIn(session, credentials, scope);
	if (result.status === "code_required" && result.signInId) {
		ctx.ui.notify(result.sentTo ?? "Enter the one-time code", "info");
		const code = await ctx.ui.input("One-time code");
		if (!code) throw new Error("sign-in cancelled");
		const done = await runtime.agent!.submitMediatedCode(session, result.signInId, code);
		if (!done.session) throw new Error(done.status);
		return rememberSession(runtime, done.session);
	}
	if (!result.session) throw new Error(result.status);
	return rememberSession(runtime, result.session);
}

async function signOut(runtime: Runtime, domain: string): Promise<LiveSession> {
	const session = needSession(runtime, domain);
	await runtime.agent!.revoke(session);
	return session;
}

async function connectMcp(runtime: Runtime, pi: ExtensionAPI, domain: string): Promise<string[]> {
	const session = needSession(runtime, domain);
	const names: string[] = [];
	for (const api of runtime.agent!.supportedApis(session.discovery.document)) {
		if (api.type !== "mcp") continue;
		const registration = await runtime.agent!.mcpRegistration(session, api);
		pi.registerMcpServer(registration.name, registration.config);
		names.push(registration.name);
	}
	return names;
}

async function ensureAgent(runtime: Runtime): Promise<PersonalAgent> {
	if (runtime.agent) return runtime.agent;
	const state = await runtime.ready;
	if (!state.clientId || !state.redirectUris?.length) {
		throw new Error("This agent has no client_id yet. A company has to be able to download the client metadata from an HTTPS URL.");
	}
	const ca = process.env.PI_POPPY_CA ? await readFile(process.env.PI_POPPY_CA, "utf8") : undefined;
	runtime.agent = new PersonalAgent({
		clientId: state.clientId,
		clientName: state.clientName,
		redirectUris: state.redirectUris,
		signingPrivateJwk: state.signingPrivateJwk,
		signingKid: state.signingKid,
		store: runtime.store!,
		ca,
		allowLoopback: process.env.PI_POPPY_ALLOW_LOOPBACK === "1",
	});
	return runtime.agent;
}

async function ensureState(runtime: Runtime): Promise<SecretState> {
	runtime.store ??= new FileStore(process.env.PI_POPPY_STORE || join(homedir(), ".pi", "poppy.json"));
	let state = runtime.state ?? (await runtime.store.load());
	if (!state) {
		const generated = generateEs256();
		state = emptyState({
			clientName: "pi-poppy",
			signingKid: "pi-poppy-1",
			signingPrivateJwk: generated.privateJwk,
			signingPublicJwk: publicOnly(generated.publicJwk),
		});
	}
	if (!state.clientId || !state.redirectUris?.length) await publishLocalIdentity(runtime, state);
	else if (state.localIdentity && !runtime.identity) await serveLocalIdentity(runtime, state);
	runtime.state = state;
	await runtime.store.save(state);
	return state;
}

async function publishLocalIdentity(runtime: Runtime, state: SecretState): Promise<void> {
	const tls = createTestMaterial();
	state.localIdentity = { cert: tls.certPem, key: tls.keyPem, ca: tls.caPem, port: 0 };
	await serveLocalIdentity(runtime, state);
}

async function serveLocalIdentity(runtime: Runtime, state: SecretState): Promise<void> {
	const local = state.localIdentity;
	if (!local) return;
	const identity = new IdentityServer({
		cert: local.cert,
		key: local.key,
		clientName: state.clientName,
		signingPublicJwk: publicOnly(state.signingPublicJwk),
		kid: state.signingKid,
		port: local.port || undefined,
	});
	await identity.start();
	local.port = Number(new URL(identity.clientId).port);
	state.clientId = identity.clientId;
	state.redirectUris = [identity.redirectUri];
	runtime.identity = identity;
}

function rememberSession(runtime: Runtime, session: LiveSession): LiveSession {
	runtime.sessions.set(session.discovery.document.organization.domain, session);
	return session;
}

function needSession(runtime: Runtime, domain: string): LiveSession {
	const host = domain.includes("://") ? new URL(domain).hostname : domain;
	const stripped = host.replace(/^www\./, "");
	for (const session of runtime.sessions.values()) {
		const org = session.discovery.document.organization.domain;
		const requested = session.discovery.requestedHost;
		if (org === host || org === stripped || requested === host || requested === stripped) return session;
	}
	throw new Error(`No session for ${domain}. Call poppy_session_start.`);
}

function contextOf(params: { locale?: string; time_zone?: string; user_available?: boolean }): Record<string, unknown> | undefined {
	const context: Record<string, unknown> = {};
	if (params.locale) context.locale = params.locale;
	if (params.time_zone) context.time_zone = params.time_zone;
	if (params.user_available !== undefined) context.user_available = params.user_available;
	return Object.keys(context).length ? context : undefined;
}

function stripSecrets(value: unknown): unknown {
	const text = JSON.stringify(value);
	if (text.includes("pat_") || text.includes("st1_") || text.includes("refresh_token")) return { redacted: true };
	return value;
}

function ok(text: string, details: Record<string, unknown>): AgentToolResult<Record<string, unknown>> {
	return { content: [{ type: "text", text }], details };
}

function fail(text: string): AgentToolResult<Record<string, unknown>> {
	return { content: [{ type: "text", text }], details: {}, isError: true };
}
