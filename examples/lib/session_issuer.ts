/**
 * Shared signed-out session issuer for the local examples.
 * A DPoP proof produces a DPoP token. A request with resource set and no
 * proof produces the Bearer token MCP uses.
 */
import { randomBytes, type JsonWebKey } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomId } from "../../src/codec.ts";
import { importPublicJwk, jwkThumbprint, publicOnly, verifyJwt, type JwtHeader } from "../../src/jwt.ts";
import { headerOne, httpRequest } from "../../src/net.ts";
import { parseJson } from "../../src/json.ts";
import { parseClientMetadata } from "../../src/schema.ts";

export interface IssuedToken {
	token: string;
	tokenType: "DPoP" | "Bearer";
	sessionId: string;
	userId: string;
	resource?: string;
}

export class SessionIssuer {
	readonly tokens = new Map<string, IssuedToken>();
	private readonly sessions = new Map<string, { clientId: string; userId: string }>();
	private readonly seenJti = new Set<string>();
	private readonly agentCa = process.env.TODO_AGENT_CA ? readFileSync(process.env.TODO_AGENT_CA, "utf8") : undefined;

	async handleToken(req: IncomingMessage, res: ServerResponse, origin: string): Promise<void> {
		const form = await readBody(req).then((body) => new URLSearchParams(body));
		const tokenEndpoint = `${origin}/oauth/token`;
		if (form.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer") {
			return sendJson(res, 400, { error: "unsupported_grant_type", error_description: "only a signed-out session can be started here" });
		}
		try {
			const clientId = form.get("client_id") ?? "";
			const client = await this.loadClient(clientId);
			this.verifyAssertion(form.get("client_assertion") ?? "", client, tokenEndpoint, false);
			const user = this.verifyAssertion(form.get("assertion") ?? "", client, tokenEndpoint, true);
			const userId = typeof user.payload.sub === "string" ? user.payload.sub : "";
			if (!userId || user.payload.iss !== clientId) throw new Error("session assertion iss or sub is wrong");
			const existing = form.get("session_id");
			const known = existing ? this.sessions.get(existing) : undefined;
			if (existing && (!known || known.clientId !== clientId || known.userId !== userId)) {
				return sendJson(res, 400, { error: "invalid_session", error_description: "session has ended or belongs to someone else" });
			}
			const sessionId = existing || `ses_${randomId(8)}`;
			this.sessions.set(sessionId, { clientId, userId });
			const proof = headerOne(req.headers, "dpop");
			const resource = form.get("resource") ?? undefined;
			if (!proof) {
				if (!resource) return sendJson(res, 400, { error: "invalid_dpop_proof", error_description: "DPoP proof required" });
				return this.issue(res, sessionId, userId, "Bearer", resource);
			}
			this.verifyDpop(proof, tokenEndpoint);
			return this.issue(res, sessionId, userId, "DPoP", resource);
		} catch (error) {
			const message = error instanceof Error ? error.message : "token request failed";
			sendJson(res, 400, { error: "invalid_client", error_description: message });
		}
	}

	require(req: IncomingMessage, expected: "DPoP" | "Bearer"): IssuedToken {
		const header = headerOne(req.headers, "authorization") ?? "";
		const prefix = expected === "DPoP" ? "DPoP " : "Bearer ";
		if (!header.startsWith(prefix)) {
			const error = new Error(`expected ${expected} token`);
			(error as Error & { status: number }).status = 401;
			throw error;
		}
		const issued = this.tokens.get(header.slice(prefix.length));
		if (!issued || issued.tokenType !== expected) {
			const error = new Error("unknown session token");
			(error as Error & { status: number }).status = 401;
			throw error;
		}
		return issued;
	}

	private issue(res: ServerResponse, sessionId: string, userId: string, tokenType: "DPoP" | "Bearer", resource?: string): void {
		const token = `st1_${randomBytes(24).toString("base64url")}`;
		this.tokens.set(token, { token, tokenType, sessionId, userId, resource });
		sendJson(res, 200, {
			access_token: token,
			token_type: tokenType,
			expires_in: 3600,
			scope: "",
			session_id: sessionId,
			signed_in: false,
		});
	}

	private async loadClient(clientId: string): Promise<{ clientId: string; keys: Map<string, ReturnType<typeof importPublicJwk>> }> {
		const document = await this.fetchHttps(clientId);
		const meta = parseClientMetadata(parseJson(document), clientId);
		const jwks = parseJson(await this.fetchHttps(meta.jwks_uri)) as { keys?: JsonWebKey[] };
		const keys = new Map<string, ReturnType<typeof importPublicJwk>>();
		for (const jwk of jwks.keys ?? []) keys.set(typeof jwk.kid === "string" ? jwk.kid : `k${keys.size}`, importPublicJwk(jwk));
		if (keys.size === 0) throw new Error("jwks is empty");
		return { clientId: meta.client_id, keys };
	}

	private async fetchHttps(url: string): Promise<string> {
		const response = await httpRequest(url, {
			method: "GET",
			metadata: true,
			followRedirects: false,
			timeoutMs: 5_000,
			maxBytes: 100_000,
			ca: this.agentCa,
			allowLoopback: true,
		});
		if (response.status !== 200) throw new Error(`fetch ${url} failed ${response.status}`);
		return response.body.toString("utf8");
	}

	private verifyAssertion(token: string, client: { clientId: string; keys: Map<string, ReturnType<typeof importPublicJwk>> }, audience: string, userAssertion: boolean): ReturnType<typeof verifyJwt> {
		const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
		if (header.jwk) throw new Error("assertion must not embed a key");
		const key = (header.kid && client.keys.get(header.kid)) || (!header.kid && client.keys.size === 1 ? [...client.keys.values()][0] : undefined);
		if (!key) throw new Error("unknown signing key");
		const verified = verifyJwt(token, key, { audience, issuer: userAssertion ? client.clientId : undefined, requireStringAud: true, maxLifetimeSec: 120 });
		if (!userAssertion && (verified.payload.iss !== client.clientId || verified.payload.sub !== client.clientId)) {
			throw new Error("client assertion iss or sub mismatch");
		}
		const jti = String(verified.payload.jti ?? "");
		if (!jti || this.seenJti.has(jti)) throw new Error("assertion jti was reused");
		this.seenJti.add(jti);
		return verified;
	}

	private verifyDpop(token: string, tokenEndpoint: string): void {
		const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
		if (header.typ !== "dpop+jwt" || !header.jwk) throw new Error("DPoP proof is malformed");
		const key = importPublicJwk(header.jwk);
		jwkThumbprint(publicOnly(header.jwk));
		const verified = verifyJwt(token, key, { maxLifetimeSec: 120 });
		if (verified.payload.htm !== "POST" || verified.payload.htu !== tokenEndpoint) throw new Error("DPoP htm or htu mismatch");
		const jti = String(verified.payload.jti ?? "");
		if (!jti || this.seenJti.has(`dpop:${jti}`)) throw new Error("DPoP jti was reused");
		this.seenJti.add(`dpop:${jti}`);
	}
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
	if (headers) {
		for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
	}
	res.setHeader("cache-control", "no-store");
	res.writeHead(status, { "content-type": "application/json" });
	res.end(`${JSON.stringify(body)}\n`);
}

export function readBody(req: IncomingMessage): Promise<string> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => chunks.push(chunk));
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

export interface Todo {
	id: string;
	text: string;
	done: boolean;
}

export function todoStore(): Map<string, Todo[]> {
	return new Map();
}

export function listTodos(store: Map<string, Todo[]>, userId: string): Todo[] {
	return store.get(userId) ?? [];
}

export function addTodo(store: Map<string, Todo[]>, userId: string, text: string): Todo {
	const todo = { id: randomId(6), text, done: false };
	const list = store.get(userId) ?? [];
	list.push(todo);
	store.set(userId, list);
	return todo;
}

export function completeTodo(store: Map<string, Todo[]>, userId: string, id: string): Todo | undefined {
	const todo = (store.get(userId) ?? []).find((item) => item.id === id);
	if (todo) todo.done = true;
	return todo;
}
