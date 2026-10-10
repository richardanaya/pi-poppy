/**
 * A website-only Poppy company with an in-memory todo list per user.
 *
 *   node --experimental-strip-types examples/todo_website/server.ts
 *
 * poppy.json offers the website and an OAuth issuer so a personal agent can
 * start a signed-out session. The human sign-in form is separate. Users,
 * passwords, todos, and sessions live in this process and disappear when it
 * exits. The first form sign-in for an email creates that user.
 *
 * TODO_AGENT_CA is a PEM CA the company uses when it downloads client
 * metadata. This example also allows loopback for that fetch.
 */
import { randomBytes, type JsonWebKey } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { randomId } from "../../src/codec.ts";
import { importPublicJwk, jwkThumbprint, publicOnly, verifyJwt, type JwtHeader } from "../../src/jwt.ts";
import { headerOne, httpRequest } from "../../src/net.ts";
import { parseJson } from "../../src/json.ts";
import { parseClientMetadata } from "../../src/schema.ts";
import { createTestMaterial } from "../../src/tls.ts";

interface Todo {
	id: string;
	text: string;
	done: boolean;
}

interface User {
	email: string;
	password: string;
	todos: Todo[];
}

const users = new Map<string, User>();
const sessions = new Map<string, string>();
const poppySessions = new Map<string, { clientId: string; userId: string }>();
const seenJti = new Set<string>();
const agentCa = process.env.TODO_AGENT_CA ? readFileSync(process.env.TODO_AGENT_CA, "utf8") : undefined;

const tls = createTestMaterial();
const server = createServer({ cert: tls.certPem, key: tls.keyPem }, (req, res) => {
	void handle(req, res);
});

server.listen(0, "127.0.0.1", () => {
	const port = (server.address() as AddressInfo).port;
	process.stdout.write(`https://127.0.0.1:${port}/\n`);
	process.stdout.write(`poppy.json https://127.0.0.1:${port}/.well-known/poppy.json\n`);
	process.stdout.write(`trust this CA for the process that fetches it: ${tls.dir}/ca.crt\n`);
});

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
	const url = new URL(req.url ?? "/", "https://127.0.0.1");
	const origin = `https://${req.headers.host ?? "127.0.0.1"}`;
	const domain = (req.headers.host ?? "127.0.0.1").replace(/:\d+$/, "");
	if (req.method === "GET" && url.pathname === "/.well-known/poppy.json") {
		send(res, 200, `${JSON.stringify({
			protocol_version: "0.1",
			organization: { name: "Todo", domain },
			auth: { issuer: origin },
			web: {},
		}, null, 2)}\n`, "application/json");
		return;
	}
	if (req.method === "GET" && url.pathname === "/.well-known/oauth-authorization-server") {
		sendJson(res, 200, {
			issuer: origin,
			token_endpoint: `${origin}/oauth/token`,
			revocation_endpoint: `${origin}/oauth/revoke`,
			poppy_domains: [domain],
			scopes_supported: ["poppy:read"],
		});
		return;
	}
	if (req.method === "POST" && url.pathname === "/oauth/token") {
		await issueSession(req, res, origin);
		return;
	}
	if (req.method === "POST" && url.pathname === "/oauth/revoke") {
		sendJson(res, 200, {});
		return;
	}
	const user = currentUser(req);
	if (req.method === "POST" && url.pathname === "/login") {
		const form = await readForm(req);
		const email = (form.get("email") ?? "").trim().toLowerCase();
		const password = form.get("password") ?? "";
		if (!email || !password) return sendPage(res, 400, loginPage("Email and password are required."));
		const existing = users.get(email);
		if (!existing) users.set(email, { email, password, todos: [] });
		else if (existing.password !== password) return sendPage(res, 401, loginPage("Wrong password."));
		const sid = randomBytes(18).toString("base64url");
		sessions.set(sid, email);
		res.setHeader("set-cookie", `todo=${sid}; HttpOnly; Path=/; SameSite=Lax`);
		res.writeHead(303, { location: "/" });
		res.end();
		return;
	}
	if (req.method === "POST" && url.pathname === "/logout") {
		const sid = readCookie(req, "todo");
		if (sid) sessions.delete(sid);
		res.setHeader("set-cookie", "todo=; HttpOnly; Path=/; Max-Age=0");
		res.writeHead(303, { location: "/" });
		res.end();
		return;
	}
	if (!user) {
		sendPage(res, req.method === "GET" && url.pathname === "/" ? 200 : 401, loginPage(""));
		return;
	}
	if (req.method === "POST" && url.pathname === "/todos") {
		const form = await readForm(req);
		const text = (form.get("text") ?? "").trim();
		if (text) user.todos.push({ id: randomBytes(6).toString("base64url"), text, done: false });
		res.writeHead(303, { location: "/" });
		res.end();
		return;
	}
	const done = /^\/todos\/([^/]+)\/done$/.exec(url.pathname);
	if (req.method === "POST" && done) {
		const todo = user.todos.find((item) => item.id === done[1]);
		if (todo) todo.done = !todo.done;
		res.writeHead(303, { location: "/" });
		res.end();
		return;
	}
	if (req.method === "GET" && url.pathname === "/") {
		sendPage(res, 200, listPage(user));
		return;
	}
	send(res, 404, "not found\n", "text/plain");
}

async function issueSession(req: IncomingMessage, res: ServerResponse, origin: string): Promise<void> {
	const form = await readForm(req);
	const tokenEndpoint = `${origin}/oauth/token`;
	if (form.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer") {
		return sendJson(res, 400, { error: "unsupported_grant_type", error_description: "only a signed-out session can be started here" });
	}
	try {
		const clientId = form.get("client_id") ?? "";
		const client = await loadClient(clientId);
		verifyAssertion(form.get("client_assertion") ?? "", client, tokenEndpoint, false);
		const user = verifyAssertion(form.get("assertion") ?? "", client, tokenEndpoint, true);
		const userId = typeof user.payload.sub === "string" ? user.payload.sub : "";
		if (!userId || user.payload.iss !== clientId) {
			return sendJson(res, 400, { error: "invalid_grant", error_description: "session assertion iss or sub is wrong" });
		}
		const proof = headerOne(req.headers, "dpop");
		if (!proof) return sendJson(res, 400, { error: "invalid_dpop_proof", error_description: "DPoP proof required" }, { "www-authenticate": 'DPoP error="invalid_dpop_proof"' });
		verifyDpop(proof, tokenEndpoint);
		const existing = form.get("session_id");
		const known = existing ? poppySessions.get(existing) : undefined;
		if (existing && (!known || known.clientId !== clientId || known.userId !== userId)) {
			return sendJson(res, 400, { error: "invalid_session", error_description: "session has ended or belongs to someone else" });
		}
		const sessionId = existing || `ses_${randomId(8)}`;
		poppySessions.set(sessionId, { clientId, userId });
		sendJson(res, 200, {
			access_token: `st1_${randomBytes(24).toString("base64url")}`,
			token_type: "DPoP",
			expires_in: 3600,
			scope: "",
			session_id: sessionId,
			signed_in: false,
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : "token request failed";
		sendJson(res, 400, { error: "invalid_client", error_description: message });
	}
}

async function loadClient(clientId: string): Promise<{ clientId: string; keys: Map<string, ReturnType<typeof importPublicJwk>> }> {
	const document = await fetchHttps(clientId);
	const meta = parseClientMetadata(parseJson(document), clientId);
	const jwks = parseJson(await fetchHttps(meta.jwks_uri)) as { keys?: JsonWebKey[] };
	const keys = new Map<string, ReturnType<typeof importPublicJwk>>();
	for (const jwk of jwks.keys ?? []) keys.set(typeof jwk.kid === "string" ? jwk.kid : `k${keys.size}`, importPublicJwk(jwk));
	if (keys.size === 0) throw new Error("jwks is empty");
	return { clientId: meta.client_id, keys };
}

async function fetchHttps(url: string): Promise<string> {
	const response = await httpRequest(url, {
		method: "GET",
		metadata: true,
		followRedirects: false,
		timeoutMs: 5_000,
		maxBytes: 100_000,
		ca: agentCa,
		allowLoopback: true,
	});
	if (response.status !== 200) throw new Error(`fetch ${url} failed ${response.status}`);
	return response.body.toString("utf8");
}

function verifyAssertion(token: string, client: { clientId: string; keys: Map<string, ReturnType<typeof importPublicJwk>> }, audience: string, userAssertion: boolean): ReturnType<typeof verifyJwt> {
	const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
	if (header.jwk) throw new Error("assertion must not embed a key");
	const key = (header.kid && client.keys.get(header.kid)) || (!header.kid && client.keys.size === 1 ? [...client.keys.values()][0] : undefined);
	if (!key) throw new Error("unknown signing key");
	const verified = verifyJwt(token, key, { audience, issuer: userAssertion ? client.clientId : undefined, requireStringAud: true, maxLifetimeSec: 120 });
	if (!userAssertion && (verified.payload.iss !== client.clientId || verified.payload.sub !== client.clientId)) {
		throw new Error("client assertion iss or sub mismatch");
	}
	const jti = String(verified.payload.jti ?? "");
	if (!jti || seenJti.has(jti)) throw new Error("assertion jti was reused");
	seenJti.add(jti);
	return verified;
}

function verifyDpop(token: string, tokenEndpoint: string): void {
	const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as JwtHeader;
	if (header.typ !== "dpop+jwt" || !header.jwk) throw new Error("DPoP proof is malformed");
	const key = importPublicJwk(header.jwk);
	jwkThumbprint(publicOnly(header.jwk));
	const verified = verifyJwt(token, key, { maxLifetimeSec: 120 });
	if (verified.payload.htm !== "POST" || verified.payload.htu !== tokenEndpoint) throw new Error("DPoP htm or htu mismatch");
	const jti = String(verified.payload.jti ?? "");
	if (!jti || seenJti.has(`dpop:${jti}`)) throw new Error("DPoP jti was reused");
	seenJti.add(`dpop:${jti}`);
}

function currentUser(req: IncomingMessage): User | undefined {
	const sid = readCookie(req, "todo");
	const email = sid ? sessions.get(sid) : undefined;
	return email ? users.get(email) : undefined;
}

function readCookie(req: IncomingMessage, name: string): string | undefined {
	const header = req.headers.cookie ?? "";
	for (const part of header.split(";")) {
		const [key, value] = part.trim().split("=");
		if (key === name) return value;
	}
	return undefined;
}

function readForm(req: IncomingMessage): Promise<URLSearchParams> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => chunks.push(chunk));
		req.on("end", () => resolve(new URLSearchParams(Buffer.concat(chunks).toString("utf8"))));
		req.on("error", reject);
	});
}

function loginPage(message: string): string {
	return `<!doctype html><title>Todo</title><h1>Todo</h1>${message ? `<p>${escapeHtml(message)}</p>` : ""}<form method="post" action="/login"><label>Email <input name="email" type="email" required></label><label>Password <input name="password" type="password" required></label><button>Sign in</button></form><p>The first sign-in creates the user. The list stays in memory until this process exits.</p>`;
}

function listPage(user: User): string {
	const items = user.todos.map((todo) => `<li><form method="post" action="/todos/${todo.id}/done"><button>${todo.done ? "undo" : "done"}</button></form> ${todo.done ? `<s>${escapeHtml(todo.text)}</s>` : escapeHtml(todo.text)}</li>`).join("");
	return `<!doctype html><title>Todo</title><h1>${escapeHtml(user.email)}</h1><form method="post" action="/logout"><button>Sign out</button></form><ul>${items}</ul><form method="post" action="/todos"><input name="text" required><button>Add</button></form>`;
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char] ?? char);
}

function sendPage(res: ServerResponse, status: number, html: string): void {
	send(res, status, html, "text/html; charset=utf-8");
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
	if (headers) {
		for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
	}
	res.setHeader("cache-control", "no-store");
	send(res, status, `${JSON.stringify(body)}\n`, "application/json");
}

function send(res: ServerResponse, status: number, body: string, type: string): void {
	res.writeHead(status, { "content-type": type });
	res.end(body);
}
