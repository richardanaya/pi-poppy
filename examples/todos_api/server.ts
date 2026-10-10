/**
 * In-memory todos behind a Poppy OpenAPI document.
 *
 *   TODO_AGENT_CA=agent-ca.pem node --experimental-strip-types examples/todos_api/server.ts
 *
 * A personal agent starts a signed-out session, then calls GET /todos and
 * POST /todos with its DPoP session token. Lists are keyed by the agent's
 * user id and disappear when this process exits.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { addTodo, completeTodo, listTodos, readBody, sendJson, SessionIssuer, todoStore } from "../lib/session_issuer.ts";
import { createTestMaterial } from "../../src/tls.ts";

const issuer = new SessionIssuer();
const todos = todoStore();
const tls = createTestMaterial();
const server = createServer({ cert: tls.certPem, key: tls.keyPem }, (req, res) => {
	void handle(req, res).catch((error: Error & { status?: number }) => {
		if (!res.headersSent) sendJson(res, error.status ?? 400, { error: "invalid_request", error_description: error.message });
	});
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
		return sendJson(res, 200, {
			protocol_version: "0.1",
			organization: { name: "Todos API", domain },
			auth: { issuer: origin },
			apis: [{ type: "openapi", url: `${origin}/openapi.json`, description: "In-memory todos" }],
		});
	}
	if (req.method === "GET" && url.pathname === "/.well-known/oauth-authorization-server") {
		return sendJson(res, 200, {
			issuer: origin,
			token_endpoint: `${origin}/oauth/token`,
			revocation_endpoint: `${origin}/oauth/revoke`,
			poppy_domains: [domain],
		});
	}
	if (req.method === "GET" && url.pathname === "/openapi.json") {
		return sendJson(res, 200, {
			openapi: "3.1.0",
			info: { title: "Todos", version: "0.1.0" },
			paths: {
				"/todos": {
					get: { summary: "List todos for this agent user" },
					post: { summary: "Add a todo. JSON body { text }" },
				},
				"/todos/{id}/done": { post: { summary: "Mark a todo done" } },
			},
		});
	}
	if (req.method === "POST" && url.pathname === "/oauth/token") return issuer.handleToken(req, res, origin);
	if (req.method === "POST" && url.pathname === "/oauth/revoke") return sendJson(res, 200, {});
	const auth = issuer.require(req, "DPoP");
	if (req.method === "GET" && url.pathname === "/todos") return sendJson(res, 200, { todos: listTodos(todos, auth.userId) });
	if (req.method === "POST" && url.pathname === "/todos") {
		const body = JSON.parse(await readBody(req) || "{}") as { text?: string };
		const text = (body.text ?? "").trim();
		if (!text) return sendJson(res, 400, { error: "invalid_request", error_description: "text is required" });
		return sendJson(res, 200, { todo: addTodo(todos, auth.userId, text) });
	}
	const done = /^\/todos\/([^/]+)\/done$/.exec(url.pathname);
	if (req.method === "POST" && done) {
		const todo = completeTodo(todos, auth.userId, done[1] ?? "");
		if (!todo) return sendJson(res, 404, { error: "not_found", error_description: "todo not found" });
		return sendJson(res, 200, { todo });
	}
	sendJson(res, 404, { error: "not_found" });
}
