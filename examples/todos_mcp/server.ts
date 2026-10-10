/**
 * In-memory todos behind a Poppy MCP endpoint.
 *
 *   TODO_AGENT_CA=agent-ca.pem node --experimental-strip-types examples/todos_mcp/server.ts
 *
 * poppy_mcp_connect asks for a Bearer token whose resource is this MCP URL.
 * Tools are list_todos, add_todo, and complete_todo. Lists are keyed by the
 * agent's user id and disappear when this process exits.
 */
import { randomId } from "../../src/codec.ts";
import { headerOne } from "../../src/net.ts";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { addTodo, completeTodo, listTodos, readBody, sendJson, SessionIssuer, todoStore } from "../lib/session_issuer.ts";
import { createTestMaterial } from "../../src/tls.ts";

const issuer = new SessionIssuer();
const todos = todoStore();
const mcpSessions = new Set<string>();
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
			organization: { name: "Todos MCP", domain },
			auth: { issuer: origin },
			apis: [{ type: "mcp", url: `${origin}/mcp`, description: "In-memory todos" }],
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
	if (req.method === "POST" && url.pathname === "/oauth/token") return issuer.handleToken(req, res, origin);
	if (req.method === "POST" && url.pathname === "/oauth/revoke") return sendJson(res, 200, {});
	if (req.method === "POST" && url.pathname === "/mcp") return mcp(req, res);
	sendJson(res, 404, { error: "not_found" });
}

async function mcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
	const rpc = JSON.parse(await readBody(req) || "{}") as { id?: unknown; method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };
	if (rpc.method === "initialize") {
		const id = randomId(12);
		mcpSessions.add(id);
		res.writeHead(200, { "content-type": "application/json", "mcp-session-id": id, "cache-control": "no-store" });
		res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "todos-mcp", version: "0.1.0" } } }));
		return;
	}
	if (rpc.method === "notifications/initialized") {
		res.writeHead(202);
		res.end();
		return;
	}
	const sid = headerOne(req.headers, "mcp-session-id");
	if (!sid || !mcpSessions.has(sid)) return sendJson(res, 400, { error: "invalid_request", error_description: "Mcp-Session-Id required" });
	const auth = issuer.require(req, "Bearer");
	if (rpc.method === "tools/list") {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { tools: [
			{ name: "list_todos", description: "List this agent's todos", inputSchema: { type: "object", properties: {} } },
			{ name: "add_todo", description: "Add a todo", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } },
			{ name: "complete_todo", description: "Mark a todo done", inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } },
		] } }));
		return;
	}
	if (rpc.method === "tools/call") {
		const name = rpc.params?.name;
		const args = rpc.params?.arguments ?? {};
		let text = "";
		if (name === "list_todos") text = JSON.stringify(listTodos(todos, auth.userId));
		else if (name === "add_todo") text = JSON.stringify(addTodo(todos, auth.userId, String(args.text ?? "")));
		else if (name === "complete_todo") text = JSON.stringify(completeTodo(todos, auth.userId, String(args.id ?? "")) ?? null);
		else return sendJson(res, 400, { jsonrpc: "2.0", id: rpc.id, error: { code: -32601, message: "unknown tool" } });
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { content: [{ type: "text", text }] } }));
		return;
	}
	sendJson(res, 400, { jsonrpc: "2.0", id: rpc.id, error: { code: -32601, message: "unknown method" } });
}
