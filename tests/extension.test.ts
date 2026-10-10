import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import poppy from "../index.ts";
import { publicOnly } from "../src/jwt.ts";
import { headerOne, httpRequest } from "../src/net.ts";
import { emptyState, FileStore } from "../src/store.ts";
import { USERS, boot, net } from "./harness.ts";

test("S044 S063 S090 S115 S121 S143 extension tools ask the user and register MCP through pi", async () => {
	const lab = await boot();
	const dir = await mkdtemp(join(tmpdir(), "poppy-ext-"));
	const storePath = join(dir, "poppy.json");
	const caPath = join(dir, "ca.pem");
	await writeFile(caPath, lab.tls.caPem);
	const identityStore = new FileStore(storePath);
	const state = emptyState({
		clientName: "Pi Poppy",
		signingKid: "agent-1",
		signingPrivateJwk: lab.signing.privateJwk,
		signingPublicJwk: publicOnly(lab.signing.publicJwk),
	});
	state.clientId = lab.identity.clientId;
	state.redirectUris = [lab.identity.redirectUri];
	await identityStore.save(state);
	process.env.PI_POPPY_STORE = storePath;
	process.env.PI_POPPY_ALLOW_LOOPBACK = "1";
	process.env.PI_POPPY_CA = caPath;

	const tools = new Map<string, { parameters: unknown; promptGuidelines?: string[]; execute: Function }>();
	const commands = new Map<string, { handler: Function }>();
	const servers: Array<{ name: string; config: unknown }> = [];
	const pi = {
		registerTool(tool: { name: string; parameters: unknown; promptGuidelines?: string[]; execute: Function }) {
			tools.set(tool.name, tool);
		},
		registerCommand(name: string, options: { handler: Function }) {
			commands.set(name, options);
		},
		registerMcpServer(name: string, config: unknown) {
			servers.push({ name, config });
		},
	};
	poppy(pi as unknown as ExtensionAPI);
	assert.equal(tools.has("poppy_discover"), true);
	assert.equal(commands.has("poppy-connect"), true);
	const source = await readFile(new URL("../index.ts", import.meta.url), "utf8");
	assert.equal(source.includes("mcp_servers_change"), false);
	const signInParams = JSON.stringify(tools.get("poppy_sign_in")?.parameters);
	assert.equal(signInParams.includes("password"), false);
	assert.match(tools.get("poppy_sign_in")?.promptGuidelines?.join(" ") ?? "", /only the locale/);
	assert.match(tools.get("poppy_operation_confirm")?.promptGuidelines?.join(" ") ?? "", /not the user's approval/);
	assert.match(source, /Do not request another proposal/);

	const ctx = uiContext(async (title, placeholder) => {
		if (title !== "Callback URL" || !placeholder) return "cancelled";
		const page = await httpRequest(placeholder, net(lab));
		const html = page.body.toString("utf8");
		const formToken = /name="form_token" value="([^"]+)"/.exec(html)?.[1];
		assert.ok(formToken);
		const body = new URLSearchParams({ form_token: formToken, email: USERS[0]!.email, password: USERS[0]!.password, decision: "approve" });
		body.append("scope", "poppy:read");
		body.append("scope", "poppy:write");
		const posted = await httpRequest(new URL(placeholder).origin + "/oauth/authorize", {
			...net(lab),
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: body.toString(),
			followRedirects: false,
		});
		return headerOne(posted.headers, "location") ?? "";
	});

	try {
		const started = await tools.get("poppy_session_start")!.execute("1", { domain: lab.company.baseUrl }, undefined, undefined, ctx);
		assert.equal(JSON.stringify(started).includes("st1_"), false);
		assert.equal(JSON.stringify(started).includes("pat_"), false);
		const signed = await tools.get("poppy_sign_in")!.execute("2", { scope: "poppy:read poppy:write", method: "direct" }, undefined, undefined, ctx);
		assert.match(JSON.stringify(signed), /Signed in/);
		assert.equal(JSON.stringify(signed).includes("pat_"), false);
		await tools.get("poppy_mcp_connect")!.execute("3", {}, undefined, undefined, ctx);
		assert.equal(servers.length, 1);
		const mod = await import(pathToFileURL(join(process.cwd(), "node_modules/@earendil-works/pi-coding-agent/dist/core/mcp-servers.js")).href) as {
			validateMcpServerConfig: (name: string, raw: unknown) => unknown;
		};
		const validated = mod.validateMcpServerConfig(servers[0]!.name, { ...servers[0]!.config as object, type: "http" });
		assert.equal(typeof validated, "object");
		const sent = await tools.get("poppy_conversation_send")!.execute("4", { text: "Please exchange the jacket", sender: "agent" }, undefined, undefined, ctx) as { details: { operations?: string[] } };
		const operationId = sent.details.operations?.[0];
		assert.ok(operationId);
		let sawSummary = "";
		ctx.ui.confirm = async (title: string, message: string) => {
			assert.equal(title, "Example Company");
			sawSummary = message;
			return true;
		};
		const confirmed = await tools.get("poppy_operation_confirm")!.execute("5", { operation_id: operationId }, undefined, undefined, ctx);
		assert.equal(sawSummary.length > 0, true);
		assert.match(JSON.stringify(confirmed), /Exchange placed|in_progress|succeeded/);
		assert.equal(JSON.stringify(confirmed).includes("pat_"), false);
	} finally {
		delete process.env.PI_POPPY_STORE;
		delete process.env.PI_POPPY_ALLOW_LOOPBACK;
		delete process.env.PI_POPPY_CA;
		await lab.close();
	}
});

function uiContext(onInput: (title: string, placeholder?: string) => Promise<string>): ExtensionCommandContext {
	return {
		ui: {
			notify() {},
			async confirm() {
				return true;
			},
			input: onInput,
			select: async () => undefined,
			setStatus() {},
			setWorkingMessage() {},
			setWorkingVisible() {},
			setWorkingIndicator() {},
			setHiddenThinkingLabel() {},
			setWidget() {},
			onTerminalInput() {
				return () => {};
			},
		},
	} as unknown as ExtensionCommandContext;
}
