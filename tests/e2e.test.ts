import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PersonalAgent } from "../src/agent.ts";
import { generateEs256 } from "../src/jwt.ts";
import { IdentityServer } from "../src/identity.ts";
import { MemoryStore } from "../src/store.ts";
import { createTestMaterial } from "../src/tls.ts";
import { certPaths } from "./harness.ts";

test("S002 S040 two pi-poppy processes talk over HTTPS", async () => {
	const tls = createTestMaterial();
	const paths = certPaths(tls);
	const child = spawn(process.execPath, [
		"--experimental-strip-types",
		"tests/company-peer.ts",
		"--cert",
		paths.cert,
		"--key",
		paths.key,
		"--ca",
		paths.ca,
		"--allow-loopback",
		"--user",
		"ada@example.com:correct-horse:acct_ada",
	], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
	let output = "";
	child.stdout.setEncoding("utf8");
	child.stdout.on("data", (chunk: string) => {
		output += chunk;
	});
	child.stderr.setEncoding("utf8");
	child.stderr.on("data", (chunk: string) => {
		output += chunk;
	});
	const ready = await Promise.race([
		waitFor(child, () => /ready https:\/\/127\.0\.0\.1:\d+/.exec(output)?.[0]),
		once(child, "exit").then(() => {
			throw new Error(output || "company process exited");
		}),
	]);
	const baseUrl = String(ready).replace("ready ", "");
	const keys = generateEs256();
	const identity = new IdentityServer({
		cert: tls.certPem,
		key: tls.keyPem,
		clientName: "Pi Poppy",
		signingPublicJwk: keys.publicJwk,
		kid: "agent-1",
	});
	await identity.start();
	const dir = await mkdtemp(join(tmpdir(), "poppy-e2e-"));
	await writeFile(join(dir, "ca.pem"), tls.caPem);
	const agent = new PersonalAgent({
		clientId: identity.clientId,
		clientName: "Pi Poppy",
		redirectUris: [identity.redirectUri],
		signingPrivateJwk: keys.privateJwk,
		signingKid: "agent-1",
		store: new MemoryStore(),
		ca: tls.caPem,
		allowLoopback: true,
	});
	try {
		const found = await agent.discover(baseUrl);
		assert.equal(found.document.protocol_version, "0.1");
		const live = await agent.startSession(found);
		const sent = await agent.sendMessage(live, { id: "msg_e2e", sender: "agent", text: "hello from another process" }, { wait: 0 });
		assert.equal(sent.status, "idle");
		assert.equal(sent.responder, "agent");
		assert.ok((sent.events?.events.length ?? 0) > 0);
		assert.equal(JSON.stringify(agent.describe(live)).includes(live.accessToken), false);
	} finally {
		await identity.close();
		child.kill("SIGTERM");
		await once(child, "exit").catch(() => undefined);
	}
});

async function waitFor(child: ReturnType<typeof spawn>, read: () => string | undefined): Promise<string> {
	for (let i = 0; i < 50; i++) {
		const found = read();
		if (found) return found;
		if (child.exitCode !== null) break;
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
	throw new Error("company process did not become ready");
}
