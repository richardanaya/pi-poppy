#!/usr/bin/env -S node --experimental-strip-types
/**
 * Local Personal Agent Protocol peers.
 *
 *   pi-poppy identity --store ~/.pi/poppy.json
 *   pi-poppy company --cert server.crt --key server.key
 *
 * The identity command serves client metadata and a JWKS for the key in the
 * secret store. The company command is a PAP company peer for local testing.
 */
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { generateEs256, publicOnly } from "./src/jwt.ts";
import { CompanyServer, type CompanyUser } from "./src/company.ts";
import { IdentityServer } from "./src/identity.ts";
import { emptyState, FileStore } from "./src/store.ts";
import { createTestMaterial } from "./src/tls.ts";

const { positionals, values } = parseArgs({
	allowPositionals: true,
	options: {
		store: { type: "string", default: `${process.env.HOME ?? ""}/.pi/poppy.json` },
		cert: { type: "string" },
		key: { type: "string" },
		ca: { type: "string" },
		user: { type: "string", multiple: true },
		"allow-loopback": { type: "boolean", default: false },
		"self-signed": { type: "boolean", default: false },
	},
});

const role = positionals[0];
if (role !== "identity" && role !== "company") {
	process.stderr.write("usage: pi-poppy <identity|company> [--store path] [--cert file --key file] [--user email:password:account]\n");
	process.exit(2);
}

let cert = await material(values.cert);
let key = await material(values.key);
let ca = await material(values.ca);
if (values["self-signed"] || (!cert && !key)) {
	const material = createTestMaterial();
	cert = material.certPem;
	key = material.keyPem;
	ca = material.caPem;
	process.stderr.write(`test CA written under ${material.dir}\n`);
}
if (!cert || !key) {
	process.stderr.write("company and identity need --cert and --key, or --self-signed\n");
	process.exit(2);
}

if (role === "identity") {
	const store = new FileStore(values.store!);
	let state = await store.load();
	if (!state) {
		const generated = generateEs256();
		state = emptyState({
			clientName: "pi-poppy",
			signingKid: "pi-poppy-1",
			signingPrivateJwk: generated.privateJwk,
			signingPublicJwk: generated.publicJwk,
		});
		await store.save(state);
	}
	const identity = new IdentityServer({
		cert,
		key,
		clientName: state.clientName,
		signingPublicJwk: publicOnly(state.signingPublicJwk),
		kid: state.signingKid,
	});
	await identity.start();
	state.clientId = identity.clientId;
	state.redirectUris = [identity.redirectUri];
	await store.save(state);
	process.stdout.write(`ready ${identity.clientId}\n`);
} else {
	const users: CompanyUser[] = (values.user ?? ["ada@example.com:correct-horse:acct_ada"]).map((entry) => {
		const [email, password, accountId] = entry.split(":");
		if (!email || !password || !accountId) throw new Error(`user must be email:password:account, got ${entry}`);
		return { email, password, accountId };
	});
	const company = new CompanyServer({
		cert,
		key,
		ca,
		allowLoopback: values["allow-loopback"] || Boolean(values["self-signed"]),
		users,
	});
	await company.start();
	process.stdout.write(`ready ${company.baseUrl}\n`);
}

await new Promise(() => {});

async function material(value: string | undefined): Promise<string | undefined> {
	if (!value) return undefined;
	if (value.includes("BEGIN")) return value;
	return readFile(value, "utf8");
}
