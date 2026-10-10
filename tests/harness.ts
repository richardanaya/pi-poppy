import { join } from "node:path";
import { PersonalAgent, type LiveSession } from "../src/agent.ts";
import { CompanyServer, type CompanyOptions, type CompanyUser } from "../src/company.ts";
import { headerOne, httpRequest } from "../src/net.ts";
import { generateEs256 } from "../src/jwt.ts";
import { IdentityServer } from "../src/identity.ts";
import { MemoryStore } from "../src/store.ts";
import { createTestMaterial, type TestMaterial } from "../src/tls.ts";

export const USERS: CompanyUser[] = [
	{ accountId: "acct_ada", email: "ada@example.com", password: "correct-horse" },
	{ accountId: "acct_bea", email: "bea@example.com", password: "battery-staple", unusual: true, otp: "445566" },
];

export interface Lab {
	tls: TestMaterial;
	identity: IdentityServer;
	company: CompanyServer;
	agent: PersonalAgent;
	signing: ReturnType<typeof generateEs256>;
	store: MemoryStore;
	close: () => Promise<void>;
}

let sharedTls: TestMaterial | undefined;

export async function boot(options: Partial<CompanyOptions> & { extensions?: Record<string, { version: string }> } = {}): Promise<Lab> {
	sharedTls ??= createTestMaterial();
	const tls = sharedTls;
	const keys = generateEs256();
	const identity = new IdentityServer({
		cert: tls.certPem,
		key: tls.keyPem,
		clientName: "Pi Poppy",
		signingPublicJwk: keys.publicJwk,
		kid: "agent-1",
		extensions: options.extensions ?? { operations: { version: "1" } },
	});
	await identity.start();
	const { extensions: _extensions, ...companyOptions } = options;
	if (companyOptions.blocklist?.includes("self")) companyOptions.blocklist = [identity.clientId];
	const company = new CompanyServer({
		cert: tls.certPem,
		key: tls.keyPem,
		ca: tls.caPem,
		allowLoopback: true,
		users: USERS,
		...companyOptions,
	});
	await company.start();
	const store = new MemoryStore();
	const agent = new PersonalAgent({
		clientId: identity.clientId,
		clientName: "Pi Poppy",
		redirectUris: [identity.redirectUri],
		signingPrivateJwk: keys.privateJwk,
		signingKid: "agent-1",
		store,
		ca: tls.caPem,
		allowLoopback: true,
	});
	return {
		tls,
		identity,
		company,
		agent,
		signing: keys,
		store,
		close: async () => {
			await company.close();
			await identity.close();
		},
	};
}

export function net(lab: Lab) {
	return { ca: lab.tls.caPem, allowLoopback: true as const, timeoutMs: 10_000, maxBytes: 1_000_000 };
}

export async function session(lab: Lab): Promise<LiveSession> {
	const found = await lab.agent.discover(lab.company.baseUrl);
	return lab.agent.startSession(found);
}

export async function approveDirect(lab: Lab, live: LiveSession, scope: string, user: CompanyUser = USERS[0]!): Promise<LiveSession> {
	const started = await lab.agent.beginDirectSignIn(live, scope);
	const page = await httpRequest(started.url, { ...net(lab) });
	const html = page.body.toString("utf8");
	const formToken = /name="form_token" value="([^"]+)"/.exec(html)?.[1];
	if (!formToken) throw new Error(`consent page had no form token: ${page.status}`);
	const body = new URLSearchParams();
	body.set("form_token", formToken);
	body.set("email", user.email);
	body.set("password", user.password);
	body.set("decision", "approve");
	for (const item of scope.split(" ")) body.append("scope", item);
	const endpoint = live.discovery.metadata?.authorization_endpoint;
	if (!endpoint) throw new Error("no authorization endpoint");
	const posted = await httpRequest(endpoint, {
		...net(lab),
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: body.toString(),
		followRedirects: false,
	});
	const location = headerOne(posted.headers, "location");
	if (!location) throw new Error(`no redirect (${posted.status}) ${posted.body.toString("utf8")}`);
	return lab.agent.completeDirectSignIn(location);
}

export async function approveDevice(lab: Lab, live: LiveSession, scope: string, user: CompanyUser = USERS[0]!): Promise<LiveSession> {
	const login = await lab.agent.beginDeviceSignIn(live, scope);
	const opened = await httpRequest(login.verificationUriComplete ?? login.verificationUri, { ...net(lab) });
	if (!opened.body.toString("utf8").includes("does not approve")) throw new Error("device page approved by opening");
	const body = new URLSearchParams({ user_code: login.userCode, email: user.email, password: user.password, decision: "approve" });
	const posted = await httpRequest(login.verificationUri, {
		...net(lab),
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: body.toString(),
	});
	if (posted.status !== 200) throw new Error(posted.body.toString("utf8"));
	const polled = await lab.agent.pollDeviceSignIn(login, { wait: false });
	if (polled.pending) throw new Error("device sign-in still pending");
	return polled.session;
}

export function certPaths(tls: TestMaterial): { cert: string; key: string; ca: string } {
	return { cert: join(tls.dir, "server.crt"), key: join(tls.dir, "server.key"), ca: join(tls.dir, "ca.crt") };
}
