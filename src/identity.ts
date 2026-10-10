import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { JsonWebKey } from "node:crypto";
import { publicOnly } from "./jwt.ts";

export interface IdentityServerOptions {
	cert: string;
	key: string;
	clientName: string;
	signingPublicJwk: JsonWebKey;
	kid: string;
	extensions?: Record<string, { version: string }>;
	logoUri?: string;
}

/**
 * Serves the OAuth client metadata document and JWKS, and records the Direct
 * Sign-In redirect. Companies fetch `client_id` from this server.
 */
export class IdentityServer {
	readonly clientId: string;
	readonly redirectUri: string;
	readonly jwksUri: string;
	private server: ReturnType<typeof createServer> | undefined;
	private pending: URL[] = [];
	private base = "";

	private readonly options: IdentityServerOptions;
	constructor(options: IdentityServerOptions) {
		this.options = options;
		this.clientId = "";
		this.redirectUri = "";
		this.jwksUri = "";
	}

	async start(): Promise<void> {
		this.server = createServer({ cert: this.options.cert, key: this.options.key }, (req, res) => {
			void this.handle(req, res);
		});
		await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", resolve));
		const port = (this.server.address() as AddressInfo).port;
		this.base = `https://127.0.0.1:${port}`;
		(this as { clientId: string }).clientId = `${this.base}/agent.json`;
		(this as { redirectUri: string }).redirectUri = `${this.base}/oauth/callback`;
		(this as { jwksUri: string }).jwksUri = `${this.base}/jwks.json`;
	}

	get baseUrl(): string {
		return this.base;
	}

	takeCallback(): URL | undefined {
		return this.pending.shift();
	}

	async close(): Promise<void> {
		const server = this.server;
		this.server = undefined;
		if (!server) return;
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}

	private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
		const url = new URL(req.url ?? "/", this.base || "https://127.0.0.1");
		if (req.method === "GET" && url.pathname === "/agent.json") {
			const body = {
				client_id: this.clientId,
				client_name: this.options.clientName,
				logo_uri: this.options.logoUri ?? `${this.base}/logo.png`,
				jwks_uri: this.jwksUri,
				redirect_uris: [this.redirectUri],
				token_endpoint_auth_method: "private_key_jwt",
				extensions: this.options.extensions ?? { operations: { version: "1" } },
			};
			res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=60" });
			res.end(JSON.stringify(body));
			return;
		}
		if (req.method === "GET" && url.pathname === "/jwks.json") {
			const jwk = publicOnly(this.options.signingPublicJwk);
			jwk.kid = this.options.kid;
			jwk.alg = "ES256";
			jwk.use = "sig";
			res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=60" });
			res.end(JSON.stringify({ keys: [jwk] }));
			return;
		}
		if (req.method === "GET" && url.pathname === "/logo.png") {
			res.writeHead(200, { "content-type": "image/png" });
			res.end();
			return;
		}
		if (req.method === "GET" && url.pathname === "/oauth/callback") {
			this.pending.push(url);
			res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
			res.end("<!doctype html><title>Signed in</title><p>You can return to pi-poppy.</p>");
			return;
		}
		res.writeHead(404, { "content-type": "text/plain" });
		res.end("not found");
	}
}
