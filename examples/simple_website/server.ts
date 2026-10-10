/**
 * A fake company that offers only its website.
 *
 *   node --experimental-strip-types examples/simple_website/server.ts
 *
 * poppy.json has a web entry and nothing else: no company agent, no APIs,
 * no sign-in, and no browser-session endpoint. A personal agent treats the
 * pages as an ordinary signed-out visit.
 */
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { createTestMaterial } from "../../src/tls.ts";

const tls = createTestMaterial();
const server = createServer({ cert: tls.certPem, key: tls.keyPem }, (req, res) => {
	const url = new URL(req.url ?? "/", "https://127.0.0.1");
	if (req.method === "GET" && url.pathname === "/.well-known/poppy.json") {
		const host = (req.headers.host ?? "127.0.0.1").replace(/:\d+$/, "");
		const body = {
			protocol_version: "0.1",
			organization: { name: "Simple Website", domain: host },
			web: {},
		};
		res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=60" });
		res.end(`${JSON.stringify(body, null, 2)}\n`);
		return;
	}
	if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
		res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
		res.end("<!doctype html><title>Simple Website</title><h1>Simple Website</h1><p>This company offers only its website.</p>");
		return;
	}
	res.writeHead(404, { "content-type": "text/plain" });
	res.end("not found");
});

server.listen(0, "127.0.0.1", () => {
	const port = (server.address() as AddressInfo).port;
	process.stdout.write(`https://127.0.0.1:${port}/\n`);
	process.stdout.write(`poppy.json https://127.0.0.1:${port}/.well-known/poppy.json\n`);
	process.stdout.write(`trust this CA for the process that fetches it: ${tls.dir}/ca.crt\n`);
});
