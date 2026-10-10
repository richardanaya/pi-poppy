import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface TestMaterial {
	dir: string;
	caPem: string;
	certPem: string;
	keyPem: string;
}

/** Local CA and a certificate for 127.0.0.1. Tests trust `caPem` and still verify TLS. */
export function createTestMaterial(): TestMaterial {
	const dir = mkdtempSync(join(tmpdir(), "poppy-tls-"));
	const caKey = join(dir, "ca.key");
	const caCert = join(dir, "ca.crt");
	const key = join(dir, "server.key");
	const csr = join(dir, "server.csr");
	const cert = join(dir, "server.crt");
	const ext = join(dir, "ext.cnf");
	execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCert, "-days", "2", "-subj", "/CN=pi-poppy-test-ca"], { stdio: "ignore" });
	execFileSync("openssl", ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1"], { stdio: "ignore" });
	writeFileSync(ext, "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");
	execFileSync("openssl", ["x509", "-req", "-in", csr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-out", cert, "-days", "2", "-extfile", ext], { stdio: "ignore" });
	return { dir, caPem: readFileSync(caCert, "utf8"), certPem: readFileSync(cert, "utf8"), keyPem: readFileSync(key, "utf8") };
}
