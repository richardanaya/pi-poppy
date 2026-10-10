/**
 * Company process for the end-to-end test. Not a user-facing command.
 */
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { CompanyServer, type CompanyUser } from "../src/company.ts";

const { values } = parseArgs({
	options: {
		cert: { type: "string" },
		key: { type: "string" },
		ca: { type: "string" },
		user: { type: "string", multiple: true },
		"allow-loopback": { type: "boolean", default: false },
	},
});

const cert = await material(values.cert);
const key = await material(values.key);
const ca = await material(values.ca);
if (!cert || !key) {
	process.stderr.write("company peer needs --cert and --key\n");
	process.exit(2);
}

const users: CompanyUser[] = (values.user ?? ["ada@example.com:correct-horse:acct_ada"]).map((entry) => {
	const [email, password, accountId] = entry.split(":");
	if (!email || !password || !accountId) throw new Error(`user must be email:password:account, got ${entry}`);
	return { email, password, accountId };
});

const company = new CompanyServer({ cert, key, ca, allowLoopback: values["allow-loopback"], users });
await company.start();
process.stdout.write(`ready ${company.baseUrl}\n`);
await new Promise(() => {});

async function material(value: string | undefined): Promise<string | undefined> {
	if (!value) return undefined;
	if (value.includes("BEGIN")) return value;
	return readFile(value, "utf8");
}
