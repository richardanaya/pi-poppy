import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { REQUIREMENTS } from "../src/requirements.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("S001-S143 every requirement is met, named in the README, and named by its test", async () => {
	const files = (await readdir(join(root, "tests"))).filter((name) => name.endsWith(".test.ts"));
	const sources = new Map<string, string>();
	for (const file of files) sources.set(file, await readFile(join(root, "tests", file), "utf8"));
	const readme = await readFile(join(root, "README.md"), "utf8");
	const seen = new Set<string>();
	assert.equal(REQUIREMENTS.length, 143);
	for (const requirement of REQUIREMENTS) {
		assert.match(requirement.id, /^S\d{3}$/);
		assert.equal(seen.has(requirement.id), false);
		seen.add(requirement.id);
		assert.equal(requirement.status, "met", requirement.id);
		assert.ok(readme.includes(`| ${requirement.id} |`), `${requirement.id} missing from the compliance table`);
		const named = requirement.test.split(", ").filter(Boolean);
		assert.ok(named.length > 0, requirement.id);
		for (const file of named) {
			const source = sources.get(file);
			assert.ok(source, `${requirement.id} names missing file ${file}`);
			assert.match(source, new RegExp(`\\b${requirement.id}\\b`), `${requirement.id} missing from ${file}`);
		}
	}
	assert.equal(seen.size, 143);
	for (const id of ["S256"]) assert.equal(REQUIREMENTS.some((requirement) => requirement.id === id), false);
});
