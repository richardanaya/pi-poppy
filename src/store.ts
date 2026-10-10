import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { JsonWebKey } from "node:crypto";
import type { StandingPermission } from "./approval.ts";

export interface StoredAccount {
	refreshToken: string;
	scope: string;
	/** Issuer the token was issued by. */
	issuer: string;
}

export interface StoredCompany {
	userId: string;
	dpopPrivateJwk: JsonWebKey;
	dpopKid: string;
	accounts: StoredAccount[];
}

export interface SecretState {
	version: 1;
	clientName: string;
	signingKid: string;
	signingPrivateJwk: JsonWebKey;
	signingPublicJwk: JsonWebKey;
	/** HTTPS client metadata URL. */
	clientId?: string;
	redirectUris?: string[];
	/** Certificate for the client_id served on this machine. */
	localIdentity?: { cert: string; key: string; ca: string; port: number };
	/** local user key -> issuer -> company record */
	users: Record<string, Record<string, StoredCompany>>;
	permissions: StandingPermission[];
}

export interface Store {
	load(): Promise<SecretState | undefined>;
	save(state: SecretState): Promise<void>;
}

export class MemoryStore implements Store {
	private state: SecretState | undefined;
	constructor(state: SecretState | undefined = undefined) {
		this.state = state;
	}
	load(): Promise<SecretState | undefined> {
		return Promise.resolve(this.state ? structuredClone(this.state) : undefined);
	}
	save(state: SecretState): Promise<void> {
		this.state = structuredClone(state);
		return Promise.resolve();
	}
}

/** Account tokens and private keys. Mode 0600, outside model context. */
export class FileStore implements Store {
	private readonly path: string;
	constructor(path: string) {
		this.path = path;
	}
	async load(): Promise<SecretState | undefined> {
		try {
			const text = await readFile(this.path, "utf8");
			return JSON.parse(text) as SecretState;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
			throw error;
		}
	}
	async save(state: SecretState): Promise<void> {
		await mkdir(dirname(this.path), { recursive: true });
		const tmp = `${this.path}.tmp`;
		await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
		await chmod(tmp, 0o600);
		await rename(tmp, this.path);
		await chmod(this.path, 0o600);
	}
}

export function emptyState(input: {
	clientName: string;
	signingKid: string;
	signingPrivateJwk: JsonWebKey;
	signingPublicJwk: JsonWebKey;
}): SecretState {
	return {
		version: 1,
		clientName: input.clientName,
		signingKid: input.signingKid,
		signingPrivateJwk: input.signingPrivateJwk,
		signingPublicJwk: input.signingPublicJwk,
		users: {},
		permissions: [],
	};
}
