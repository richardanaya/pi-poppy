const SECRET_HEADERS = new Set(["authorization", "dpop", "cookie", "set-cookie", "proxy-authorization"]);
const SECRET_FIELDS = new Set(["password", "secret", "code", "credentials", "access_token", "refresh_token", "device_code", "assertion", "client_assertion"]);

/** Redact headers and credential fields before anything is logged. */
export function redactHeaders(headers: Record<string, string | undefined>): Record<string, string | undefined> {
	const out: Record<string, string | undefined> = {};
	for (const [key, value] of Object.entries(headers)) {
		out[key] = SECRET_HEADERS.has(key.toLowerCase()) ? "[redacted]" : value;
	}
	return out;
}

export function redactValue(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(redactValue);
	if (!value || typeof value !== "object") return value;
	const out: Record<string, unknown> = {};
	for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
		if (SECRET_FIELDS.has(key.toLowerCase())) out[key] = "[redacted]";
		else out[key] = redactValue(inner);
	}
	return out;
}

export function redactText(text: string): string {
	return text
		.replace(/\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g, "[redacted-jwt]")
		.replace(/\b(pat_[A-Za-z0-9_-]{8,})/g, "[redacted-token]")
		.replace(/\b(st1_[A-Za-z0-9_-]{8,})/g, "[redacted-token]");
}

/** True when a tool result or log line still carries a raw credential. */
export function containsSecret(text: string, secrets: string[]): boolean {
	return secrets.some((secret) => secret.length > 0 && text.includes(secret));
}
