import { isOpaqueId } from "./codec.ts";
import { parseJson } from "./json.ts";

export class SchemaError extends Error {
	readonly errors: string[];
	constructor(message: string, errors: string[] = [message]) {
		super(message);
		this.name = "SchemaError";
		this.errors = errors;
	}
}

export interface MediatedField {
	name: string;
	label: string;
	secret: boolean;
}

export interface PoppyApi {
	type: string;
	url: string;
	description: string;
	resource?: string;
}

export interface PoppyProtocol {
	type: string;
	endpoint: string;
	resource?: string;
}

export interface PoppyExtension {
	version: string;
	endpoint?: string;
	resource?: string;
	[key: string]: unknown;
}

export interface PoppyDocument {
	protocol_version: string;
	organization: { name: string; domain: string };
	auth?: {
		issuer: string;
		direct?: { scopes: string[] };
		device?: { scopes: string[] };
		mediated?: { endpoint: string; fields: MediatedField[]; scopes: string[] };
		custom_scopes?: Record<string, string>;
	};
	agent?: { protocols: PoppyProtocol[] };
	web?: { browser_session_endpoint?: string };
	apis?: PoppyApi[];
	extensions?: Record<string, PoppyExtension>;
}

export interface OAuthServerMetadata {
	issuer: string;
	token_endpoint: string;
	revocation_endpoint: string;
	authorization_endpoint?: string;
	device_authorization_endpoint?: string;
	poppy_domains: string[];
}

export interface ClientMetadata {
	client_id: string;
	client_name?: string;
	logo_uri?: string;
	jwks_uri: string;
	redirect_uris: string[];
	token_endpoint_auth_method?: string;
	extensions?: Record<string, PoppyExtension>;
}

export interface TokenResponse {
	access_token: string;
	token_type: "DPoP" | "Bearer";
	expires_in: number;
	scope: string;
	session_id: string;
	signed_in: boolean;
	refresh_token?: string;
	refresh_token_expires_in?: number;
}

export interface DeviceAuthorizationResponse {
	device_code: string;
	user_code: string;
	verification_uri: string;
	verification_uri_complete?: string;
	expires_in: number;
	interval: number;
}

export interface AgentMessage {
	id: string;
	sender: "agent" | "human";
	text?: string;
	data?: Record<string, unknown>;
	context?: UserContext;
}

export interface CompanyMessage {
	id: string;
	role: "user" | "company";
	sender: "agent" | "human";
	text?: string;
	data?: Record<string, unknown>;
	operation?: Operation;
}

export interface UserContext {
	locale?: string;
	time_zone?: string;
	user_available?: boolean;
	[key: string]: unknown;
}

export interface Operation {
	operation_id: string;
	revision: number;
	state: "proposed" | "in_progress" | "succeeded" | "failed" | "cancelled" | "expired";
	summary: string;
	terms?: Record<string, unknown>;
	expires_at?: string;
	user_approval_required?: boolean;
	url?: string;
	confirmation: null | { revision: number; approved_by: "user" | "standing_permission"; confirmed_at: string };
	result: null | { summary: string; data?: Record<string, unknown> };
}

export interface ConversationEvent {
	id: string;
	type: string;
	created_at: string;
	message?: CompanyMessage;
	status?: string;
	responder?: string;
	error?: string;
	scope?: string;
	reason?: string;
	conversation_id?: string;
}

export interface EventsResponse {
	conversation_id: string;
	events: ConversationEvent[];
	cursor: string;
	has_more: boolean;
	status: ConversationStatus;
	responder: Responder;
}

export type ConversationStatus = "working" | "idle" | "queued" | "closed";
export type Responder = "agent" | "human";

const HTTPS = /^https:\/\/[^\s]+$/;
const LOCALE = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/;
const ZONE = /^(?:UTC|Etc\/UTC|[A-Za-z][A-Za-z0-9_+-]*\/[A-Za-z0-9_+-]+(?:\/[A-Za-z0-9_+-]+)?)$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const VERSION = /^\d+\.\d+$/;

export function parsePoppyDocument(input: unknown): PoppyDocument {
	const obj = object(input, "poppy.json");
	const version = str(obj, "protocol_version");
	if (!VERSION.test(version)) fail("protocol_version must be major.minor");
	const organization = object(obj.organization, "organization");
	const name = str(organization, "name");
	const domain = str(organization, "domain");
	if (!domain || domain.includes("/") || domain.includes(" ")) fail("organization.domain is invalid");
	const doc: PoppyDocument = { protocol_version: version, organization: { name, domain } };
	if (obj.auth !== undefined) doc.auth = parseAuth(obj.auth);
	if (obj.agent !== undefined) doc.agent = { protocols: parseProtocols(obj.agent) };
	if (obj.web !== undefined) doc.web = parseWeb(obj.web);
	if (obj.apis !== undefined) doc.apis = parseApis(obj.apis);
	if (obj.extensions !== undefined) doc.extensions = parseExtensions(obj.extensions);
	if (!doc.agent && !doc.apis && !doc.web) fail("one of agent, apis, or web is required");
	const needsAuth = Boolean(doc.agent || doc.apis || doc.web?.browser_session_endpoint);
	if (needsAuth && !doc.auth) fail("auth is required when agent, apis, or browser_session_endpoint is present");
	return doc;
}

export function parseOAuthMetadata(input: unknown): OAuthServerMetadata {
	const obj = object(input, "oauth metadata");
	const meta: OAuthServerMetadata = {
		issuer: httpsUrl(str(obj, "issuer"), "issuer"),
		token_endpoint: httpsUrl(str(obj, "token_endpoint"), "token_endpoint"),
		revocation_endpoint: httpsUrl(str(obj, "revocation_endpoint"), "revocation_endpoint"),
		poppy_domains: stringArray(obj.poppy_domains, "poppy_domains"),
	};
	if (obj.authorization_endpoint !== undefined) {
		meta.authorization_endpoint = httpsUrl(str(obj, "authorization_endpoint"), "authorization_endpoint");
	}
	if (obj.device_authorization_endpoint !== undefined) {
		meta.device_authorization_endpoint = httpsUrl(str(obj, "device_authorization_endpoint"), "device_authorization_endpoint");
	}
	return meta;
}

export function parseClientMetadata(input: unknown, fetchedUrl: string): ClientMetadata {
	const obj = object(input, "client metadata");
	const clientId = httpsUrl(str(obj, "client_id"), "client_id");
	if (clientId !== fetchedUrl) fail("client_id must equal the URL the document was fetched from");
	const jwks = httpsUrl(str(obj, "jwks_uri"), "jwks_uri");
	const redirects = stringArray(obj.redirect_uris, "redirect_uris").map((uri) => httpsUrl(uri, "redirect_uri"));
	const host = new URL(clientId).hostname;
	if (new URL(jwks).hostname !== host) fail("jwks_uri must be on the same domain as client_id");
	for (const uri of redirects) {
		if (new URL(uri).hostname !== host) fail("redirect_uris must be on the same domain as client_id");
	}
	const meta: ClientMetadata = { client_id: clientId, jwks_uri: jwks, redirect_uris: redirects };
	if (obj.client_name !== undefined) meta.client_name = str(obj, "client_name");
	if (obj.logo_uri !== undefined) meta.logo_uri = httpsUrl(str(obj, "logo_uri"), "logo_uri");
	if (obj.token_endpoint_auth_method !== undefined) meta.token_endpoint_auth_method = str(obj, "token_endpoint_auth_method");
	if (obj.extensions !== undefined) meta.extensions = parseExtensions(obj.extensions);
	return meta;
}

export function parseTokenResponse(input: unknown): TokenResponse {
	const obj = object(input, "token response");
	const tokenType = str(obj, "token_type");
	if (tokenType !== "DPoP" && tokenType !== "Bearer") fail("token_type must be DPoP or Bearer");
	const expires = num(obj, "expires_in");
	if (!(expires > 0)) fail("expires_in must be greater than 0");
	const response: TokenResponse = {
		access_token: str(obj, "access_token"),
		token_type: tokenType,
		expires_in: expires,
		scope: typeof obj.scope === "string" ? obj.scope : fail("scope must be a string"),
		session_id: str(obj, "session_id"),
		signed_in: bool(obj, "signed_in"),
	};
	validateScopeString(response.scope, true);
	if (obj.refresh_token !== undefined) response.refresh_token = str(obj, "refresh_token");
	if (obj.refresh_token_expires_in !== undefined) {
		const life = num(obj, "refresh_token_expires_in");
		if (!(life > 0)) fail("refresh_token_expires_in must be greater than 0");
		response.refresh_token_expires_in = life;
	}
	return response;
}

export function parseDeviceAuthorizationResponse(input: unknown): DeviceAuthorizationResponse {
	const obj = object(input, "device authorization");
	const interval = num(obj, "interval");
	const expires = num(obj, "expires_in");
	if (!(interval > 0) || !(expires > 0)) fail("device authorization times must be > 0");
	const response: DeviceAuthorizationResponse = {
		device_code: str(obj, "device_code"),
		user_code: str(obj, "user_code"),
		verification_uri: httpsUrl(str(obj, "verification_uri"), "verification_uri"),
		expires_in: expires,
		interval,
	};
	if (obj.verification_uri_complete !== undefined) {
		response.verification_uri_complete = httpsUrl(str(obj, "verification_uri_complete"), "verification_uri_complete");
	}
	return response;
}

export function parseAgentMessage(input: unknown): AgentMessage {
	const obj = object(input, "message");
	const id = str(obj, "id");
	if (!isOpaqueId(id)) fail("message id is not a URL-safe id");
	const sender = str(obj, "sender");
	if (sender !== "agent" && sender !== "human") fail("sender must be agent or human");
	const message: AgentMessage = { id, sender };
	if (obj.text !== undefined) message.text = str(obj, "text");
	if (obj.data !== undefined) message.data = record(obj.data, "data");
	if (obj.context !== undefined) message.context = parseContext(obj.context);
	if (message.text === undefined && message.data === undefined && message.context === undefined) {
		fail("a message must have text, data, or context");
	}
	return message;
}

export function parseContext(input: unknown): UserContext {
	const obj = object(input, "context");
	const context: UserContext = {};
	if (obj.locale !== undefined) {
		const locale = str(obj, "locale");
		if (!LOCALE.test(locale)) fail("locale must be an RFC 5646 language tag");
		context.locale = locale;
	}
	if (obj.time_zone !== undefined) {
		const zone = str(obj, "time_zone");
		if (!ZONE.test(zone)) fail("time_zone must be an IANA time zone name");
		context.time_zone = zone;
	}
	if (obj.user_available !== undefined) context.user_available = bool(obj, "user_available");
	for (const [key, value] of Object.entries(obj)) {
		if (key === "locale" || key === "time_zone" || key === "user_available") continue;
		context[key] = value;
	}
	return context;
}

export function parseOperation(input: unknown): Operation {
	const obj = object(input, "operation");
	const state = str(obj, "state");
	if (!["proposed", "in_progress", "succeeded", "failed", "cancelled", "expired"].includes(state)) {
		fail(`unknown operation state ${state}`);
	}
	const revision = num(obj, "revision");
	if (!Number.isInteger(revision) || revision < 1) fail("revision must be an integer >= 1");
	const operation: Operation = {
		operation_id: str(obj, "operation_id"),
		revision,
		state: state as Operation["state"],
		summary: str(obj, "summary"),
		confirmation: parseConfirmation(obj.confirmation),
		result: parseResult(obj.result),
	};
	if (obj.terms !== undefined) operation.terms = record(obj.terms, "terms");
	if (obj.expires_at !== undefined) operation.expires_at = timestamp(str(obj, "expires_at"), "expires_at");
	if (state === "proposed" && operation.expires_at === undefined) fail("proposed operations require expires_at");
	if (obj.user_approval_required !== undefined) operation.user_approval_required = bool(obj, "user_approval_required");
	if (obj.url !== undefined) operation.url = httpsUrl(str(obj, "url"), "url");
	if (["succeeded", "failed", "cancelled"].includes(state) && !operation.result?.summary) {
		fail("a final operation that changed something must include result.summary");
	}
	return operation;
}

export function parseEventsResponse(input: unknown): EventsResponse {
	const obj = object(input, "events");
	if (!Array.isArray(obj.events)) fail("events must be an array");
	return {
		conversation_id: str(obj, "conversation_id"),
		events: obj.events.map((event) => parseEvent(event)),
		cursor: str(obj, "cursor"),
		has_more: bool(obj, "has_more"),
		status: status(str(obj, "status")),
		responder: responder(str(obj, "responder")),
	};
}

export function parseEvent(input: unknown): ConversationEvent {
	const obj = object(input, "event");
	const id = str(obj, "id");
	if (!isOpaqueId(id)) fail("event id is invalid");
	const event: ConversationEvent = {
		id,
		type: str(obj, "type"),
		created_at: timestamp(str(obj, "created_at"), "created_at"),
	};
	if (obj.message !== undefined) event.message = parseCompanyMessage(obj.message);
	if (obj.status !== undefined) event.status = str(obj, "status");
	if (obj.responder !== undefined) event.responder = str(obj, "responder");
	if (obj.error !== undefined) event.error = str(obj, "error");
	if (obj.scope !== undefined) event.scope = str(obj, "scope");
	if (obj.reason !== undefined) event.reason = str(obj, "reason");
	if (obj.conversation_id !== undefined) event.conversation_id = str(obj, "conversation_id");
	if (event.type === "message" && !event.message) fail("message events require message");
	if (event.type === "state" && (!event.status || !event.responder)) fail("state events require status and responder");
	if (event.type === "authorization" && !event.error) fail("authorization events require error");
	if (event.type === "user_requested" && !event.reason) fail("user_requested events require reason");
	if ((event.type === "direct_opened" || event.type === "direct_closed") && !event.conversation_id) {
		fail(`${event.type} events require conversation_id`);
	}
	return event;
}

export function parseCompanyMessage(input: unknown): CompanyMessage {
	const obj = object(input, "company message");
	const role = str(obj, "role");
	if (role !== "user" && role !== "company") fail("role must be user or company");
	const sender = str(obj, "sender");
	if (sender !== "agent" && sender !== "human") fail("sender must be agent or human");
	const message: CompanyMessage = { id: str(obj, "id"), role, sender };
	if (!isOpaqueId(message.id)) fail("message id is invalid");
	if (obj.text !== undefined) message.text = str(obj, "text");
	if (obj.data !== undefined) message.data = record(obj.data, "data");
	if (obj.operation !== undefined) message.operation = parseOperation(obj.operation);
	return message;
}

export function parseJsonDocument(text: string): unknown {
	try {
		return parseJson(text);
	} catch (error) {
		throw new SchemaError(error instanceof Error ? error.message : "invalid JSON");
	}
}

export function majorVersion(version: string): number {
	return Number(version.split(".")[0]);
}

export function domainsMatch(requestedHost: string, documentDomain: string): boolean {
	return stripWww(requestedHost).toLowerCase() === stripWww(documentDomain).toLowerCase();
}

export function stripWww(host: string): string {
	return host.toLowerCase().startsWith("www.") ? host.slice(4) : host;
}

export function validateScopeString(scope: string, allowEmpty: boolean): string[] {
	if (scope === "") {
		if (!allowEmpty) fail("scope is required");
		return [];
	}
	const parts = scope.split(" ");
	if (parts.some((part) => part === "" || !SCOPE_TOKEN.test(part))) fail("invalid scope syntax");
	return parts;
}

export function supportedMajor(version: string, supported = 0): boolean {
	return majorVersion(version) === supported;
}

export function isKnownExtensionName(name: string): boolean {
	if (name === "operations") return true;
	return /^[a-z0-9.-]+\.[a-z]{2,}\/.+/.test(name);
}

function parseAuth(input: unknown): PoppyDocument["auth"] {
	const obj = object(input, "auth");
	const auth: NonNullable<PoppyDocument["auth"]> = { issuer: httpsUrl(str(obj, "issuer"), "auth.issuer") };
	if (obj.direct !== undefined) auth.direct = { scopes: scopeList(object(obj.direct, "direct").scopes, "direct.scopes") };
	if (obj.device !== undefined) auth.device = { scopes: scopeList(object(obj.device, "device").scopes, "device.scopes") };
	if (obj.mediated !== undefined) {
		const mediated = object(obj.mediated, "mediated");
		const fieldsRaw = mediated.fields;
		if (!Array.isArray(fieldsRaw) || fieldsRaw.length === 0) fail("mediated.fields is required");
		auth.mediated = {
			endpoint: httpsUrl(str(mediated, "endpoint"), "mediated.endpoint"),
			scopes: scopeList(mediated.scopes, "mediated.scopes"),
			fields: fieldsRaw.map((field) => {
				const item = object(field, "field");
				return { name: str(item, "name"), label: str(item, "label"), secret: bool(item, "secret") };
			}),
		};
	}
	if (obj.custom_scopes !== undefined) {
		const custom = record(obj.custom_scopes, "custom_scopes");
		const descriptions: Record<string, string> = {};
		for (const [key, value] of Object.entries(custom)) {
			if (key.startsWith("poppy:")) fail("custom scope names must not start with poppy:");
			if (typeof value !== "string") fail("custom scope descriptions must be strings");
			descriptions[key] = value;
		}
		auth.custom_scopes = descriptions;
	}
	return auth;
}

function parseProtocols(input: unknown): PoppyProtocol[] {
	const obj = object(input, "agent");
	if (!Array.isArray(obj.protocols) || obj.protocols.length === 0) fail("agent.protocols is required");
	return obj.protocols.map((entry) => {
		const item = object(entry, "protocol");
		const protocol: PoppyProtocol = {
			type: str(item, "type"),
			endpoint: httpsUrl(str(item, "endpoint"), "endpoint"),
		};
		if (item.resource !== undefined) protocol.resource = httpsUrl(str(item, "resource"), "resource");
		return protocol;
	});
}

function parseWeb(input: unknown): PoppyDocument["web"] {
	const obj = object(input, "web");
	const web: NonNullable<PoppyDocument["web"]> = {};
	if (obj.browser_session_endpoint !== undefined) {
		web.browser_session_endpoint = httpsUrl(str(obj, "browser_session_endpoint"), "browser_session_endpoint");
	}
	return web;
}

function parseApis(input: unknown): PoppyApi[] {
	if (!Array.isArray(input)) fail("apis must be an array");
	return input.map((entry) => {
		const item = object(entry, "api");
		const api: PoppyApi = {
			type: str(item, "type"),
			url: httpsUrl(str(item, "url"), "api url"),
			description: str(item, "description"),
		};
		if (item.resource !== undefined) api.resource = httpsUrl(str(item, "resource"), "resource");
		return api;
	});
}

function parseExtensions(input: unknown): Record<string, PoppyExtension> {
	const obj = record(input, "extensions");
	const extensions: Record<string, PoppyExtension> = {};
	for (const [name, value] of Object.entries(obj)) {
		const item = object(value, `extensions.${name}`);
			// Publishers MUST use "operations" or a domain prefix. Receivers still
		// parse other names so they can ignore extensions they don't implement.
		const version = str(item, "version");
		const extension: PoppyExtension = { ...item, version };
		if (item.endpoint !== undefined) extension.endpoint = httpsUrl(str(item, "endpoint"), "endpoint");
		if (item.resource !== undefined) extension.resource = httpsUrl(str(item, "resource"), "resource");
		extensions[name] = extension;
	}
	return extensions;
}

function parseConfirmation(input: unknown): Operation["confirmation"] {
	if (input === null) return null;
	const obj = object(input, "confirmation");
	const approved = str(obj, "approved_by");
	if (approved !== "user" && approved !== "standing_permission") fail("approved_by is invalid");
	return {
		revision: num(obj, "revision"),
		approved_by: approved,
		confirmed_at: timestamp(str(obj, "confirmed_at"), "confirmed_at"),
	};
}

function parseResult(input: unknown): Operation["result"] {
	if (input === null) return null;
	const obj = object(input, "result");
	const result: NonNullable<Operation["result"]> = { summary: str(obj, "summary") };
	if (obj.data !== undefined) result.data = record(obj.data, "result.data");
	return result;
}

function scopeList(input: unknown, label: string): string[] {
	const values = stringArray(input, label);
	for (const value of values) validateScopeString(value, false);
	return values;
}

function status(value: string): ConversationStatus {
	if (value !== "working" && value !== "idle" && value !== "queued" && value !== "closed") fail(`unknown status ${value}`);
	return value;
}

function responder(value: string): Responder {
	if (value !== "agent" && value !== "human") fail(`unknown responder ${value}`);
	return value;
}

function object(input: unknown, label: string): Record<string, unknown> {
	if (!input || typeof input !== "object" || Array.isArray(input)) fail(`${label} must be an object`);
	return input as Record<string, unknown>;
}

function record(input: unknown, label: string): Record<string, unknown> {
	return object(input, label);
}

function str(obj: Record<string, unknown>, key: string): string {
	const value = obj[key];
	if (typeof value !== "string" || value.length === 0) fail(`${key} must be a non-empty string`);
	return value;
}

function num(obj: Record<string, unknown>, key: string): number {
	const value = obj[key];
	if (typeof value !== "number" || !Number.isFinite(value)) fail(`${key} must be a number`);
	return value;
}

function bool(obj: Record<string, unknown>, key: string): boolean {
	const value = obj[key];
	if (typeof value !== "boolean") fail(`${key} must be a boolean`);
	return value;
}

function stringArray(input: unknown, label: string): string[] {
	if (!Array.isArray(input) || input.some((item) => typeof item !== "string")) fail(`${label} must be an array of strings`);
	return input as string[];
}

function httpsUrl(value: string, label: string): string {
	if (!HTTPS.test(value)) fail(`${label} must be an HTTPS URL`);
	try {
		const url = new URL(value);
		if (url.protocol !== "https:") fail(`${label} must be HTTPS`);
		if (url.username || url.password) fail(`${label} must not contain credentials`);
		return value;
	} catch {
		fail(`${label} must be an HTTPS URL`);
	}
}

function timestamp(value: string, label: string): string {
	if (!RFC3339.test(value) || Number.isNaN(Date.parse(value))) fail(`${label} must be RFC 3339`);
	return value;
}

function fail(message: string): never {
	throw new SchemaError(message);
}
