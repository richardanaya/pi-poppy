import { decimalLte } from "./codec.ts";
import type { Operation } from "./schema.ts";

export interface StandingPermission {
	id: string;
	issuer: string;
	/** Account the permission applies to, when the agent knows it. */
	accountId?: string;
	action: string;
	currency?: string;
	maxAmount?: string;
	maxUses?: number;
	uses: number;
	reserved: number;
	expiresAt?: string;
}

export interface UserApproval {
	approvedBy: "user";
	companyName: string;
	summary: string;
}

export interface StandingApproval {
	approvedBy: "standing_permission";
	permissionId: string;
}

export type Approval = UserApproval | StandingApproval;

/**
 * Build a user approval only from the company's own summary and name.
 * Conversation text is not an input: the caller has to pass the operation summary.
 */
export function userApproval(input: {
	accepted: boolean;
	companyName: string;
	summary: string;
	operation: Operation;
}): UserApproval {
	if (!input.accepted) throw new Error("user did not approve this revision");
	if (!input.companyName) throw new Error("company name is required");
	if (input.summary !== input.operation.summary) {
		throw new Error("approval must show the company's summary, not a paraphrase");
	}
	return { approvedBy: "user", companyName: input.companyName, summary: input.summary };
}

export function standingCovers(
	permission: StandingPermission,
	operation: Operation,
	issuer: string,
	nowMs = Date.now(),
): { ok: true } | { ok: false; reason: string } {
	if (operation.user_approval_required) return { ok: false, reason: "user_approval_required" };
	if (permission.issuer !== issuer) return { ok: false, reason: "company mismatch" };
	if (permission.expiresAt && Date.parse(permission.expiresAt) <= nowMs) return { ok: false, reason: "permission expired" };
	const terms = operation.terms;
	if (!terms || typeof terms.action !== "string") {
		return { ok: false, reason: "terms.action is missing; ask the user" };
	}
	if (terms.action !== permission.action) return { ok: false, reason: "action mismatch" };
	if (permission.maxUses !== undefined && permission.uses + permission.reserved >= permission.maxUses) {
		return { ok: false, reason: "no uses left" };
	}
	const price = terms.price_difference;
	if (price && typeof price === "object") {
		const amount = (price as { amount?: unknown }).amount;
		const currency = (price as { currency?: unknown }).currency;
		if (typeof amount !== "string" || typeof currency !== "string") {
			return { ok: false, reason: "price terms are incomplete; ask the user" };
		}
		if (!permission.maxAmount || !permission.currency) return { ok: false, reason: "permission has no amount limit" };
		if (permission.currency !== currency) return { ok: false, reason: "currency mismatch" };
		if (!decimalLte(amount, permission.maxAmount)) return { ok: false, reason: "amount exceeds the permission" };
	}
	return { ok: true };
}

export function reserveUse(permission: StandingPermission): void {
	if (permission.maxUses !== undefined && permission.uses + permission.reserved >= permission.maxUses) {
		throw new Error("no uses left to reserve");
	}
	permission.reserved += 1;
}

export function commitUse(permission: StandingPermission): void {
	if (permission.reserved <= 0) throw new Error("no reservation to commit");
	permission.reserved -= 1;
	permission.uses += 1;
}

export function releaseUse(permission: StandingPermission): void {
	if (permission.reserved <= 0) return;
	permission.reserved -= 1;
}
