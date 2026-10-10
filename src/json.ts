/**
 * JSON.parse that rejects duplicate member names (guides: transport and JSON).
 * Trailing commas and comments are rejected by JSON.parse itself.
 */
export function parseJson(text: string): unknown {
	const parsed = JSON.parse(text) as unknown;
	assertNoDuplicateKeys(text);
	return parsed;
}

export function assertNoDuplicateKeys(text: string): void {
	const scanner = new Scanner(text);
	scanner.skipWs();
	scanner.value();
	scanner.skipWs();
	if (!scanner.eof()) throw new Error("trailing data after JSON");
}

class Scanner {
	private i = 0;
	private readonly text: string;
	constructor(text: string) {
		this.text = text;
	}

	eof(): boolean {
		return this.i >= this.text.length;
	}

	skipWs(): void {
		while (this.i < this.text.length && /\s/.test(this.text[this.i]!)) this.i++;
	}

	value(): void {
		this.skipWs();
		const c = this.text[this.i];
		if (c === "{") this.object();
		else if (c === "[") this.array();
		else if (c === '"') this.string();
		else if (c === "t") this.literal("true");
		else if (c === "f") this.literal("false");
		else if (c === "n") this.literal("null");
		else if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) this.number();
		else throw new Error("invalid JSON");
	}

	private object(): void {
		this.expect("{");
		this.skipWs();
		const seen = new Set<string>();
		if (this.peek() === "}") {
			this.i++;
			return;
		}
		for (;;) {
			this.skipWs();
			const key = this.string();
			if (seen.has(key)) throw new Error(`duplicate JSON member "${key}"`);
			seen.add(key);
			this.skipWs();
			this.expect(":");
			this.value();
			this.skipWs();
			if (this.peek() === ",") {
				this.i++;
				continue;
			}
			this.expect("}");
			return;
		}
	}

	private array(): void {
		this.expect("[");
		this.skipWs();
		if (this.peek() === "]") {
			this.i++;
			return;
		}
		for (;;) {
			this.value();
			this.skipWs();
			if (this.peek() === ",") {
				this.i++;
				continue;
			}
			this.expect("]");
			return;
		}
	}

	private string(): string {
		this.expect('"');
		let out = "";
		while (this.i < this.text.length) {
			const c = this.text[this.i]!;
			if (c === '"') {
				this.i++;
				return out;
			}
			if (c === "\\") {
				this.i++;
				const e = this.text[this.i++];
				if (e === "u") {
					const hex = this.text.slice(this.i, this.i + 4);
					if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error("bad unicode escape");
					out += String.fromCharCode(Number.parseInt(hex, 16));
					this.i += 4;
				} else if (e === '"' || e === "\\" || e === "/") out += e;
				else if (e === "b") out += "\b";
				else if (e === "f") out += "\f";
				else if (e === "n") out += "\n";
				else if (e === "r") out += "\r";
				else if (e === "t") out += "\t";
				else throw new Error("bad escape");
			} else {
				if (c < " ") throw new Error("raw control character in string");
				out += c;
				this.i++;
			}
		}
		throw new Error("unterminated string");
	}

	private number(): void {
		const start = this.i;
		if (this.peek() === "-") this.i++;
		if (this.peek() === "0") this.i++;
		else if (this.peek() !== undefined && this.peek()! >= "1" && this.peek()! <= "9") {
			while (this.peek() !== undefined && this.peek()! >= "0" && this.peek()! <= "9") this.i++;
		} else throw new Error("invalid number");
		if (this.peek() === ".") {
			this.i++;
			if (!this.digit()) throw new Error("invalid number");
			while (this.digit()) this.i++;
		}
		if (this.peek() === "e" || this.peek() === "E") {
			this.i++;
			if (this.peek() === "+" || this.peek() === "-") this.i++;
			if (!this.digit()) throw new Error("invalid number");
			while (this.digit()) this.i++;
		}
		if (this.i === start) throw new Error("invalid number");
	}

	private digit(): boolean {
		const c = this.peek();
		return c !== undefined && c >= "0" && c <= "9";
	}

	private literal(word: string): void {
		if (this.text.slice(this.i, this.i + word.length) !== word) throw new Error("invalid JSON");
		this.i += word.length;
	}

	private expect(c: string): void {
		if (this.text[this.i] !== c) throw new Error(`expected ${c}`);
		this.i++;
	}

	private peek(): string | undefined {
		return this.text[this.i];
	}
}
