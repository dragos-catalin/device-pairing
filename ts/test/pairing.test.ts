import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
    CODE_ALPHABET,
    formatCode,
    isWellFormedCode,
    normaliseCode,
    sasDigits,
    shortCodeFromToken,
} from "../src/index.ts";

const vectors = JSON.parse(readFileSync(resolve(import.meta.dirname, "vectors.json"), "utf8")) as {
    code: { token: string; code: string }[];
    sas: { nonce: string; a: string; b: string; sas: string }[];
};
const hex = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));

describe("matches the Rust crate byte for byte", () => {
    it.each(vectors.code)("code for token $token", ({ token, code }) => {
        expect(shortCodeFromToken(hex(token))).toBe(code);
    });
    it.each(vectors.sas)("sas for nonce $nonce", ({ nonce, a, b, sas }) => {
        expect(sasDigits(hex(nonce), hex(a), hex(b))).toBe(sas);
        expect(sasDigits(hex(nonce), hex(b), hex(a))).toBe(sas);
    });
});

describe("code helpers", () => {
    it("normalises, formats and validates", () => {
        expect(normaliseCode("ab-cd ef gh")).toBe("ABCDEFGH");
        expect(formatCode("abcdefgh")).toBe("ABCD-EFGH");
        expect(isWellFormedCode("2345-6789")).toBe(true);
        expect(isWellFormedCode("ABCD-EFG")).toBe(false);
        expect(isWellFormedCode("ABCD-EFG1")).toBe(false); // 1 is not in the alphabet
        expect(CODE_ALPHABET).not.toMatch(/[01ILOU]/);
    });
    it("rejects wrong input sizes", () => {
        expect(() => shortCodeFromToken(new Uint8Array(15))).toThrow();
        expect(() => sasDigits(new Uint8Array(16), new Uint8Array(31), new Uint8Array(32))).toThrow();
    });
});
