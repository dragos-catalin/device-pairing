import { blake3 } from "@noble/hashes/blake3.js";

/**
 * TypeScript side of device-pairing: the human-facing parts that a web or
 * React Native UI needs without the Rust core. Byte-for-byte compatible with
 * the crate (shared test vectors in test/vectors.json).
 */

export const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ";
export const CODE_LEN = 8;
export const SAS_DIGITS = 6;

const CODE_CONTEXT = "device-pairing 2026 code v1";
const SAS_DOMAIN = new TextEncoder().encode("device-pairing-sas-v1");

/** Upper-case and drop spaces/dashes, so "abcd-efgh" equals "ABCDEFGH". */
export function normaliseCode(input: string): string {
    return input.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}

/** Group a code for display: "ABCD-EFGH". */
export function formatCode(code: string): string {
    const n = normaliseCode(code);
    return n.length === CODE_LEN ? `${n.slice(0, 4)}-${n.slice(4)}` : n;
}

/** True when the input has the right length and only alphabet characters. */
export function isWellFormedCode(input: string): boolean {
    const n = normaliseCode(input);
    return n.length === CODE_LEN && [...n].every((c) => CODE_ALPHABET.includes(c));
}

/** The code derived from a window's 16-byte token (same as the crate). */
export function shortCodeFromToken(token: Uint8Array): string {
    if (token.length !== 16) throw new Error("token must be 16 bytes");
    const key = blake3(token, { context: new TextEncoder().encode(CODE_CONTEXT) });
    const digest = blake3(key);
    let out = "";
    for (let i = 0; i < CODE_LEN; i++) out += CODE_ALPHABET[digest[i]! % CODE_ALPHABET.length];
    return out;
}

function compare(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
    return 0;
}

/** Six-digit SAS over (nonce, sorted ids), identical to the crate's `sas_digits`. */
export function sasDigits(nonce: Uint8Array, idA: Uint8Array, idB: Uint8Array): string {
    if (nonce.length !== 16 || idA.length !== 32 || idB.length !== 32) throw new Error("nonce 16 bytes, ids 32 bytes");
    const [lo, hi] = compare(idA, idB) <= 0 ? [idA, idB] : [idB, idA];
    const buf = new Uint8Array(SAS_DOMAIN.length + 16 + 64);
    buf.set(SAS_DOMAIN, 0);
    buf.set(nonce, SAS_DOMAIN.length);
    buf.set(lo, SAS_DOMAIN.length + 16);
    buf.set(hi, SAS_DOMAIN.length + 48);
    const out = blake3(buf);
    const n = new DataView(out.buffer, out.byteOffset, 8).getBigUint64(0, true);
    return (n % 10n ** BigInt(SAS_DIGITS)).toString().padStart(SAS_DIGITS, "0");
}
