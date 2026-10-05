//! Shared test vectors for the TypeScript package (ts/test/vectors.json).
//! The test fails when the file and the Rust output disagree, so a change to
//! derivation in either language breaks the build.
#![allow(missing_docs)]

use device_pairing::{sas_digits, short_code_from_token};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn vectors() -> String {
    let mut out = String::from("{\n  \"code\": [\n");
    let codes: Vec<String> = (0u8..4)
        .map(|i| {
            let token: [u8; 16] = std::array::from_fn(|j| {
                i.wrapping_mul(31)
                    .wrapping_add(u8::try_from(j).unwrap_or(0))
            });
            format!(
                "    {{ \"token\": \"{}\", \"code\": \"{}\" }}",
                hex(&token),
                short_code_from_token(&token)
            )
        })
        .collect();
    out.push_str(&codes.join(",\n"));
    out.push_str("\n  ],\n  \"sas\": [\n");
    let sas: Vec<String> = (0u8..4)
        .map(|i| {
            let nonce = [i; 16];
            let a: [u8; 32] = std::array::from_fn(|j| u8::try_from(j).unwrap_or(0) ^ i);
            let b: [u8; 32] = std::array::from_fn(|j| 255 - u8::try_from(j).unwrap_or(0));
            format!(
                "    {{ \"nonce\": \"{}\", \"a\": \"{}\", \"b\": \"{}\", \"sas\": \"{}\" }}",
                hex(&nonce),
                hex(&a),
                hex(&b),
                sas_digits(&nonce, &a, &b)
            )
        })
        .collect();
    out.push_str(&sas.join(",\n"));
    out.push_str("\n  ]\n}\n");
    out
}

#[test]
fn ts_vectors_match_rust() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/ts/test/vectors.json");
    let want = vectors();
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::write(path, &want).expect("write vectors");
    }
    let have = std::fs::read_to_string(path)
        .expect("ts/test/vectors.json exists (run with UPDATE_VECTORS=1)");
    // Compare parsed JSON: a formatter in ts/ may re-wrap the file.
    let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).expect("valid json");
    assert_eq!(parse(&have), parse(&want));
}
