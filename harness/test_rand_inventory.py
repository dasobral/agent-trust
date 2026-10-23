"""Static randomness inventory for the adapter seam (docs/adapter-contract.md section 8).

Section 8 requires every adapter and client key to come from the configured
``OpenMlsRand`` (C-6). The adapter MUST NOT call ``SignatureKeyPair::new`` (OsRng) or
the provider's ``signature_key_gen`` (an internal ChaCha20 RNG), and it must not reach
any other hidden randomness source. This module scans the seam's Rust sources for
those constructors. Comments, doc comments and string literals that merely mention a
name are ignored; only code is checked.

This is a static check of call sites, not a proof: randomness reached through a type
alias, a re-export or ``Default::default()`` type inference is not detected here, and
HPKE encapsulation randomness is a documented limitation (section 8, D-5).

Standard library only. It reads source files as text and imports no production module.

Run from the repository root with: python3 -m unittest harness.test_rand_inventory -v
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The entropy seam: the trusted adapter, the client endpoint and the wire encodings.
SCANNED = ("src/adapter.rs", "src/client.rs", "src/wire.rs")

# Explicitly NOT scanned. src/mls.rs is the legacy MLS laboratory from before the
# adapter (Task 3). It sits outside the entropy seam, uses OpenMlsRustCrypto and
# SignatureKeyPair::new by design, and no adapter path calls it. Section 8 makes no
# claim about it.
EXCLUDED = {"src/mls.rs": "legacy MLS lab outside the entropy seam (section 8)"}

# Forbidden hidden-randomness constructors, matched against code only.
FORBIDDEN = {
    "SignatureKeyPair::new": re.compile(r"\bSignatureKeyPair\s*::\s*new\b"),
    "signature_key_gen": re.compile(r"\bsignature_key_gen\b"),
    "OsRng": re.compile(r"\bOsRng\b"),
    "thread_rng": re.compile(r"\bthread_rng\b"),
    "getrandom": re.compile(r"\bgetrandom\b"),
    "rand::random": re.compile(r"\brand\s*::\s*random\b"),
    "OpenMlsRustCrypto::default": re.compile(r"\bOpenMlsRustCrypto\s*::\s*default\b"),
    "RustCrypto::default": re.compile(r"(?<![A-Za-z0-9_])RustCrypto\s*::\s*default\b"),
}

_IDENT = re.compile(r"[A-Za-z0-9_]")
_RAW_STRING = re.compile(r'b?r(#*)"')


def strip_non_code(source: str) -> str:
    """Returns ``source`` with every comment and string or char literal blanked.

    Line comments (``//``, ``///``, ``//!``), nested block comments, string, byte
    string and raw string literals, and char literals become spaces. Newlines are
    kept, so line numbers stay valid. Lifetimes (``'a``) are code and are kept.
    """
    out: list[str] = []
    i, n = 0, len(source)

    def blank(text: str) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in text)

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        prev = source[i - 1] if i > 0 else ""

        # Line comment, including doc comments.
        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            end = n if end < 0 else end
            out.append(blank(source[i:end]))
            i = end
            continue

        # Block comment, nested.
        if ch == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif source.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(blank(source[i:j]))
            i = j
            continue

        # Raw strings: r"..", r#".."#, br#".."#.
        if not _IDENT.match(prev):
            raw = _RAW_STRING.match(source, i)
            if raw:
                close = '"' + raw.group(1)
                end = source.find(close, raw.end())
                end = n if end < 0 else end + len(close)
                out.append(blank(source[i:end]))
                i = end
                continue

        # Ordinary and byte strings with escapes.
        if ch == '"' or (ch == "b" and nxt == '"' and not _IDENT.match(prev)):
            j = i + (2 if ch == "b" else 1)
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            out.append(blank(source[i:j + 1]))
            i = j + 1
            continue

        # Char literals ('a', '\n', '\u{..}'); a lone quote is a lifetime.
        if ch == "'":
            if nxt == "\\":
                end = source.find("'", i + 3)
                if end > 0:
                    out.append(blank(source[i:end + 1]))
                    i = end + 1
                    continue
            elif i + 2 < n and source[i + 2] == "'":
                out.append(blank(source[i:i + 3]))
                i += 3
                continue

        out.append(ch)
        i += 1
    return "".join(out)


def findings(source: str) -> list[tuple[int, str]]:
    """Every ``(line number, forbidden name)`` that occurs in code."""
    found = []
    for number, line in enumerate(strip_non_code(source).splitlines(), start=1):
        for name, pattern in FORBIDDEN.items():
            if pattern.search(line):
                found.append((number, name))
    return found


class RandInventoryTests(unittest.TestCase):
    def test_adapter_never_calls_hidden_randomness_constructors(self):
        self.assertTrue(set(SCANNED).isdisjoint(EXCLUDED))
        for relative in SCANNED:
            path = REPO_ROOT / relative
            with self.subTest(file=relative):
                # A missing file must fail, never pass vacuously.
                self.assertTrue(path.is_file(), f"{relative} is missing")
                source = path.read_text(encoding="utf-8")
                self.assertTrue(source.strip(), f"{relative} is empty")
                self.assertEqual(
                    findings(source), [],
                    f"{relative} calls a hidden randomness constructor (section 8)",
                )

    def test_scanner_flags_offending_lines_and_ignores_comments(self):
        source = "\n".join([
            "/// Never `SignatureKeyPair::new` or the provider's `signature_key_gen`.",
            "//! Mentions OsRng, thread_rng, getrandom and rand::random in a doc.",
            "fn ok(seed: &[u8; 32]) -> SignatureKeyPair {",
            "    // SignatureKeyPair::new(SignatureScheme::ED25519) is forbidden here",
            "    /* RustCrypto::default() /* nested OsRng */ still a comment */",
            '    let note = "OpenMlsRustCrypto::default() in a string";',
            '    let raw = r#"thread_rng() in a "raw" string"#;',
            "    let c = '\"'; let d = '\\''; fn lt<'a>(x: &'a str) -> &'a str { x }",
            "    use openmls_traits::random::OpenMlsRand;",
            "    SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), pk)",
            "}",
            "fn offending() {",
            "    let kp = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();",
            "    let (sk, pk) = crypto.signature_key_gen(scheme)?; // signature_key_gen",
            "    let mut rng = rand::rngs::OsRng;",
            "    let mut t = rand::thread_rng();",
            "    getrandom::getrandom(&mut buf)?;",
            "    let x: u64 = rand::random();",
            "    let p = OpenMlsRustCrypto::default();",
            "    let q = RustCrypto :: default();",
            "}",
        ])
        self.assertEqual(findings(source), [
            (13, "SignatureKeyPair::new"),
            (14, "signature_key_gen"),
            (15, "OsRng"),
            (16, "thread_rng"),
            (17, "getrandom"),
            (18, "rand::random"),
            (19, "OpenMlsRustCrypto::default"),
            (20, "RustCrypto::default"),
        ])

    def test_each_forbidden_constructor_is_flagged_alone(self):
        calls = {
            "SignatureKeyPair::new": "SignatureKeyPair::new(scheme)",
            "signature_key_gen": "provider.crypto().signature_key_gen(scheme)",
            "OsRng": "OsRng.fill_bytes(&mut seed)",
            "thread_rng": "thread_rng().gen()",
            "getrandom": "getrandom(&mut seed)",
            "rand::random": "rand::random::<[u8; 32]>()",
            "OpenMlsRustCrypto::default": "OpenMlsRustCrypto::default()",
            "RustCrypto::default": "RustCrypto::default()",
        }
        self.assertEqual(set(calls), set(FORBIDDEN))
        for name, call in calls.items():
            with self.subTest(name=name):
                self.assertEqual(findings(f"let x = {call};"), [(1, name)])
                self.assertEqual(findings(f"// let x = {call};"), [])
                self.assertEqual(findings(f'let s = "{call}";'), [])

    def test_legacy_lab_is_excluded_explicitly(self):
        self.assertIn("src/mls.rs", EXCLUDED)
        self.assertNotIn("src/mls.rs", SCANNED)


if __name__ == "__main__":
    unittest.main()
