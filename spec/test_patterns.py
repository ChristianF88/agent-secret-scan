#!/usr/bin/env python3
r"""Check detection-patterns.yaml: YAML validity, Rust-regex compatibility hints,
and each regex rule's positive/negative examples (with value/name filters).

This is a quick authoring aid. The authority is the Rust engine: `cargo test`
runs every example through the real prefilter, regex crate and filters.
Python `re` differs from it in edge cases (`\s` on \x1c-\x1f, `\w` on some
Unicode marks, case folding of the dotless i)."""
import base64, json, re, sys, yaml

import os
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detection-patterns.yaml")
doc = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
vf = doc["value_filters"]
refs = [re.compile(p) for p in vf["references"]]
placeholders = {p.lower() for p in vf["placeholders"]}
ph_patterns = [re.compile(p) for p in vf["placeholder_patterns"]]
defaults = set(vf["defaults"])
name_excl = [re.compile(p) for p in doc["credential_names"]["name_exclusions"]]
# Constructs the Rust regex crate does not support.
UNSUPPORTED = re.compile(r"\(\?[=!]|\(\?<[=!]|\\[1-9]|\(\?>|[*+?}]\+")


def clean(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v.strip()


password_names = [re.compile(p) for p in doc["credential_names"]["password_names"]]
NOT_PASSWORD_CATEGORIES = {"password_hash", "http", "auth_artifact", "config_key", "connection_string", "credential_file"}


def filtered(s, password=False):
    """References always; placeholders only for non-passwords (passwords have no shape)."""
    if not s:
        return False
    if any(r.search(s) for r in refs):
        return True
    if password or s in defaults:   # known defaults are reported as default_credential
        return False
    return s.lower() in placeholders or any(r.search(s) for r in ph_patterns)


def filtered_shape(s, password=False):
    """Mirror of analyzers::filter::filtered_shape: the value, the value
    without trailing , ;, and the value after an auth scheme."""
    if filtered(s, password):
        return True
    t = clean(s.rstrip(",;"))
    if t != s and filtered(t, password):
        return True
    scheme, _, rest = t.partition(" ")
    return bool(rest) and scheme.lower() in ("bearer", "basic", "token") and filtered(clean(rest), password)


BIP39 = set(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "spec", "data",
                              "bip39-english.txt")).read().split())


def bip39_mnemonic(v):
    """Mirror of spec::postprocess::bip39_mnemonic: longest 12/15/18/21/24-word list prefix."""
    words = v.split()
    n = 0
    while n < min(len(words), 24) and words[n].lower() in BIP39:
        n += 1
    for k in (24, 21, 18, 15, 12):
        if k <= n:
            return " ".join(words[:k])
    return None


def b64url_json(part):
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except ValueError:
        return None


def jwt_ok(v):
    """Mirror of spec::postprocess::jwt_claims: header and payload are JSON objects, header has alg."""
    parts = v.split(".")
    if len(parts) != 3:
        return False
    h, p = b64url_json(parts[0]), b64url_json(parts[1])
    return isinstance(h, dict) and isinstance(h.get("alg"), str) and isinstance(p, dict)


def postprocess(pp, s):
    if pp == "trim_trailing_punctuation":
        return s.rstrip(".,;:)")
    if pp == "bip39_wordlist_check":
        return bip39_mnemonic(s)
    if pp == "jwt_decode_check_exp":
        return s if jwt_ok(s) else None
    return s


SHAPE_CHECKED = {"bip39_wordlist_check", "jwt_decode_check_exp"}


def kept(m, category=None, shape_checked=False, kind=None):
    """Return the first secret that survives filters, else None. `kind` is
    the rule's explicit kind (overrides the category default)."""
    gd = m.groupdict()
    name = gd.get("name") or gd.get("name2")
    if name and any(p.search(name) for p in name_excl):
        return None
    if name:
        password = any(p.search(name) for p in password_names)
    elif kind:
        password = kind in ("password", "passphrase")
    else:
        password = category not in NOT_PASSWORD_CATEGORIES
    # Validated structures (mnemonic, JWT) skip the shape-based placeholder filters.
    password = password or shape_checked
    for k, v in gd.items():
        if not k.startswith("secret") or not v:
            continue
        s = clean(v)
        if not s or filtered_shape(s, password):
            continue
        return s
    return None


def complex_enough(v):
    return bool(re.search(r"\d|[^A-Za-z0-9]", v) or (re.search("[a-z]", v) and re.search("[A-Z]", v)))


def hits(rx, text, cx=False, pp=None, category=None, kind=None):
    out = []
    for m in rx.finditer(text):
        s = kept(m, category, pp in SHAPE_CHECKED, kind)
        if s:
            s = postprocess(pp, s)
        if s and (not cx or complex_enough(s)):
            out.append(s)
    return out


fails, total = 0, 0
for rule in doc["regex_rules"]:
    rid = rule["id"]
    if UNSUPPORTED.search(rule["regex"]):
        print(f"UNSUPPORTED-SYNTAX {rid}"); fails += 1
    try:
        rx = re.compile(rule["regex"])
    except re.error as e:
        print(f"COMPILE-FAIL {rid}: {e}"); fails += 1; continue
    for alt in ("alt_regex",):
        if alt in rule:
            re.compile(rule[alt])
    # Unquoted `x:` inside [...] parses as a mapping, not a string.
    if not all(isinstance(k, str) for k in rule["keywords"]):
        print(f"KEYWORD-NOT-STRING {rid}: {rule['keywords']!r}"); fails += 1
    kws = [k.lower() for k in rule["keywords"] if isinstance(k, str)]
    for t in rule.get("pos") or []:
        total += 1
        # The scanner only runs a rule where the prefilter found a keyword.
        if not any(k in t.lower() for k in kws):
            print(f"NO-KEYWORD {rid}: {t!r}"); fails += 1
        h = hits(rx, t, rule.get("require_complexity", False), rule.get("postprocess"), rule.get("category"), rule.get("kind"))
        if not h:
            print(f"MISS  {rid}: {t!r}"); fails += 1
    for t in rule.get("neg") or []:
        total += 1
        h = hits(rx, t, rule.get("require_complexity", False), rule.get("postprocess"), rule.get("category"), rule.get("kind"))
        if h:
            print(f"FP    {rid}: {t!r} -> {h}"); fails += 1

# Typed shell/CLI fields: unknown values fail (the Rust loader rejects them too).
sem = doc["shell_semantics"]
ENUMS = [
    ("shell_semantics.stdin_sinks[].payload", [s.get("payload", "secret") for s in sem["stdin_sinks"]],
     {"secret", "token", "userpass", "sql"}),
    ("shell_semantics.stdin_sources[].payload", [s.get("payload") for s in sem["stdin_sources"]],
     {"args", "printf", "stdin"}),
    ("shell_semantics.value_flags[].unlisted", [v.get("unlisted", "boolean") for v in sem["value_flags"]],
     {"boolean", "value"}),
    ("cli_tools[].args[].names", [a.get("names", "credential") for t in doc["cli_tools"] for a in t.get("args") or []],
     {"credential", "any"}),
]
for field, values, allowed in ENUMS:
    for v in values:
        if v not in allowed:
            print(f"BAD-VALUE {field}: {v!r} (allowed: {sorted(allowed)})"); fails += 1
for v in sem["value_flags"]:
    for f in v.get("value", []) + v.get("boolean", []):
        if not isinstance(f, str) or not f.startswith("-"):
            print(f"BAD-FLAG shell_semantics.value_flags {v['cmd']}: {f!r}"); fails += 1
for t in doc["cli_tools"]:
    for a in t.get("args") or []:
        if "names" in a and not str(a.get("kind", "")).startswith("keyvalue"):
            print(f"NAMES-WITHOUT-KEYVALUE cli_tools.{t['tool']}: {a!r}"); fails += 1

for ff in doc["file_formats"]:
    if "regex" in ff:
        re.compile(ff["regex"])
print(f"rules={len(doc['regex_rules'])} cli_tools={len(doc['cli_tools'])} "
      f"examples={total} failures={fails}")
sys.exit(1 if fails else 0)
