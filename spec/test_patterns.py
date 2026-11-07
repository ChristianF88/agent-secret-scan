#!/usr/bin/env python3
"""Check detection-patterns.yaml: YAML validity, Rust-regex compatibility hints,
and each regex rule's positive/negative examples (with value/name filters)."""
import re, sys, yaml

import os
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detection-patterns.yaml")
doc = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
vf = doc["value_filters"]
refs = [re.compile(p) for p in vf["references"]]
placeholders = {p.lower() for p in vf["placeholders"]}
name_excl = [re.compile(p) for p in doc["credential_names"]["name_exclusions"]]
# Constructs the Rust regex crate does not support.
UNSUPPORTED = re.compile(r"\(\?[=!]|\(\?<[=!]|\\[1-9]|\(\?>|[*+?}]\+")


def clean(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v.strip()


def kept(m):
    """Return the first secret that survives filters, else None."""
    gd = m.groupdict()
    name = gd.get("name") or gd.get("name2")
    if name and any(p.search(name) for p in name_excl):
        return None
    for k, v in gd.items():
        if not k.startswith("secret") or not v:
            continue
        s = clean(v)
        if not s or s.lower() in placeholders or any(r.search(s) for r in refs):
            continue
        return s
    return None


def complex_enough(v):
    return bool(re.search(r"\d|[^A-Za-z0-9]", v) or (re.search("[a-z]", v) and re.search("[A-Z]", v)))


def hits(rx, text, cx=False, trim=False):
    out = []
    for m in rx.finditer(text):
        s = kept(m)
        if s and trim:
            s = s.rstrip(".,;:)")
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
        h = hits(rx, t, rule.get("require_complexity", False), rule.get("postprocess") == "trim_trailing_punctuation")
        if not h:
            print(f"MISS  {rid}: {t!r}"); fails += 1
    for t in rule.get("neg") or []:
        total += 1
        h = hits(rx, t, rule.get("require_complexity", False), rule.get("postprocess") == "trim_trailing_punctuation")
        if h:
            print(f"FP    {rid}: {t!r} -> {h}"); fails += 1

for ff in doc["file_formats"]:
    if "regex" in ff:
        re.compile(ff["regex"])
print(f"rules={len(doc['regex_rules'])} cli_tools={len(doc['cli_tools'])} "
      f"examples={total} failures={fails}")
sys.exit(1 if fails else 0)
