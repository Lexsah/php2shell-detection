#!/usr/bin/env python3
"""Minimal Sigma evaluator for the webserver rules in this repo (field|contains / |endswith / equals,
lists = OR, 'all of selection_*' / single selection). Parses combined-format access logs.
Usage: sigma_eval.py <rule.yml> <access.log>   -> prints match count, exit 0 if >=1 match."""
import re, sys, fnmatch, yaml

LOG = re.compile(r'(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]+)" '
                 r'(?P<status>\d{3}) \S+ "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')

def fields(line):
    m = LOG.match(line)
    if not m: return None
    uri = m["uri"]
    return {"cs-method": m["method"], "c-uri": uri,
            "c-uri-query": uri.split("?", 1)[1] if "?" in uri else "",
            "cs-user-agent": m["ua"], "sc-status": m["status"], "cs-referrer": m["ref"]}

def match_item(ev, key, val):
    name, *mods = key.split("|")
    data = str(ev.get(name, ""))
    vals = val if isinstance(val, list) else [val]
    for v in vals:
        v = str(v)
        if "contains" in mods and v.lower() in data.lower(): return True
        if "endswith" in mods and data.lower().endswith(v.lower()): return True
        if "startswith" in mods and data.lower().startswith(v.lower()): return True
        if not mods and fnmatch.fnmatch(data.lower(), v.lower()): return True
    return False

def match_sel(ev, sel):
    if isinstance(sel, list):  # list of maps = OR
        return any(match_sel(ev, s) for s in sel)
    return all(match_item(ev, k, v) for k, v in sel.items())

def evaluate(rule, ev):
    det = rule["detection"]; cond = det["condition"].strip()
    sels = {k: v for k, v in det.items() if k != "condition"}
    m = re.fullmatch(r"all of (\w+)\*", cond)
    if m: return all(match_sel(ev, v) for k, v in sels.items() if k.startswith(m.group(1)))
    if cond in sels: return match_sel(ev, sels[cond])
    raise SystemExit(f"unsupported condition: {cond}")

rule = yaml.safe_load(open(sys.argv[1]))
hits = 0
for line in open(sys.argv[2]):
    ev = fields(line.strip())
    if ev and evaluate(rule, ev): hits += 1
print(hits)
sys.exit(0 if hits else 1)
