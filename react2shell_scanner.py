#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# react2shell_scanner.py -- triage scanner for CVE-2025-55182 (React2Shell)
# and its Next.js downstream CVE-2025-66478.
#
# Copyright (c) 2026 Vineeth Kumar, Foxcorn Lab
# SPDX-License-Identifier: MIT
#
# Modes:
#   audit    - inspect a local project (package.json / package-lock.json /
#              node_modules) for vulnerable react-server-dom-* and next
#              versions. Most reliable signal.
#   scan     - fingerprint a remote host for Next.js, try to read an exposed
#              framework version, verdict against the fixed matrix.
#   logcheck - hunt web access logs for React2Shell exploitation indicators.
#
# Detection only. No payloads are ever sent.

import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

VERSION = "1.0.0"

# --- Vulnerable version matrix (React advisory + Next.js security releases) ---
# react-server-dom-{webpack,parcel,turbopack}: exact vulnerable releases
RSC_VULN = {"19.0.0", "19.1.0", "19.1.1", "19.2.0"}
RSC_FIXED = {"19.0.0": "19.0.1", "19.1.0": "19.1.2",
             "19.1.1": "19.1.2", "19.2.0": "19.2.1"}
RSC_PACKAGES = ("react-server-dom-webpack", "react-server-dom-parcel",
                "react-server-dom-turbopack")

# next: (vulnerable_start, vulnerable_end_exclusive, fixed_release)
NEXT_RANGES = [
    ((14, 3, 0), (15, 0, 5), "15.0.5"),
    ((15, 1, 0), (15, 1, 9), "15.1.9"),
    ((15, 2, 0), (15, 2, 6), "15.2.6"),
    ((15, 3, 0), (15, 3, 6), "15.3.6"),
    ((15, 4, 0), (15, 4, 8), "15.4.8"),
    ((15, 5, 0), (15, 5, 7), "15.5.7"),
    ((16, 0, 0), (16, 0, 7), "16.0.7"),
]

NEXT_MARKERS = [
    re.compile(r"__next", re.I),
    re.compile(r"/_next/static", re.I),
    re.compile(r"x-powered-by:\s*next\.js", re.I),
]
NEXT_VERSION_RES = [
    re.compile(r'"version"\s*:\s*"(\d+)\.(\d+)\.(\d+)[^"]*"[^}]*"name"\s*:\s*"next"', re.I),
    re.compile(r"next[^\d]*(\d+)\.(\d+)\.(\d+)", re.I),
]
BUILD_ID_RE = re.compile(r"/_next/static/([A-Za-z0-9_-]+)/")

# Log-hunt: React2Shell exploitation rides on POSTs carrying React Flight
# (RSC) payloads to Server Function endpoints. Access logs rarely show
# bodies, so these are heuristics, not proof.
LOG_RES = [
    re.compile(r"text/x-component", re.I),
    re.compile(r"Next-Action", re.I),
    re.compile(r"RSC", re.I),
]


def vt(s):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(map(int, m.groups())) if m else None


def rsc_verdict(pkg, version):
    v = vt(version)
    if not v:
        return "unknown", "could not parse version %r" % version
    vs = "%d.%d.%d" % v
    if vs in RSC_VULN:
        return ("vulnerable",
                "%s %s is a known-vulnerable release, fix: %s"
                % (pkg, vs, RSC_FIXED[vs]))
    return "patched", "%s %s not in the vulnerable set" % (pkg, vs)


def next_verdict(version):
    v = vt(version)
    if not v:
        return "unknown", "could not parse version %r" % version
    vs = "%d.%d.%d" % v
    for start, end, fixed in NEXT_RANGES:
        if start <= v < end:
            return ("vulnerable",
                    "next %s in vulnerable range, fix: >= %s" % (vs, fixed))
    return "patched", "next %s outside all vulnerable ranges" % vs


# ---------------- audit: local project ----------------

def read_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def audit_project(root):
    findings = []
    pkg = read_json(os.path.join(root, "package.json")) or {}
    lock = read_json(os.path.join(root, "package-lock.json")) or {}

    def check(pkg_name, version, source):
        if pkg_name in RSC_PACKAGES:
            v, d = rsc_verdict(pkg_name, version)
        elif pkg_name == "next":
            v, d = next_verdict(version)
        else:
            return
        findings.append({"package": pkg_name, "version": version,
                         "source": source, "verdict": v, "detail": d})

    deps = dict(pkg.get("dependencies", {}))
    deps.update(pkg.get("devDependencies", {}))
    for name in list(deps):
        if name in RSC_PACKAGES or name == "next":
            # resolved version from lockfile beats the semver range
            ver = None
            for key in ("packages", "dependencies"):
                node = (lock.get(key) or {}).get(
                    "" if key == "packages" else name)
                if key == "packages":
                    node = (lock.get("packages") or {}).get(
                        "node_modules/" + name)
                if isinstance(node, dict) and node.get("version"):
                    ver = node["version"]
                    break
            if not ver:
                mod = os.path.join(root, "node_modules", name,
                                   "package.json")
                mj = read_json(mod)
                ver = (mj or {}).get("version")
            check(name, ver or deps[name] + " (range, unresolved)",
                  "package.json" + (" + lockfile" if ver else ""))

    if not findings:
        findings.append({"package": "-", "version": "-",
                         "source": root, "verdict": "not-applicable",
                         "detail": "no react-server-dom-* or next "
                                   "dependency found"})
    return findings


# ---------------- scan: remote host ----------------

def _ctx(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url, timeout, insecure):
    req = urllib.request.Request(
        url, headers={"User-Agent": "react2shell-scanner/%s" % VERSION})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_ctx(insecure)) as r:
            hdrs = dict(r.headers)
            body = r.read(600000).decode("utf-8", "replace")
            blob = "\n".join("%s: %s" % kv for kv in hdrs.items()) + body
            return r.status, blob
    except urllib.error.HTTPError as e:
        try:
            body = e.read(600000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, "ERROR: %s" % e


def scan_target(target, timeout=10, insecure=False):
    base = target if "://" in target else "http://%s" % target
    result = {"target": target,
              "checked_at": datetime.now(timezone.utc).isoformat(),
              "is_nextjs": False, "next_version": None,
              "verdict": "not-nextjs",
              "detail": "no Next.js markers found"}
    status, blob = fetch(base.rstrip("/") + "/", timeout, insecure)
    if status is None:
        result["verdict"] = "unreachable"
        result["detail"] = blob
        return result
    if not any(rx.search(blob) for rx in NEXT_MARKERS):
        return result
    result["is_nextjs"] = True

    version = None
    for rx in NEXT_VERSION_RES:
        m = rx.search(blob)
        if m:
            version = "%s.%s.%s" % (m.group(1), m.group(2), m.group(3))
            break
    # build manifest sometimes exposes more; one cheap extra request
    if not version:
        m = BUILD_ID_RE.search(blob)
        if m:
            st, manifest = fetch(
                "%s/_next/static/%s/_buildManifest.js"
                % (base.rstrip("/"), m.group(1)), timeout, insecure)
            if st == 200:
                for rx in NEXT_VERSION_RES:
                    mm = rx.search(manifest)
                    if mm:
                        version = "%s.%s.%s" % (mm.group(1), mm.group(2),
                                                mm.group(3))
                        break
    if version:
        result["next_version"] = version
        v, d = next_verdict(version)
        result["verdict"] = v
        result["detail"] = d
    else:
        result["verdict"] = "needs-manual-check"
        result["detail"] = ("Next.js detected but the framework version is "
                            "not exposed. Check package.json / lockfile: "
                            "vulnerable next ranges are 14.3.0-15.0.4, "
                            "15.1.0-15.1.8, 15.2.0-15.2.5, 15.3.0-15.3.5, "
                            "15.4.0-15.4.7, 15.5.0-15.5.6, 16.0.0-16.0.6.")
    return result


# ---------------- logcheck ----------------

def logcheck(path):
    hits = []
    with open(path, "r", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            if '"POST ' not in line:
                continue
            markers = sorted({rx.pattern for rx in LOG_RES
                              if rx.search(line)})
            if markers:
                ip = line.split()[0] if line.split() else "?"
                hits.append({"line": lineno, "ip": ip,
                             "markers": markers,
                             "raw": line.strip()[:300]})
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Triage scanner for CVE-2025-55182 (React2Shell) / "
                    "CVE-2025-66478. Detection only, no payloads sent.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="audit a local JS project")
    a.add_argument("path", help="project root with package.json")
    a.add_argument("--json", action="store_true")

    s = sub.add_parser("scan", help="fingerprint remote host(s)")
    s.add_argument("targets", nargs="+")
    s.add_argument("--timeout", type=int, default=10)
    s.add_argument("-k", "--insecure", action="store_true")
    s.add_argument("--json", action="store_true")

    l = sub.add_parser("logcheck", help="hunt access logs for indicators")
    l.add_argument("logfile")
    l.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "audit":
        findings = audit_project(args.path)
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            for f in findings:
                print("[%s] %s %s (%s)" % (
                    f["verdict"].upper(), f["package"],
                    f["version"], f["source"]))
                print("  %s" % f["detail"])
        return 2 if any(f["verdict"] == "vulnerable"
                        for f in findings) else 0

    if args.cmd == "scan":
        results = [scan_target(t, args.timeout, args.insecure)
                   for t in args.targets]
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print("[%s] %s" % (r["verdict"].upper(), r["target"]))
                print("  next: %s" % (r["next_version"] or "n/a"))
                print("  %s" % r["detail"])
        return 2 if any(r["verdict"] == "vulnerable"
                        for r in results) else 0

    hits = logcheck(args.logfile)
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        if not hits:
            print("No React2Shell exploitation indicators found.")
        for h in hits:
            print("line %d | ip %s | markers: %s" % (
                h["line"], h["ip"], ", ".join(h["markers"])))
            print("  %s" % h["raw"])
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
