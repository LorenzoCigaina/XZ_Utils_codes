#!/usr/bin/env python3
"""static_triage.py - static triage helper for the XZ Utils project.

Phases covered (static only: files are read, never executed, built or installed):
  1. hash         MD5 / SHA-1 / SHA-256, optional check against known-good hashes
  2. file type    magic bytes (python-magic if installed) + Shannon entropy
  3. ASCII strings printable runs + keyword hits for suspicious build/shell patterns
  +  compare      tarball tree vs git checkout, by SHA-256

Examples:
  python3 static_triage.py triage xz-utils_5.6.1.orig.tar.xz --extract work/ --json report.json
  python3 static_triage.py triage liblzma.so.5.6.1 --expected expected.txt --algo sha1
  python3 static_triage.py compare work/xz-utils_5.6.1.orig/xz-5.6.1 ~/xz-git

expected.txt uses the sha256sum format: "<hash>  <filename>" (md5/sha1/sha256 accepted).
Keyword hits are heuristics and noisy on purpose: read the flagged files by hand.
"""
import argparse
import hashlib
import json
import math
import os
import re
import tarfile
from collections import Counter

MAGIC = [  # (signature, offset, label)
    (b"\xfd7zXZ\x00", 0, "XZ compressed data"),
    (b"\x7fELF", 0, "ELF executable / shared object"),
    (b"\x1f\x8b", 0, "gzip compressed data"),
    (b"BZh", 0, "bzip2 compressed data"),
    (b"(\xb5/\xfd", 0, "Zstandard compressed data"),
    (b"!<arch>\n", 0, "ar archive (e.g. .deb)"),
    (b"PK\x03\x04", 0, "Zip archive"),
    (b"#!", 0, "script with shebang"),
    (b"ustar", 257, "tar archive"),
    (b"\x5d\x00\x00", 0, "possible raw LZMA (.lzma) data"),
]

KEYWORDS = ["eval", "/bin/sh", "bash", "base64", "xz -d", "tr ", "head -c", "sed ",
            "awk", "curl", "wget", "RPM_ARCH", "linux-gnu", "x86_64", "dpkg",
            "ifunc", "RSA_public_decrypt", "sshd", "systemd", "dlopen", "getenv"]


# ---------- phase 1: hash ----------
def digests(path):
    hs = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in hs.values():
                h.update(chunk)
    return {n: h.hexdigest() for n, h in hs.items()}


def load_expected(path):
    expected = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                expected[os.path.basename(parts[1].lstrip("*"))] = parts[0].lower()
    return expected


def check(info, expected):
    want = expected.get(os.path.basename(info["path"]))
    if not want:
        return "no-ref"
    algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(want))
    return "OK" if algo and info[algo] == want else "MISMATCH"


# ---------- phase 2: file type ----------
def file_type(path):
    try:
        import magic  # optional: pip install python-magic
        return magic.from_file(path)
    except Exception:
        pass
    with open(path, "rb") as f:
        head = f.read(512)
    for sig, off, label in MAGIC:
        if head[off:off + len(sig)] == sig:
            return label
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head)
    if head and printable / len(head) > 0.95:
        return "ASCII text"
    return "data (unknown)"


def entropy(path, limit=1 << 22):
    with open(path, "rb") as f:
        data = f.read(limit)
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# ---------- phase 3: ASCII strings ----------
def ascii_strings(path, min_len):
    pattern = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    with open(path, "rb") as f:
        data = f.read()
    return [m.group().decode("ascii") for m in pattern.finditer(data)]


def triage(path, args):
    info = {"path": path, "size": os.path.getsize(path), "type": file_type(path),
            "entropy": round(entropy(path), 2), **digests(path)}
    strs = ascii_strings(path, args.min_len)
    kws = KEYWORDS + (args.kw or [])
    lowered = [(s, s.lower()) for s in strs]
    hits = {}
    for kw in kws:
        count = sum(kw.lower() in low for _, low in lowered)
        if count:
            hits[kw] = count
    info["n_strings"] = len(strs)
    info["keyword_hits"] = hits
    info["sample_strings"] = [s for s, low in lowered
                              if any(kw.lower() in low for kw in kws)][:args.show]
    return info


# ---------- helpers ----------
def walk(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d != ".git")
                for name in sorted(files):
                    fp = os.path.join(root, name)
                    if not os.path.islink(fp):  # never follow symlinks
                        yield fp
        else:
            yield p


def safe_extract(archive, dest):
    """Extract regular files and directories only, refusing paths that escape dest."""
    os.makedirs(dest, exist_ok=True)
    dest_real = os.path.realpath(dest)
    with tarfile.open(archive) as tar:
        members = []
        for m in tar.getmembers():
            if not (m.isfile() or m.isdir()):
                continue  # skip links, devices, fifos
            real = os.path.realpath(os.path.join(dest, m.name))
            if real != dest_real and not real.startswith(dest_real + os.sep):
                raise RuntimeError(f"unsafe path in archive: {m.name}")
            members.append(m)
        try:
            tar.extractall(dest, members=members, filter="data")
        except TypeError:  # older Python without extraction filters
            tar.extractall(dest, members=members)


# ---------- commands ----------
def run_triage(args):
    expected = load_expected(args.expected) if args.expected else {}
    targets = []
    for p in args.paths:
        targets.append(p)
        if args.extract and os.path.isfile(p) and tarfile.is_tarfile(p):
            dest = os.path.join(args.extract, os.path.basename(p).split(".tar")[0])
            safe_extract(p, dest)
            targets.append(dest)
    results = []
    for fp in walk(targets):
        r = triage(fp, args)
        r["check"] = check(r, expected) if expected else "-"
        r["flag"] = bool(r["keyword_hits"]) or r["entropy"] > 7.5 or r["check"] == "MISMATCH"
        results.append(r)

    print(f"{args.algo}  size  entropy  check  type  path   ('!' = flagged)")
    for r in results:
        mark = "!" if r["flag"] else " "
        print(f"{mark} {r[args.algo]}  {r['size']:>9}  H={r['entropy']:<4}  "
              f"{r['check']:<8}  {r['type'][:30]:<30}  {r['path']}")
    flagged = [r for r in results if r["flag"]]
    if flagged:
        print("\n--- details for flagged files ---")
        for r in flagged:
            print(f"\n{r['path']}  [{r['check']}]")
            print(f"  md5    {r['md5']}\n  sha1   {r['sha1']}\n  sha256 {r['sha256']}")
            print(f"  strings: {r['n_strings']}  hits: {r['keyword_hits'] or 'none'}")
            for s in r["sample_strings"]:
                print(f"    {s[:100]}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nfull report written to {args.json}")


def tree_hashes(root):
    return {os.path.relpath(fp, root): digests(fp)["sha256"] for fp in walk([root])}


def run_compare(args):
    a, b = tree_hashes(args.dir_a), tree_hashes(args.dir_b)
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    differ = sorted(p for p in set(a) & set(b) if a[p] != b[p])
    print(f"only in {args.dir_a}: {len(only_a)}")
    for p in only_a:
        print("  +", p)
    print(f"only in {args.dir_b}: {len(only_b)}")
    for p in only_b:
        print("  -", p)
    print(f"same path, different content: {len(differ)}")
    for p in differ:
        print("  ~", p)


def main():
    ap = argparse.ArgumentParser(description="Static triage helper (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="hash, file type, ASCII strings")
    t.add_argument("paths", nargs="+", help="files or directories")
    t.add_argument("--expected", help="known-good hashes, sha256sum format")
    t.add_argument("--algo", choices=["md5", "sha1", "sha256"], default="sha256",
                   help="hash shown in the table (snapshot.debian.org uses sha1)")
    t.add_argument("--min-len", type=int, default=8, help="min string length")
    t.add_argument("--show", type=int, default=5, help="sample strings per flagged file")
    t.add_argument("--kw", action="append", help="extra keyword (repeatable)")
    t.add_argument("--extract", metavar="DIR", help="extract tar archives into DIR first")
    t.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    t.set_defaults(func=run_triage)
    c = sub.add_parser("compare", help="compare two directory trees by SHA-256")
    c.add_argument("dir_a")
    c.add_argument("dir_b")
    c.set_defaults(func=run_compare)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
