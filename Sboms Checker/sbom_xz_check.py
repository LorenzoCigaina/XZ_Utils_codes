#!/usr/bin/env python3
"""sbom_xz_check.py - exposure check for CVE-2024-3094 (xz/liblzma backdoor)
on a CycloneDX JSON SBOM (generated e.g. with Syft).

What it does (SBOM = inventory, not a detector):
  1. finds xz/liblzma components and compares their version in two ways:
       - "naive": looks only at the version string (what a simple scanner does)
       - "informed": understands Debian's 'X+reallyY' convention (string says X,
         code is Y) and uses the effective version
  2. compares the SHA-256 of the liblzma library files listed in the SBOM with a
     list of hashes known to be compromised (hash > version string)
  3. shows which packages depend on xz/liblzma (e.g. libsystemd0 -> liblzma5)
  4. optionally queries OSV (--osv); needs network.

Usage:
  python3 sbom_xz_check.py sbom.json
  python3 sbom_xz_check.py sbom.json --known-bad bad_hashes.json
  python3 sbom_xz_check.py sbom.json --osv --osv-ecosystem Debian
Exit code: 1 if the informed check finds the system exposed, 0 otherwise.
"""
import argparse
import json
import re
import sys
import urllib.request

TARGET_NAMES = {"xz-utils", "liblzma5", "liblzma-dev", "xz-libs", "xz", "liblzma",
                "xz-devel", "xz-lzma-compat"}

# Local advisory, so the demo works offline. Verify the data on NVD/OSV before citing it.
ADVISORY = {"id": "CVE-2024-3094", "cvss": 10.0, "affected_upstream": {"5.6.0", "5.6.1"}}

# SHA-256 of library files known to be compromised. Provenance must be stated.
KNOWN_BAD_SHA256 = {
    "605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4":
        "liblzma.so.5.6.1 from the Debian package liblzma5 5.6.1-1 (measured by our team)",
}


def effective_version(version):
    """Debian convention: '5.6.1+really5.4.5-1' = version string 5.6.1, code 5.4.5."""
    m = re.search(r"\+really([0-9][0-9.]*)", version)
    if m:
        return m.group(1), True
    m = re.match(r"(?:\d+:)?([0-9]+(?:\.[0-9]+)*)", version)
    return (m.group(1) if m else version), False


def naive_flag(version):
    return any(v in version for v in ADVISORY["affected_upstream"])


def sha256_of(component):
    for h in component.get("hashes") or []:
        if h.get("alg", "").upper().replace("-", "") == "SHA256":
            return h["content"].lower()
    return None


def reverse_chains(sbom, target_ref, label):
    """Packages that (transitively) depend on target_ref, as readable chains."""
    rev = {}
    for dep in sbom.get("dependencies") or []:
        for child in dep.get("dependsOn") or []:
            rev.setdefault(child, []).append(dep["ref"])
    chains = []

    def walk(ref, path):
        parents = rev.get(ref, [])
        if not parents:
            if len(path) > 1:
                chains.append(" -> ".join(label(r) for r in reversed(path)))
            return
        for p in parents:
            if p not in path:  # avoid cycles
                walk(p, path + [p])

    walk(target_ref, [target_ref])
    return chains


def osv_query(name, version, ecosystem):
    body = json.dumps({"version": version,
                       "package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r).get("vulns", [])


def main():
    ap = argparse.ArgumentParser(description="xz backdoor exposure check on a CycloneDX SBOM")
    ap.add_argument("sbom")
    ap.add_argument("--known-bad", help="JSON {sha256: description} of compromised files")
    ap.add_argument("--osv", action="store_true", help="also query OSV (needs network)")
    ap.add_argument("--osv-ecosystem", default="Debian")
    args = ap.parse_args()

    with open(args.sbom) as f:
        sbom = json.load(f)
    bad = dict(KNOWN_BAD_SHA256)
    if args.known_bad:
        with open(args.known_bad) as f:
            bad.update({k.lower(): v for k, v in json.load(f).items()})

    comps = sbom.get("components") or []
    by_ref = {c.get("bom-ref"): c for c in comps}
    label = lambda r: f"{by_ref[r]['name']} {by_ref[r].get('version', '')}".strip() if r in by_ref else r

    targets = [c for c in comps if c.get("type") == "library" and c.get("name") in TARGET_NAMES]
    lib_files = [c for c in comps if c.get("type") == "file"
                 and re.search(r"/liblzma[^/]*\.so", c.get("name", ""))]
    exposed = False

    print(f"SBOM: {args.sbom} ({len(comps)} components)")
    if not targets:
        print("No xz/liblzma component found: not exposed according to this SBOM.")
        return 0

    for c in targets:
        v = c.get("version", "?")
        eff, really = effective_version(v)
        naive = naive_flag(v)
        informed = eff in ADVISORY["affected_upstream"]
        exposed |= informed
        print(f"\n== {c['name']} {v}")
        print(f"  version string check : {'ALERT' if naive else 'ok'}   (looks only at the text of the version)")
        print(f"  effective version    : {eff}" + ("  ('+really' convention: code differs from the string)" if really else ""))
        print(f"  informed version check: {'ALERT' if informed else 'ok'}")
        if naive and not informed:
            print("  -> the version-string check is a FALSE POSITIVE for this package")
        if informed:
            print(f"  -> {ADVISORY['id']} (CVSS {ADVISORY['cvss']}): affected upstream version {eff}")
        for chain in reverse_chains(sbom, c.get("bom-ref"), label):
            print(f"  depended on by       : {chain}")
        if args.osv:
            source = "xz-utils" if c["name"] in {"liblzma5", "liblzma-dev"} else c["name"]
            try:
                vulns = osv_query(source, v, args.osv_ecosystem)
                ids = ", ".join(x["id"] for x in vulns) or "none"
                print(f"  OSV ({source} {v}, {args.osv_ecosystem}): {ids}")
            except Exception as e:  # offline or API error
                print(f"  OSV query failed: {e}")

    print("\n== file hashes (liblzma libraries listed in the SBOM)")
    if not lib_files:
        print("  none: the SBOM has no file-level hashes (generate it with a tool that records them)")
    for f in lib_files:
        h = sha256_of(f)
        if not h:
            continue
        hit = bad.get(h)
        exposed |= bool(hit)
        print(f"  {f['name']}\n    sha256 {h}\n    -> {'KNOWN COMPROMISED: ' + hit if hit else 'not in the known-bad list'}")

    print("\nVERDICT:", "EXPOSED" if exposed else "not exposed (according to version and known hashes)")
    print("Limit: an SBOM lists what is installed; it cannot tell by itself whether a component "
          "was tampered with. The hash check only finds files already known to be bad.")
    return 1 if exposed else 0


if __name__ == "__main__":
    sys.exit(main())
