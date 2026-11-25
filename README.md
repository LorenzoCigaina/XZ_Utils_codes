# XZ Utils backdoor (CVE-2024-3094) – analysis tools

Code written by Team 2 for the *Foundations of Cybersecurity* course (University of Pavia).
It supports the static analysis of the attack artifacts and an SBOM-based exposure check.

## Contents

| File | Purpose |
|---|---|
| `static_triage.py` | Static triage (hash, file type, entropy, ASCII strings) and folder comparison |
| `sbom_xz_check.py` | Checks a CycloneDX SBOM for exposed xz/liblzma versions |
| `xz_5_6_x_trigger.yar` | Two YARA rules for the modified `build-to-host.m4` and the carrier test file |

## Requirements

- Python 3 (standard library only; `python-magic` is optional)
- [Syft](https://github.com/anchore/syft) to generate SBOMs
- [YARA](https://virustotal.github.io/yara/) to run the rules

## Usage

```bash
# Triage of a tarball (extracted safely), compared with known hashes, JSON report
python3 static_triage.py triage xz-utils_5.6.1.orig.tar.xz --extract work/ --expected expected.txt --json report.json

# Compare two folders by SHA-256 (e.g. tarball content vs Git checkout)
python3 static_triage.py compare work/xz-utils_5.6.1.orig/xz-5.6.1 ~/xz-git

# SBOM check (add --osv to query OSV; needs network)
syft scan <target> -o cyclonedx-json=sbom.json
python3 sbom_xz_check.py sbom.json --osv --osv-ecosystem Debian

# YARA rules
yara -r xz_5_6_x_trigger.yar <folder>
```

`expected.txt` uses the `sha256sum` format. `sbom_xz_check.py` exits with code 1 when the verdict is "exposed".

## Notes and limits

- All the analyses were **static**, in an isolated VM: never execute, compile or install the compromised files.
- This repository contains **no compromised files**. Packages and tarballs come from [snapshot.debian.org](https://snapshot.debian.org) and the public xz repository.
- `syft scan file.deb` records only the hash of the archive. For the SHA-256 of each file, scan an extracted package or a container image.
- The known-bad hash in `sbom_xz_check.py` was measured by us from the Debian package (it shows the mechanism, not an independent detection). OSV results change over time.
- The YARA rules were written from the 5.6.1 diff and tested on few samples.
