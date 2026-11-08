#!/usr/bin/env python3
"""Detection-only local triage for CVE-2026-19868 in SonicWall SonicOS.

Grades a SonicOS firmware version you supply (or an offline inventory of
them) against SonicWall advisory SNWLID-2026-0014, published 6 November
2026. The flaw is an authentication-enforcement weakness (CWE-308) in the
SSLVPN service: a user holding valid credentials for an alternate login
method can bypass SAML authentication controls, including SAML-enforced
multi-factor authentication. It only matters where SAML handles SSLVPN
logins, and it needs those alternate credentials, so this is not an
unauthenticated remote takeover. It is on CISA's Known Exploited
Vulnerabilities catalog (added 6 November 2026, federal due date
20 November 2026), which is why a same-day check is worth doing.

This tool sends no traffic, probes no firewall, and attempts no login.
It only compares firmware version strings against a table. A VULNERABLE
grade means the firmware is below the fixed build; it does not mean the
firewall was compromised, and a PATCHED grade does not prove it was never
attacked. If compromise is suspected, preserve evidence and rotate
credentials before upgrading, because an upgrade alone does not undo a
bypassed login that already happened.

Usage:
    python3 sonicos_scanner.py --generation gen7 --version '7.3.3-7015'
    python3 sonicos_scanner.py --generation gen8 --version '8.2.3-8015'
    python3 sonicos_scanner.py --generation gen7 --version '7.3.3-7015' --no-saml
    python3 sonicos_scanner.py --inventory-json firewalls.json
    python3 sonicos_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input). UNKNOWN does not change the
exit code, but it is not clean: an unparseable, mismatched, or unlisted
generation/version pair has not been cleared, it has simply not been
graded.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CVE_ID = "CVE-2026-19868"
# Fixed builds from SonicWall advisory SNWLID-2026-0014 (6 November 2026).
# Gen7: 7.3.3-7015 and older are affected, 7.3.4-7013 and later are fixed.
# Gen8: 8.2.2-8015 and older are affected, 8.2.3-8015 and later are fixed.
# The two generations are independent lines: a Gen7 build is never graded
# against the Gen8 fix, or the other way round.
FIXED = {
    "gen7": (7, 3, 4, 7013),
    "gen8": (8, 2, 3, 8015),
}
# Advisory boundary builds, named in reasons so the traps read clearly.
AFFECTED_MAX = {
    "gen7": (7, 3, 3, 7015),
    "gen8": (8, 2, 2, 8015),
}
GENERATION_MAJOR = {
    "gen7": 7,
    "gen8": 8,
    "gen6": 6,
    "gen5": 5,
}

_VERSION_RE = re.compile(
    r"^\s*(?:sonicos\s+)?v?(\d+)\.(\d+)\.(\d+)-(\d+)\s*$", re.IGNORECASE
)


def normalize_generation(text):
    """Return a canonical generation key, or None for an unrecognised one."""
    if not isinstance(text, str):
        return None
    key = re.sub(r"[\s_\-]+", "", text.strip().lower())
    if key in GENERATION_MAJOR:
        return key
    if key in ("7",):
        return "gen7"
    if key in ("8",):
        return "gen8"
    if key in ("6",):
        return "gen6"
    if key in ("5",):
        return "gen5"
    return None


def parse_version(text):
    """Return (major, minor, patch, build) or None for an unparseable string."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def format_version(version):
    return f"{version[0]}.{version[1]}.{version[2]}-{version[3]}"


def grade(version_text, generation_text, saml=True):
    """Grade one generation + firmware version pair.

    Returns a dict with grade, fixed, and reason keys. Grades:
    PATCHED, VULNERABLE, NOT-EXPOSED, UNKNOWN.
    """
    generation = normalize_generation(generation_text)
    if generation is None:
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "reason": f"generation {generation_text!r} is not a recognised "
            "SonicWall generation (gen7 or gen8); it has not been cleared, "
            "only left ungraded",
        }
    if generation not in FIXED:
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "reason": f"{generation} is end of support and outside the "
            "advisory's Gen7/Gen8 table, so this flaw has no published "
            "mapping for it and no fix exists on that line; migrate to "
            "Gen8 hardware, do not treat it as cleared",
        }
    version = parse_version(version_text)
    if version is None:
        return {
            "grade": "UNKNOWN",
            "fixed": format_version(FIXED[generation]),
            "reason": f"firmware {version_text!r} does not parse as a "
            "SonicOS build like 7.3.3-7015; a bare 7.3.3 with no build "
            "number cannot be graded, and is not clean",
        }
    if version[0] != GENERATION_MAJOR[generation]:
        return {
            "grade": "UNKNOWN",
            "fixed": format_version(FIXED[generation]),
            "reason": f"version {format_version(version)} is a "
            f"{generation} build, not a {generation} one; a build from "
            "another generation cannot grade this firewall",
        }
    fixed = FIXED[generation]
    if version >= fixed:
        reason = (
            f"build is at or above the fixed {format_version(fixed)} "
            f"for {generation}"
        )
        if version == fixed and generation == "gen7":
            reason += "; 7.3.4-7015 exists too, but 7.3.4-7013 is already the fix"
        return {"grade": "PATCHED", "fixed": format_version(fixed), "reason": reason}
    if not saml:
        return {
            "grade": "NOT-EXPOSED",
            "fixed": format_version(fixed),
            "reason": f"build {format_version(version)} is below the fixed "
            f"{format_version(fixed)}, but SAML does not handle SSLVPN "
            "logins on this firewall, so the bypass has nothing to bypass; "
            "still upgrade, because the code is vulnerable and a config "
            "change can expose it",
        }
    if version == AFFECTED_MAX[generation] and generation == "gen8":
        return {
            "grade": "VULNERABLE",
            "fixed": format_version(fixed),
            "reason": "THE BUILD-NUMBER TRAP: 8.2.2-8015 and 8.2.3-8015 "
            "share the build number 8015 and only the middle digit "
            "changes. A check on the build number alone clears this "
            "firewall by mistake; only the full 8.2.3-8015 string is fixed",
        }
    if version == AFFECTED_MAX[generation] and generation == "gen7":
        return {
            "grade": "VULNERABLE",
            "fixed": format_version(fixed),
            "reason": "this is the advisory boundary build, 7.3.3-7015, "
            "the newest affected Gen7 build; upgrade to 7.3.4-7013 or later",
        }
    return {
        "grade": "VULNERABLE",
        "fixed": format_version(fixed),
        "reason": f"build is below the fixed {format_version(fixed)} for "
        f"{generation}; upgrade, there is no workaround",
    }


def render(result, version_text, generation_text, label=None, saml=True):
    lines = []
    if label:
        lines.append(f"[{label}]")
    lines.append(f"generation: {generation_text}")
    lines.append(f"firmware:   {version_text}")
    lines.append(f"saml sslvpn: {'yes' if saml else 'no'}")
    lines.append(f"grade:      {result['grade']}")
    if result["fixed"]:
        lines.append(f"fixed in:   {result['fixed']}")
    lines.append(f"reason:     {result['reason']}")
    return "\n".join(lines)


def load_inventory(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("inventory JSON must be a list of entries")
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("each inventory entry must be an object")
        if "version" not in entry or "generation" not in entry:
            raise ValueError(
                "each inventory entry needs 'version' and 'generation' keys"
            )
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for CVE-2026-19868 (SonicWall SonicOS)."
    )
    parser.add_argument("--generation", help="firewall generation: gen7 or gen8")
    parser.add_argument("--version", help="firmware build, e.g. 7.3.3-7015")
    parser.add_argument("--no-saml", action="store_true",
                        help="SAML does not handle SSLVPN logins on this firewall")
    parser.add_argument("--inventory-json", help="JSON list of generation/version entries")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--list", action="store_true", help="print the advisory table")
    args = parser.parse_args(argv)

    if args.list:
        for generation in ("gen7", "gen8"):
            print(
                f"{generation}: {format_version(AFFECTED_MAX[generation])} "
                f"and older affected, fixed in "
                f"{format_version(FIXED[generation])} and later"
            )
        return 0
    if args.inventory_json:
        try:
            entries = load_inventory(args.inventory_json)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        results = []
        vulnerable = False
        for entry in entries:
            saml = entry.get("saml_sslvpn", True)
            result = grade(entry["version"], entry["generation"], saml=saml)
            if result["grade"] == "VULNERABLE":
                vulnerable = True
            results.append({
                "label": entry.get("label", entry.get("host")),
                "generation": entry["generation"],
                "version": entry["version"],
                "saml_sslvpn": saml,
                **result,
            })
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for result in results:
                print(render(result, result["version"], result["generation"],
                             label=result["label"], saml=result["saml_sslvpn"]))
                print()
        return 2 if vulnerable else 0
    if not args.generation or not args.version:
        parser.error("--generation and --version are required (or --inventory-json / --list)")
    result = grade(args.version, args.generation, saml=not args.no_saml)
    if args.json:
        print(json.dumps({
            "generation": args.generation,
            "version": args.version,
            "saml_sslvpn": not args.no_saml,
            **result,
        }, indent=2))
    else:
        print(render(result, args.version, args.generation,
                     saml=not args.no_saml))
    return 2 if result["grade"] == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
