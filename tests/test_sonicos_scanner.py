#!/usr/bin/env python3
"""Tests for sonicos_scanner. Run: python3 -m unittest discover -s tests -v"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sonicos_scanner import (
    FIXED,
    AFFECTED_MAX,
    format_version,
    grade,
    normalize_generation,
    parse_version,
)


class TestParsing(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_version("7.3.3-7015"), (7, 3, 3, 7015))
        self.assertEqual(parse_version("SonicOS 8.2.3-8015"), (8, 2, 3, 8015))
        self.assertEqual(parse_version("sonicos 7.3.4-7013"), (7, 3, 4, 7013))
        self.assertEqual(parse_version("  7.3.4-7015  "), (7, 3, 4, 7015))

    def test_parse_rejects_bare_version(self):
        # The incomplete-version trap: no build number, no grade.
        self.assertIsNone(parse_version("7.3.3"))
        self.assertIsNone(parse_version("8.2.3"))
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version("7.3.3.7015"))
        self.assertIsNone(parse_version(None))

    def test_generation(self):
        self.assertEqual(normalize_generation("gen7"), "gen7")
        self.assertEqual(normalize_generation("Gen 7"), "gen7")
        self.assertEqual(normalize_generation("7"), "gen7")
        self.assertEqual(normalize_generation("GEN8"), "gen8")
        self.assertEqual(normalize_generation("8"), "gen8")
        self.assertEqual(normalize_generation("gen6"), "gen6")
        self.assertIsNone(normalize_generation("gen9"))
        self.assertIsNone(normalize_generation(""))
        self.assertIsNone(normalize_generation(None))

    def test_table(self):
        self.assertEqual(FIXED["gen7"], (7, 3, 4, 7013))
        self.assertEqual(FIXED["gen8"], (8, 2, 3, 8015))
        self.assertEqual(AFFECTED_MAX["gen7"], (7, 3, 3, 7015))
        self.assertEqual(AFFECTED_MAX["gen8"], (8, 2, 2, 8015))


class TestGrades(unittest.TestCase):
    def test_fixed_builds_patched(self):
        self.assertEqual(grade("7.3.4-7013", "gen7")["grade"], "PATCHED")
        self.assertEqual(grade("8.2.3-8015", "gen8")["grade"], "PATCHED")

    def test_later_builds_patched(self):
        # 7.3.4-7015 shipped 5 November, after the fix; still patched.
        self.assertEqual(grade("7.3.4-7015", "gen7")["grade"], "PATCHED")
        self.assertEqual(grade("7.3.5-7013", "gen7")["grade"], "PATCHED")
        self.assertEqual(grade("8.2.4-8015", "gen8")["grade"], "PATCHED")
        self.assertEqual(grade("8.3.0-8000", "gen8")["grade"], "PATCHED")

    def test_boundary_builds_vulnerable(self):
        self.assertEqual(grade("7.3.3-7015", "gen7")["grade"], "VULNERABLE")
        self.assertEqual(grade("8.2.2-8015", "gen8")["grade"], "VULNERABLE")

    def test_gen8_build_number_trap(self):
        # Same build number 8015 on both sides of the fix; only the
        # middle digit changes. The reason must call the trap out.
        result = grade("8.2.2-8015", "gen8")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertIn("BUILD-NUMBER TRAP", result["reason"])

    def test_gen7_7013_is_the_fix_not_7015(self):
        # 7.3.4-7013 is fixed even though 7.3.4-7015 exists.
        result = grade("7.3.4-7013", "gen7")
        self.assertEqual(result["grade"], "PATCHED")
        self.assertIn("7.3.4-7015", result["reason"])

    def test_older_builds_vulnerable(self):
        for version in ("7.3.2-7015", "7.3.0-7015", "7.0.1-5050", "7.2.0-7015"):
            with self.subTest(version=version):
                self.assertEqual(grade(version, "gen7")["grade"], "VULNERABLE")
        for version in ("8.2.1-8015", "8.2.0-8015", "8.1.0-8015"):
            with self.subTest(version=version):
                self.assertEqual(grade(version, "gen8")["grade"], "VULNERABLE")

    def test_one_build_below_fix_is_vulnerable(self):
        self.assertEqual(grade("7.3.4-7012", "gen7")["grade"], "VULNERABLE")
        self.assertEqual(grade("8.2.3-8014", "gen8")["grade"], "VULNERABLE")

    def test_cross_generation_is_unknown(self):
        result = grade("8.2.2-8015", "gen7")
        self.assertEqual(result["grade"], "UNKNOWN")
        result = grade("7.3.3-7015", "gen8")
        self.assertEqual(result["grade"], "UNKNOWN")

    def test_bare_version_is_unknown(self):
        result = grade("7.3.3", "gen7")
        self.assertEqual(result["grade"], "UNKNOWN")
        self.assertIn("no build number", result["reason"])

    def test_unknown_generation_is_unknown(self):
        result = grade("7.3.3-7015", "gen9")
        self.assertEqual(result["grade"], "UNKNOWN")

    def test_gen6_eol_is_unknown_not_clean(self):
        result = grade("6.5.4-44", "gen6")
        self.assertEqual(result["grade"], "UNKNOWN")
        self.assertIn("end of support", result["reason"])

    def test_no_saml_is_not_exposed(self):
        result = grade("7.3.3-7015", "gen7", saml=False)
        self.assertEqual(result["grade"], "NOT-EXPOSED")
        # A patched build stays PATCHED even without SAML.
        result = grade("7.3.4-7013", "gen7", saml=False)
        self.assertEqual(result["grade"], "PATCHED")
        # UNKNOWN stays UNKNOWN even without SAML.
        result = grade("7.3.3", "gen7", saml=False)
        self.assertEqual(result["grade"], "UNKNOWN")


class TestCLI(unittest.TestCase):
    def run_cli(self, *argv):
        script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sonicos_scanner.py",
        )
        proc = subprocess.run(
            [sys.executable, script, *argv],
            capture_output=True, text=True,
        )
        return proc

    def test_vulnerable_exit_2(self):
        proc = self.run_cli("--generation", "gen7", "--version", "7.3.3-7015")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("VULNERABLE", proc.stdout)

    def test_patched_exit_0(self):
        proc = self.run_cli("--generation", "gen8", "--version", "8.2.3-8015")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PATCHED", proc.stdout)

    def test_unknown_exit_0(self):
        proc = self.run_cli("--generation", "gen7", "--version", "7.3.3")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("UNKNOWN", proc.stdout)

    def test_no_saml_flag(self):
        proc = self.run_cli("--generation", "gen7", "--version", "7.3.3-7015",
                            "--no-saml")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("NOT-EXPOSED", proc.stdout)

    def test_missing_args_exit_2(self):
        proc = self.run_cli("--generation", "gen7")
        self.assertEqual(proc.returncode, 2)  # argparse error exit
        proc = self.run_cli("--generation", "gen7", "--version", "bogus")
        self.assertEqual(proc.returncode, 0)  # unparseable grades UNKNOWN
        self.assertIn("UNKNOWN", proc.stdout)

    def test_json_output(self):
        proc = self.run_cli("--generation", "gen7", "--version", "7.3.3-7015",
                            "--json")
        data = json.loads(proc.stdout)
        self.assertEqual(data["grade"], "VULNERABLE")
        self.assertEqual(data["fixed"], "7.3.4-7013")

    def test_list(self):
        proc = self.run_cli("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("7.3.4-7013", proc.stdout)
        self.assertIn("8.2.3-8015", proc.stdout)

    def test_inventory_json(self):
        entries = [
            {"label": "fw-edge", "generation": "gen7", "version": "7.3.3-7015"},
            {"label": "fw-core", "generation": "gen8", "version": "8.2.3-8015"},
            {"label": "fw-branch", "generation": "gen7", "version": "7.3.3-7015",
             "saml_sslvpn": False},
            {"label": "fw-old", "generation": "gen6", "version": "6.5.4-44"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(entries, fh)
            path = fh.name
        try:
            proc = self.run_cli("--inventory-json", path)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("VULNERABLE", proc.stdout)
            self.assertIn("PATCHED", proc.stdout)
            self.assertIn("NOT-EXPOSED", proc.stdout)
            self.assertIn("UNKNOWN", proc.stdout)
            proc = self.run_cli("--inventory-json", path, "--json")
            data = json.loads(proc.stdout)
            self.assertEqual(len(data), 4)
            self.assertEqual(data[0]["grade"], "VULNERABLE")
            self.assertEqual(data[1]["grade"], "PATCHED")
            self.assertEqual(data[2]["grade"], "NOT-EXPOSED")
            self.assertEqual(data[3]["grade"], "UNKNOWN")
        finally:
            os.unlink(path)

    def test_inventory_bad_file_exit_1(self):
        proc = self.run_cli("--inventory-json", "/nonexistent/file.json")
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
