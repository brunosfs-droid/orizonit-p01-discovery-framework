from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".md", ".txt", ".json", ".yml", ".yaml", ".py", ".ps1", ".psm1",
    ".sh", ".toml", ".ini", ".cfg", ".conf", ".html", ".js", ".css",
}

# Construct restricted strings in fragments so this guard does not flag itself.
RESTRICTED = (
    ("share" + "point").lower(),
    ("one" + "drive").lower(),
    ("google" + " drive").lower(),
    ("orizonit-p01-" + "discovery-framework").lower(),
    ("produto" + " 02").lower(),
    ("produto" + " 03").lower(),
    ("product" + " 02").lower(),
    ("product" + " 03").lower(),
)


class PublicRepositoryBoundaryTests(unittest.TestCase):
    def test_no_known_internal_repository_references(self) -> None:
        findings: list[str] = []

        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
                "LICENSE", "NOTICE", "Dockerfile", "Makefile"
            }:
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            lowered = text.lower()
            for restricted in RESTRICTED:
                if restricted in lowered:
                    rel = path.relative_to(ROOT)
                    findings.append(f"{rel}: contains restricted public-repository reference {restricted!r}")

        self.assertEqual([], findings, "\n".join(findings))


if __name__ == "__main__":
    unittest.main()
