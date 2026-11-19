#!/usr/bin/env python3
"""Print one version's section of CHANGELOG.md, for the GitHub Release body.

    python tools/changelog.py v1.1.3            # the "## [1.1.3]" section, without its heading
    python tools/changelog.py 1.1.3 --file CHANGELOG.md

If the version has no section yet, the "## [Unreleased]" section is used instead (with a
warning on stderr), so a tag pushed before the changelog was renamed still gets its notes.
Exits 1 when neither has any content: a release without notes is a mistake.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_HEADING = re.compile(r"^## \[([^\]]+)\]", re.M)


def sections(text: str) -> dict[str, str]:
    """{"1.1.2": "<body>", "Unreleased": "<body>"}; bodies are stripped, headings removed.
    The link references at the end ("[1.1.2]: https://...") are not part of any body."""
    text = re.split(r"^\[[^\]]+\]: ", text, maxsplit=1, flags=re.M)[0]
    marks = list(_HEADING.finditer(text))
    out = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[m.end():end]
        body = body.split("\n", 1)[1] if "\n" in body else ""          # drop the rest of the heading line
        out[m.group(1)] = body.strip()
    return out


def notes_for(version: str, text: str) -> tuple[str, bool]:
    """(notes, exact): exact is False when the Unreleased section stood in."""
    version = version.lstrip("v")
    found = sections(text)
    if found.get(version):
        return found[version], True
    if found.get("Unreleased"):
        return found["Unreleased"], False
    raise LookupError(f"CHANGELOG.md has no notes for {version} and the Unreleased section is empty")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version")
    ap.add_argument("--file", type=Path, default=ROOT / "CHANGELOG.md")
    args = ap.parse_args(argv)
    try:
        notes, exact = notes_for(args.version, args.file.read_text(encoding="utf-8"))
    except (LookupError, OSError) as exc:
        print(f"changelog: {exc}", file=sys.stderr)
        return 1
    if not exact:
        print(f"changelog: no section for {args.version}; using [Unreleased]", file=sys.stderr)
    print(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
