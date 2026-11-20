"""CHANGELOG.md and tools/changelog.py: every released tag has notes, and the release job
puts the matching section above the downloads."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import changelog  # noqa: E402

TEXT = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("tag", ["v1.0.0", "v1.1.0", "v1.1.1", "v1.1.2"])
def test_every_release_has_its_own_notes(tag):
    notes, exact = changelog.notes_for(tag, TEXT)
    assert exact and len(notes) > 100 and "## [" not in notes
    assert "https://github.com/" not in notes.splitlines()[-1]            # link references are not included


def test_tags_in_the_repository_all_have_sections():
    tags = subprocess.run(["git", "-C", str(ROOT), "tag", "-l", "v*"], capture_output=True, text=True).stdout.split()
    found = changelog.sections(TEXT)
    for tag in tags:
        assert tag.lstrip("v") in found, f"{tag} is missing from CHANGELOG.md"


def test_unreleased_stands_in_and_empty_notes_fail(capsys):
    notes, exact = changelog.notes_for("v9.9.9", TEXT)
    assert not exact and notes == changelog.sections(TEXT)["Unreleased"]
    with pytest.raises(LookupError):
        changelog.notes_for("2.0.0", "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - x\n\nnotes\n")
    sample = "## [Unreleased]\n\n## [2.0.0] - 2027-01-01\n\n### Added\n- thing\n\n[2.0.0]: https://x\n"
    assert changelog.notes_for("v2.0.0", sample) == ("### Added\n- thing", True)


def test_cli_prints_the_section(tmp_path):
    f = tmp_path / "CHANGELOG.md"
    f.write_text("## [1.2.3] - 2027-01-01\n\nFixed it.\n", encoding="utf-8")
    assert changelog.main(["v1.2.3", "--file", str(f)]) == 0
    assert changelog.main(["v0.0.1", "--file", str(f)]) == 1


def test_release_job_puts_the_notes_above_the_downloads():
    wf = (ROOT / ".github" / "workflows" / "build.yml").read_text()
    job = wf[wf.index("  release:"):]
    assert "actions/checkout@v4" in job and "CHANGELOG.md" in job
    assert 'python3 tools/changelog.py "$TAG" > changelog-notes.md' in job
    assert job.index("## What's changed") < job.index("cat ../changelog-notes.md") < job.index('echo "## Downloads"')


def test_cli_writes_utf8_even_on_a_legacy_windows_code_page(tmp_path):
    f = tmp_path / "CHANGELOG.md"
    f.write_text("## [1.2.3] - 2027-01-01\n\nScan → Review → Apply\n", encoding="utf-8")
    env = {**__import__("os").environ, "PYTHONIOENCODING": "cp1250"}      # what Windows Git Bash gave
    res = subprocess.run([sys.executable, str(ROOT / "tools" / "changelog.py"), "v1.2.3", "--file", str(f)],
                         capture_output=True, env=env)
    assert res.returncode == 0, res.stderr
    assert res.stdout.decode("utf-8").strip() == "Scan → Review → Apply"
