"""Contract tests: each rule fires on the document shape it describes.

The builder synthesises a valid document, then each test mutates exactly one
aspect of it. One integration test runs the checker against the real ``SKILL.md``
at the repository root, which is the artifact this repository exists to ship.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailauth_skill.cli import main
from mailauth_skill.contract import (
    REQUIRED_FRONTMATTER,
    SECTIONS,
    analyse,
    render_text,
    split_frontmatter,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_URLS = (
    "https://www.rfc-editor.org/rfc/rfc7208.html",
    "https://www.rfc-editor.org/rfc/rfc6376.html",
    "https://www.rfc-editor.org/rfc/rfc7489.html",
    "https://cwe.mitre.org/data/definitions/290.html",
    "https://attack.mitre.org/techniques/T1566/",
)

BASE_METADATA: dict[str, object] = {
    "name": "email-authentication-assessment",
    "id": "email-authentication-assessment@1.0.0",
    "version": "1.0.0",
    "category": "email-security",
    "domain": "internet mail authentication",
    "description": "Assess whether SPF, DKIM and DMARC stop unauthenticated use of the From domain.",
    "agent": "security agent with shell access and DNS",
    "knowledge": ["smtp identities", "spf evaluation", "dkim canonicalization"],
    "tools": ["dig", "openssl"],
    "os": ["linux", "macos"],
    "permissions": ["outbound dns"],
    "dependencies": ["bind9-dnsutils"],
    "cwe": ["CWE-290"],
    "owasp": ["A07"],
    "attack": ["T1566"],
    "references": ["RFC 7208"],
}

FLOORS = {letter: floor for letter, _, floor in SECTIONS}
TITLES = {letter: title for letter, title, _ in SECTIONS}


def _filler(letter: str) -> str:
    if letter == "K":
        return (
            "Authorization is required before any query and the scope must be written down. "
            "Stop conditions are listed below.\n\n"
            + "Each control names the boundary it protects and the evidence it leaves behind. " * 20
        )
    if letter == "P":
        return (
            "Authoritative primary sources used by this skill, each consulted for the normative "
            "behaviour it defines and cited by section rather than by title alone. Protocol "
            "specifications come first, then the weakness and technique mappings, then the "
            "documentation of each named tool.\n\n"
            + "\n".join(f"- {url}" for url in DEFAULT_URLS)
        )
    return "Each step names its precondition and the observation that would falsify it. " * (
        FLOORS[letter] // 8 + 4
    )


def build(
    *,
    front_over: dict[str, object] | None = None,
    drop_keys: tuple[str, ...] = (),
    bodies: dict[str, str] | None = None,
    titles: dict[str, str] | None = None,
    drop_sections: tuple[str, ...] = (),
    order: list[str] | None = None,
    h1: str | None = "# Email Authentication Assessment (SPF, DKIM, DMARC)",
    append: str = "",
) -> str:
    metadata = dict(BASE_METADATA)
    metadata.update(front_over or {})
    for key in drop_keys:
        metadata.pop(key, None)

    lines = ["---"]
    for key in REQUIRED_FRONTMATTER:
        if key not in metadata:
            continue
        value = metadata[key]
        if isinstance(value, list):
            lines.append(f"{key}: [{', '.join(str(v) for v in value)}]")
        else:
            lines.append(f"{key}: {value}")
    lines.append("---")
    lines.append("")

    if h1:
        lines.extend([h1, ""])

    for letter in order or [letter for letter, _, _ in SECTIONS]:
        if letter in drop_sections:
            continue
        title = (titles or {}).get(letter, TITLES[letter])
        body = (bodies or {}).get(letter, _filler(letter))
        lines.extend([f"## {letter}. {title}", "", body, ""])

    if append:
        lines.append(append)
    return "\n".join(lines)


def rules(report) -> set[str]:
    return {finding.rule for finding in report.findings}


# --------------------------------------------------------------------------- #
# Frontmatter
# --------------------------------------------------------------------------- #


def test_valid_document_passes():
    report = analyse(build())
    assert report.ok, [f.message for f in report.errors]
    assert len(report.sections) == len(SECTIONS)


def test_missing_frontmatter_fence():
    report = analyse("# Title\n\nno frontmatter here\n")
    assert "FM001" in rules(report)


def test_unclosed_frontmatter():
    report = analyse("---\nname: email-authentication-assessment\n")
    assert "FM001" in rules(report)


def test_nested_value_is_rejected_not_guessed():
    report = analyse("---\nname: x\ntools:\n  nested: 1\n---\n# x\n")
    assert "FM001" in rules(report)


def test_missing_required_key():
    report = analyse(build(drop_keys=("category",)))
    assert "FM002" in rules(report)


def test_empty_required_value():
    report = analyse(build(front_over={"description": ""}))
    assert "FM003" in rules(report)


def test_name_must_be_kebab_case():
    report = analyse(build(front_over={"name": "Email_Auth"}))
    assert "FM004" in rules(report)


def test_version_must_be_semver():
    report = analyse(build(front_over={"version": "1.0"}))
    assert "FM005" in rules(report)


def test_id_must_equal_name_at_version():
    report = analyse(build(front_over={"id": "something-else@1.0.0"}))
    assert "FM006" in rules(report)


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #


def test_missing_section():
    report = analyse(build(drop_sections=("M",)))
    assert "SEC001" in rules(report)


def test_wrong_section_title():
    report = analyse(build(titles={"C": "Background Reading"}))
    assert "SEC004" in rules(report)


def test_section_below_word_floor():
    report = analyse(build(bodies={"B": "too short"}))
    assert "SEC003" in rules(report)


def test_sections_out_of_order():
    order = [letter for letter, _, _ in SECTIONS]
    order[1], order[2] = order[2], order[1]
    report = analyse(build(order=order))
    assert "SEC002" in rules(report)


def test_duplicate_section():
    document = build() + "\n## A. Skill Metadata\n\nrepeat\n"
    report = analyse(document)
    assert "SEC002" in rules(report)


# --------------------------------------------------------------------------- #
# Hygiene
# --------------------------------------------------------------------------- #


def test_placeholder_marker_detected():
    report = analyse(build(append="TODO: finish the remediation section"))
    assert "TXT001" in rules(report)


def test_unclosed_code_fence():
    report = analyse(build(bodies={"C": _filler("C") + "\n```shell\necho hi\n"}))
    assert "TXT002" in rules(report)


def test_untagged_code_fence_is_a_warning():
    report = analyse(build(bodies={"C": _filler("C") + "\n```\nplain\n```\n"}))
    assert "TXT003" in rules(report)
    assert report.ok  # warnings do not fail the contract


def test_reference_count_floor():
    report = analyse(
        build(
            bodies={
                "P": "Two sources.\n\n- https://www.rfc-editor.org/rfc/rfc7208.html\n"
                "- https://www.rfc-editor.org/rfc/rfc6376.html\n"
            }
        )
    )
    assert "REF001" in rules(report)


def test_non_authoritative_reference_host_is_a_warning():
    urls = list(DEFAULT_URLS)
    urls[0] = "https://example.net/some-blog-post"
    report = analyse(build(bodies={"P": "Sources.\n\n" + "\n".join(f"- {u}" for u in urls)}))
    assert "REF002" in rules(report)


def test_safety_vocabulary_required():
    report = analyse(
        build(bodies={"K": "Authorization and scope are documented in the ticket reference."})
    )
    assert "SAF001" in rules(report)


def test_missing_h1():
    report = analyse(build(h1=None))
    assert "FM008" in rules(report)


def test_h1_should_contain_the_skill_name():
    report = analyse(build(h1="# Something Else Entirely"))
    assert "FM009" in rules(report)


# --------------------------------------------------------------------------- #
# Parser details
# --------------------------------------------------------------------------- #


def test_inline_list_parsed():
    frontmatter, _, error = split_frontmatter("---\ntools: [dig, openssl]\n---\nbody\n")
    assert error is None
    assert frontmatter == {"tools": ["dig", "openssl"]}


def test_block_list_parsed():
    frontmatter, _, error = split_frontmatter("---\ncwe:\n  - CWE-290\n  - CWE-345\n---\nbody\n")
    assert error is None
    assert frontmatter == {"cwe": ["CWE-290", "CWE-345"]}


def test_render_is_ascii_only():
    text = render_text(analyse(build()))
    assert text.isascii()
    assert "PASS" in text


def test_json_report_roundtrip():
    payload = json.loads(json.dumps(analyse(build()).as_dict()))
    assert payload["ok"] is True
    assert payload["errors"] == 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_exit_zero_on_valid(tmp_path, capsys):
    target = tmp_path / "SKILL.md"
    target.write_text(build(), encoding="utf-8")
    assert main(["check", str(target)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_cli_exit_one_on_invalid(tmp_path, capsys):
    target = tmp_path / "SKILL.md"
    target.write_text(build(drop_sections=("B",)), encoding="utf-8")
    assert main(["check", str(target)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_exit_two_on_missing_file(capsys):
    assert main(["check", "definitely-not-here.md"]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_json_is_parseable(tmp_path, capsys):
    target = tmp_path / "SKILL.md"
    target.write_text(build(), encoding="utf-8")
    assert main(["check", str(target), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert len(payload["sections"]) == len(SECTIONS)


# --------------------------------------------------------------------------- #
# The artifact this repository ships
# --------------------------------------------------------------------------- #


def test_shipped_skill_satisfies_the_contract():
    report = analyse((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8"), "SKILL.md")
    assert report.ok, [f"{f.rule}: {f.message}" for f in report.errors]
    assert not report.warnings, [f"{f.rule}: {f.message}" for f in report.warnings]
    assert report.total_words > 3000
