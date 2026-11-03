"""Structural contract for a single-file cybersecurity skill.

The contract is deliberately mechanical: it can prove that a skill file is
*complete enough to be usable* (every required section exists, every section
carries real prose, references point at authoritative sources, authorization
language is present). It cannot prove that a procedure is wise or that a command
is correct -- that is a review job, and the limitations section of the skill says so.

Frontmatter dialect
-------------------
A deliberately small YAML subset is parsed:

    ---
    name: email-authentication-assessment
    tools: [dig, openssl]
    cwe:
      - CWE-290
    ---

Scalars, inline lists (``[a, b]``) and block lists (``- item``) are supported.
Nested mappings and multi-line scalars are rejected rather than guessed at,
because a checker that half-understands YAML reports false confidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# --------------------------------------------------------------------------- #
# Contract constants
# --------------------------------------------------------------------------- #

REQUIRED_FRONTMATTER: tuple[str, ...] = (
    "name",
    "id",
    "version",
    "category",
    "domain",
    "description",
    "agent",
    "knowledge",
    "tools",
    "os",
    "permissions",
    "dependencies",
    "cwe",
    "owasp",
    "attack",
    "references",
)

#: (letter, title, minimum body words). Floors are set from what a section must
#: contain to be actionable, not from the length of any one example document.
SECTIONS: tuple[tuple[str, str, int], ...] = (
    ("A", "Skill Metadata", 20),
    ("B", "Executive Overview", 120),
    ("C", "Technical Foundations", 250),
    ("D", "Prerequisites and Environment", 150),
    ("E", "Detailed Operational Methodology", 400),
    ("F", "Practical Technical Examples", 250),
    ("G", "Tools and Commands", 200),
    ("H", "Vulnerability Discovery and Validation", 250),
    ("I", "Advanced Techniques", 200),
    ("J", "Automation and AI Agent Integration", 250),
    ("K", "Security, Authorization and Operational Safety", 200),
    ("L", "Reporting and Documentation", 150),
    ("M", "Troubleshooting and Edge Cases", 200),
    ("N", "Limitations and Known Issues", 120),
    ("O", "Quality Assurance Checklist", 100),
    ("P", "References", 30),
)

#: Hosts whose documents may be cited without a warning. Primary sources only:
#: RFCs, MITRE, NIST, OWASP and the upstream project of each named tool.
AUTHORITATIVE_HOSTS: tuple[str, ...] = (
    "www.rfc-editor.org",
    "datatracker.ietf.org",
    "www.ietf.org",
    "cwe.mitre.org",
    "attack.mitre.org",
    "owasp.org",
    "www.nist.gov",
    "nvlpubs.nist.gov",
    "csrc.nist.gov",
    "python.org",
    "docs.python.org",
    "www.openssl.org",
    "www.opendkim.org",
    "launchpad.net",
    "github.com",
    "dmarc.org",
    "www.m3aawg.org",
    "www.gnu.org",
    "man7.org",
    "www.knot-dns.cz",
    "learn.microsoft.com",
)

MIN_REFERENCES = 5

PLACEHOLDER_RE = re.compile(
    r"\b(?:TODO|TBD|FIXME|XXX)\b|<insert\b|<placeholder>|lorem ipsum",
    re.IGNORECASE,
)
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9'’./:@_+-]*")
HEADING_RE = re.compile(r"^##[ \t]+([A-P])\.?[ \t]+(.+?)[ \t]*$", re.MULTILINE)
URL_RE = re.compile(r"https?://[^\s<>()\[\]\"']+")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Finding:
    rule: str
    level: str  # "error" | "warning"
    message: str
    line: int | None = None

    def as_dict(self) -> dict:
        return {"rule": self.rule, "level": self.level, "message": self.message, "line": self.line}


@dataclass
class Section:
    letter: str
    title: str
    words: int
    floor: int
    body: str

    @property
    def ok(self) -> bool:
        return self.words >= self.floor


@dataclass
class Report:
    path: str
    frontmatter: dict[str, object] = field(default_factory=dict)
    sections: list[Section] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    fences: int = 0
    untagged_fences: int = 0
    references: list[str] = field(default_factory=list)
    total_words: int = 0

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "ok": self.ok,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "frontmatter_keys": len(self.frontmatter),
            "sections": [
                {"letter": s.letter, "title": s.title, "words": s.words, "floor": s.floor, "ok": s.ok}
                for s in self.sections
            ],
            "total_words": self.total_words,
            "code_fences": self.fences,
            "untagged_fences": self.untagged_fences,
            "references": self.references,
            "findings": [f.as_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def split_frontmatter(text: str) -> tuple[dict[str, object] | None, str, str | None]:
    """Return ``(frontmatter, body, error)`` for a document with ``---`` fenced YAML."""
    if not text.startswith("---"):
        return None, text, "document does not start with a '---' frontmatter fence"
    lines = text.splitlines()
    if lines[0].strip() != "---":
        return None, text, "first line is not exactly '---'"
    end = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            end = index
            break
    if end is None:
        return None, text, "frontmatter is not closed by a second '---' line"

    raw = lines[1:end]
    body = "\n".join(lines[end + 1 :])
    parsed: dict[str, object] = {}
    key: str | None = None
    for line in raw:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in " \t":
            stripped = line.strip()
            if not stripped.startswith("- "):
                return None, text, f"unsupported nested value under '{key}': {stripped!r}"
            if key is None:
                return None, text, "block list item without an owning key"
            current = parsed.setdefault(key, [])
            if not isinstance(current, list):
                return None, text, f"key '{key}' mixes scalar and list values"
            current.append(stripped[2:].strip().strip("'\""))
            continue
        if ":" not in line:
            return None, text, f"frontmatter line is not 'key: value': {line!r}"
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            return None, text, f"frontmatter line has an empty key: {line!r}"
        if value == "":
            parsed[key] = []  # a block list may follow
            continue
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            parsed[key] = [p.strip().strip("'\"") for p in inner.split(",")] if inner else []
        else:
            parsed[key] = value.strip("'\"")
    return parsed, body, None


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _count_words(text: str) -> int:
    return len(WORD_RE.findall(text))


def _scan_fences(body: str) -> tuple[int, int]:
    """Return ``(unclosed_openings, untagged_openings)``.

    Fences are counted by toggling: an opening fence carries an optional info
    string, the next fence line closes it. A document that ends inside a fence
    reports one unclosed opening.
    """
    in_fence = False
    untagged = 0
    for line in body.splitlines():
        if not line.startswith("```"):
            continue
        if in_fence:
            in_fence = False
            continue
        if not line[3:].strip():
            untagged += 1
        in_fence = True
    return (1 if in_fence else 0), untagged


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


def analyse(text: str, path: str = "<memory>") -> Report:
    report = Report(path=path)
    frontmatter, body, error = split_frontmatter(text)
    if error:
        report.findings.append(Finding("FM001", "error", error))
        return report
    assert frontmatter is not None
    report.frontmatter = frontmatter

    # ---- frontmatter rules -------------------------------------------------
    for key in REQUIRED_FRONTMATTER:
        if key not in frontmatter:
            report.findings.append(Finding("FM002", "error", f"required frontmatter key missing: {key}"))
            continue
        value = frontmatter[key]
        empty = (isinstance(value, str) and not value.strip()) or (
            isinstance(value, list) and not [v for v in value if str(v).strip()]
        )
        if empty:
            report.findings.append(Finding("FM003", "error", f"frontmatter key has no value: {key}"))

    name = str(frontmatter.get("name", "")).strip()
    version = str(frontmatter.get("version", "")).strip()
    identifier = str(frontmatter.get("id", "")).strip()

    if name and not KEBAB_RE.match(name):
        report.findings.append(Finding("FM004", "error", f"name is not lowercase kebab-case: {name!r}"))
    if version and not SEMVER_RE.match(version):
        report.findings.append(Finding("FM005", "error", f"version is not semver: {version!r}"))
    if identifier and name and version and identifier != f"{name}@{version}":
        report.findings.append(
            Finding(
                "FM006",
                "error",
                f"id must equal 'name@version' ({name}@{version}); found {identifier!r}",
            )
        )

    # ---- headings ----------------------------------------------------------
    matches = list(HEADING_RE.finditer(body))
    if not matches:
        report.findings.append(Finding("SEC001", "error", "no '## A. ...' style section headings found"))
    found: dict[str, tuple[str, str, int]] = {}
    seen_order: list[str] = []
    for match in matches:
        letter, title = match.group(1), match.group(2).strip()
        start = match.end()
        nxt = body.find("\n## ", start)
        section_body = body[start : nxt if nxt != -1 else len(body)]
        # Trim a trailing horizontal rule so it does not inflate the word count.
        section_body = re.sub(r"\n---\s*$", "\n", section_body)
        found[letter] = (title, section_body, _line_of(body, match.start()))
        seen_order.append(letter)

    expected = [entry[0] for entry in SECTIONS]
    for letter, title, floor in SECTIONS:
        if letter not in found:
            report.findings.append(Finding("SEC001", "error", f"required section missing: '{letter}. {title}'"))
            continue
        found_title, section_body, line = found[letter]
        if found_title.casefold() != title.casefold():
            report.findings.append(
                Finding(
                    "SEC004",
                    "error",
                    f"section {letter} title should be '{title}'; found {found_title!r}",
                    line,
                )
            )
        words = _count_words(section_body)
        section = Section(letter, found_title, words, floor, section_body)
        report.sections.append(section)
        if words < floor:
            report.findings.append(
                Finding(
                    "SEC003",
                    "error",
                    f"section {letter} has {words} words; the floor is {floor}",
                    line,
                )
            )

    known = [letter for letter in seen_order if letter in expected]
    if known != sorted(known, key=expected.index):
        report.findings.append(
            Finding("SEC002", "error", f"sections are not in A..P order: {''.join(seen_order)}")
        )
    if len(seen_order) != len(set(seen_order)):
        duplicates = sorted({l for l in seen_order if seen_order.count(l) > 1})
        report.findings.append(Finding("SEC002", "error", f"duplicate section letters: {duplicates}"))

    # ---- hygiene -----------------------------------------------------------
    for match in PLACEHOLDER_RE.finditer(body):
        report.findings.append(
            Finding(
                "TXT001",
                "error",
                f"placeholder marker in body: {match.group(0)!r}",
                _line_of(body, match.start()),
            )
        )

    unclosed, untagged = _scan_fences(body)
    report.fences = body.count("```") // 2
    report.untagged_fences = untagged
    if unclosed:
        report.findings.append(Finding("TXT002", "error", f"{unclosed} code fence(s) are never closed"))
    if untagged:
        report.findings.append(
            Finding("TXT003", "warning", f"{untagged} code fence(s) have no language tag")
        )

    # ---- references --------------------------------------------------------
    references_section = next((s for s in report.sections if s.letter == "P"), None)
    if references_section is not None:
        report.references = URL_RE.findall(references_section.body)
        if len(report.references) < MIN_REFERENCES:
            report.findings.append(
                Finding(
                    "REF001",
                    "error",
                    f"section P cites {len(report.references)} URL(s); at least {MIN_REFERENCES} are required",
                )
            )
        for url in report.references:
            host = url.split("//", 1)[-1].split("/", 1)[0].lower()
            if host not in AUTHORITATIVE_HOSTS:
                report.findings.append(
                    Finding("REF002", "warning", f"reference host is not on the authoritative list: {host}")
                )

    # ---- safety language ---------------------------------------------------
    safety = next((s for s in report.sections if s.letter == "K"), None)
    if safety is not None:
        lowered = safety.body.casefold()
        required_terms = ("authoriz", "scope", "stop")
        missing = [t for t in required_terms if t not in lowered]
        if missing:
            report.findings.append(
                Finding("SAF001", "error", f"section K lacks required safety vocabulary: {missing}")
            )

    # ---- title -------------------------------------------------------------
    headings = [line for line in body.splitlines() if line.startswith("# ")]
    if not headings:
        report.findings.append(Finding("FM008", "error", "document has no H1 title"))
    elif name and name.replace("-", "") not in headings[0].casefold().replace("-", "").replace(" ", ""):
        report.findings.append(
            Finding("FM009", "warning", f"H1 does not contain the skill name {name!r}: {headings[0]!r}")
        )

    report.total_words = _count_words(body)
    return report


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_text(report: Report) -> str:
    """Render a report as ASCII-only console text (cp1252-safe)."""
    lines: list[str] = []
    lines.append(f"skill: {report.path}")
    keys = len(report.frontmatter)
    required = len(REQUIRED_FRONTMATTER)
    lines.append(f"  frontmatter   {keys}/{required} keys")
    lines.append(f"  sections      {len(report.sections)}/{len(SECTIONS)} present")
    floor_failures = [s for s in report.sections if not s.ok]
    lines.append(f"  word floors   {'OK' if not floor_failures else f'{len(floor_failures)} below floor'}")
    lines.append(f"  references    {len(report.references)} url(s)")
    lines.append(f"  body words    {report.total_words}")
    lines.append(f"  code fences   {report.fences} pair(s), {report.untagged_fences} untagged")
    if report.findings:
        lines.append("")
        lines.append("findings")
        for finding in report.findings:
            location = f" line {finding.line}" if finding.line else ""
            lines.append(f"  [{finding.level}] {finding.rule}{location}: {finding.message}")
    lines.append("")
    lines.append(
        f"{'PASS' if report.ok else 'FAIL'}: {len(report.errors)} error(s), {len(report.warnings)} warning(s)"
    )
    return "\n".join(lines)


def section_table(text: str) -> list[dict[str, object]]:
    """Word counts per section for ``stats``."""
    report = analyse(text)
    return [
        {"letter": s.letter, "title": s.title, "words": s.words, "floor": s.floor, "ok": s.ok}
        for s in report.sections
    ]


def iter_rules() -> Iterable[tuple[str, str]]:
    return RULE_CATALOGUE.items()


RULE_CATALOGUE: dict[str, str] = {
    "FM001": "frontmatter fence missing or malformed",
    "FM002": "required frontmatter key missing",
    "FM003": "required frontmatter key present but empty",
    "FM004": "name is not lowercase kebab-case",
    "FM005": "version is not semver (MAJOR.MINOR.PATCH)",
    "FM006": "id does not equal 'name@version'",
    "FM008": "document has no H1 title",
    "FM009": "H1 does not contain the skill name (warning)",
    "SEC001": "required A..P section missing",
    "SEC002": "sections out of order or duplicated",
    "SEC003": "section below its word floor",
    "SEC004": "section title differs from the required title",
    "TXT001": "placeholder marker (TODO/TBD/FIXME/...) in the body",
    "TXT002": "unclosed code fence",
    "TXT003": "code fence without a language tag (warning)",
    "REF001": "fewer than five reference URLs in section P",
    "REF002": "reference host is not an authoritative primary source (warning)",
    "SAF001": "section K lacks authorization/scope/stop vocabulary",
}


def load(path: str | Path) -> Report:
    text = Path(path).read_text(encoding="utf-8")
    return analyse(text, str(path))


def to_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, ensure_ascii=True)
