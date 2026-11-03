# Changelog

All notable changes to this repository are recorded here. The skill document and
the checker share a version number because the contract they implement is one
artifact.

## [Unreleased]

### Added

- `examples/skills/http-desync-smuggling-assessment/SKILL.md`: a second skill in an
  unrelated domain, written to the same A..P contract, to show that the checker
  enforces a contract rather than one document's shape.
- `examples/skills/dns-resolver-security-assessment/SKILL.md`: a third skill, DNS
  resolver security, in a third category with no overlap in CWE, tooling or
  references with either earlier document.
- A parametrised integration test covering all three shipped skills, and a test
  asserting the contract is not bespoke to any one domain.
- Captured output for the second skill in `results/check-second-skill.txt` and
  `results/stats-second-skill.txt`, and for the third in
  `results/check-third-skill.txt` and `results/stats-third-skill.txt`.

### Fixed

- The console summary reported half the true number of code fence pairs, because
  `render_text` divided an already-halved count by two again.

## [1.0.0] - 2026-11-03

### Added

- `SKILL.md`: a complete email authentication assessment skill with the sixteen
  required sections, covering SPF retrieval and term accounting, DKIM selector and
  key verification, DMARC policy and alignment analysis, controlled empirical
  testing, aggregate report review, staged remediation, and the authorization
  boundary.
- `mailauth` CLI with `check`, `stats` and `explain`.
- Contract checker enforcing sixteen frontmatter keys, sixteen ordered sections
  with word floors, placeholder and code-fence hygiene, authoritative reference
  hosts, and the safety vocabulary in section K.
- Test suite: one test per rule plus an integration test that checks the shipped
  skill against its own contract.
- Synthetic fixtures: a zone file with deliberately awkward records and a
  hand-written DMARC aggregate report.
- GitHub Actions CI on Python 3.11 and 3.12, gating on warnings as well as errors.
