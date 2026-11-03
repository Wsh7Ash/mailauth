# Changelog

All notable changes to this repository are recorded here. The skill document and
the checker share a version number because the contract they implement is one
artifact.

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
