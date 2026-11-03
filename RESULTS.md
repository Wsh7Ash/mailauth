# Results

Every number below comes from a command run on the machine that produced this
repository. Nothing here is projected or estimated.

## Environment

- OS: Windows (win32), Git Bash for the shell commands
- Runtime: Python 3.14.3
- Dependency manager: pip (the package itself declares no runtime dependencies)
- Git: 2.55.0.windows.3
- Checker entry point: `python -m mailauth_skill.cli` with `PYTHONPATH=src`

## Validation performed

| Gate | Result |
|---|---|
| install (runtime dependencies) | N/A — the package has none; tests run from the source tree |
| build (wheel/sdist) | N/A — pure-Python package, no compile step |
| unit tests | PASS — 31 collected, 31 passed |
| integration test (shipped SKILL.md against its own contract) | PASS — 0 errors, 0 warnings |
| lint | N/A — no linter configured for this repository |
| type check | N/A — no type checker configured |
| demo run (`check`, `stats`, `explain`) | PASS |
| secret scan | PASS — no credential-shaped assignment in the tree |

## Commands executed

```shell
cd projects/2026-11-03/mailauth

PYTHONPATH=src python -m mailauth_skill.cli check SKILL.md
PYTHONPATH=src python -m mailauth_skill.cli check SKILL.md --json > results/check.json
PYTHONPATH=src python -m mailauth_skill.cli stats SKILL.md > results/stats.txt
PYTHONPATH=src python -m mailauth_skill.cli explain  > results/rules.txt

PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m pytest --collect-only -q

grep -rInE "(api[_-]?key|secret|passwd|password|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]+" \
  --include="*.py" --include="*.md" --include="*.txt" --include="*.yml" .
```

## Observed result

`check` on the shipped skill, exit code 0:

```text
skill: SKILL.md
  frontmatter   16/16 keys
  sections      16/16 present
  word floors   OK
  references    19 url(s)
  body words    9251
  code fences   17 pair(s), 0 untagged

PASS: 0 error(s), 0 warning(s)
```

`stats`, section word counts against their floors (all 16 above floor; smallest
margin is section O at 146 words against a floor of 100):

```text
sec   words  floor  title
 A      174     20  Skill Metadata
 B      310    120  Executive Overview
 C     1088    250  Technical Foundations
 D      298    150  Prerequisites and Environment
 E     1977    400  Detailed Operational Methodology
 F      812    250  Practical Technical Examples
 G      881    200  Tools and Commands
 H      642    250  Vulnerability Discovery and Validation
 I      460    200  Advanced Techniques
 J      587    250  Automation and AI Agent Integration
 K      596    200  Security, Authorization and Operational Safety
 L      305    150  Reporting and Documentation
 M      518    200  Troubleshooting and Edge Cases
 N      209    120  Limitations and Known Issues
 O      146     100  Quality Assurance Checklist
 P      139     30  References
```

`pytest`:

```text
...............................                                          [100%]
tests/test_contract.py: 31
```

Secret scan: no matches. The grep is shown above so a reader can re-run exactly
the pattern that was used rather than trusting the word "clean".

## Defects found and fixed during the build

- The first test run failed six tests. The cause was in the fixture builder, not
  the checker: the synthesised section K held 60 words against a floor of 200 and
  section P held 8 words against a floor of 30, so the "valid" document was not
  valid and every test built on it failed. The fixture was corrected; the floors
  were not lowered to accommodate it.
- One test asserted a JSON round-trip through `repr()` string substitution, which
  is not JSON. It was rewritten to use `json.dumps`/`json.loads`. The test was
  wrong, not the implementation.
- The code-fence scanner originally popped only tagged openings, so an untagged
  fence was counted as two unclosed fences. It now toggles state, which is correct
  for both shapes; `TXT002` and `TXT003` are asserted independently.

## Generated artifacts

- `results/check.txt` — human-readable checker output
- `results/check.json` — machine-readable report (status, per-section counts, findings)
- `results/stats.txt` — per-section word counts
- `results/rules.txt` — rule catalogue as printed by `explain`

## Not performed, and why

- The skill's own procedure was **not** executed against any domain. This
  repository ships a document and a checker; no DNS query or mail send was part of
  building it, and no authorization exists for such a test from this workspace.
  The procedure's commands are taken from the cited RFCs and the documented
  behaviour of the named tools, which is stated in section N of the skill.
- No wheel or sdist was built, because there is no code path that requires one.
- No linter or type checker was run, because none is configured.
