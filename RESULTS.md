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
| unit tests | PASS — 34 collected, 34 passed |
| integration test (shipped SKILL.md against its own contract) | PASS — 0 errors, 0 warnings |
| second skill, unrelated domain, same checker | PASS — 0 errors, 0 warnings, no per-domain code |
| third skill, unrelated domain, same checker | PASS — 0 errors, 0 warnings, no per-domain code |
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
  code fences   35 pair(s), 0 untagged

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
..................................                                       [100%]
34 passed
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
  for both shapes;  `TXT002` and `TXT003` are asserted independently.
- While adding the second skill, the console line for code fences was found to
  report half the true count: `render_text` divided `report.fences` — already a
  pair count — by two again, so a document with 35 pairs printed `17 pair(s)`.
  Fixed to print the value `analyse` computes. No test had asserted the rendered
  number, which is why it survived the first build; the regenerated
  `results/check.txt` now shows the correct figure.

## Second skill (reusability check)

Added after the first build, with one purpose: show that the checker enforces a
contract rather than one document's shape. The document is
`examples/skills/http-desync-smuggling-assessment/SKILL.md` — HTTP request
smuggling, which shares no vocabulary, no CWE, no tools and no references with the
email-authentication skill.

```shell
PYTHONPATH=src python -m mailauth_skill.cli check \
  examples/skills/http-desync-smuggling-assessment/SKILL.md
PYTHONPATH=src python -m mailauth_skill.cli stats \
  examples/skills/http-desync-smuggling-assessment/SKILL.md
```

Observed, exit code 0:

```text
skill: examples/skills/http-desync-smuggling-assessment/SKILL.md
  frontmatter   16/16 keys
  sections      16/16 present
  word floors   OK
  references    13 url(s)
  body words    7124
  code fences   9 pair(s), 0 untagged

PASS: 0 error(s), 0 warning(s)
```

Per-section words against floors (smallest margin is section O at 114 words
against a floor of 100):

```text
sec   words  floor  title
 A      133     20  Skill Metadata
 B      432    120  Executive Overview
 C     1202    250  Technical Foundations
 D      550    150  Prerequisites and Environment
 E     1294    400  Detailed Operational Methodology
 F      506    250  Practical Technical Examples
 G      254    200  Tools and Commands
 H      589    250  Vulnerability Discovery and Validation
 I      446    200  Advanced Techniques
 J      368    250  Automation and AI Agent Integration
 K      313    200  Security, Authorization and Operational Safety
 L      187    150  Reporting and Documentation
 M      357    200  Troubleshooting and Edge Cases
 N      180    120  Limitations and Known Issues
 O      114    100  Quality Assurance Checklist
 P       94     30  References
```

What this does and does not show: it shows that no rule is keyed to email
semantics, because every rule fired identically on a document with different
frontmatter values. It does not show that the floors are right for every possible
skill; a section that legitimately needs fewer words would need the floor
reconsidered rather than the prose padded.

## Third skill (contract, not convention)

`examples/skills/dns-resolver-security-assessment/SKILL.md` — DNS resolver
security, a third category with no overlap in vocabulary, CWE, tools or
references with either earlier document. Same binary, same rules:

```shell
PYTHONPATH=src python -m mailauth_skill.cli check \
  examples/skills/dns-resolver-security-assessment/SKILL.md
PYTHONPATH=src python -m mailauth_skill.cli stats \
  examples/skills/dns-resolver-security-assessment/SKILL.md
```

Observed, exit code 0:

```text
skill: examples/skills/dns-resolver-security-assessment/SKILL.md
  frontmatter   16/16 keys
  sections      16/16 present
  word floors   OK
  references    15 url(s)
  body words    7096
  code fences   6 pair(s), 0 untagged

PASS: 0 error(s), 0 warning(s)
```

Per-section words against floors (smallest margin is section O at 120 against a
floor of 100, then section L at 160 against 150):

```text
sec   words  floor  title
 A      195     20  Skill Metadata
 B      632    120  Executive Overview
 C     1149    250  Technical Foundations
 D      536    150  Prerequisites and Environment
 E     1146    400  Detailed Operational Methodology
 F      431    250  Practical Technical Examples
 G      268    200  Tools and Commands
 H      556    250  Vulnerability Discovery and Validation
 I      522    200  Advanced Techniques
 J      329    250  Automation and AI Agent Integration
 K      313    200  Security, Authorization and Operational Safety
 L      160    150  Reporting and Documentation
 M      325    200  Troubleshooting and Edge Cases
 N      184    120  Limitations and Known Issues
 O      120    100  Quality Assurance Checklist
 P      125     30  References
```

Patience with floors: two of the three documents were first rejected for a single
section a few words under its floor (section G at 188 and 190 words against 200).
Both times the fix was to write the missing substance — version pinning, transcript
hygiene — not to lower the floor. That is the behaviour the floors are there to
force, and it is evidence the rule is doing work rather than decorating the file.

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
