# mailauth

One production-grade skill that answers a single question with evidence: **can
anyone send mail as this domain, and what is the smallest change that stops them?**

`SKILL.md` is the deliverable. It is a complete, independently usable procedure
for authorized assessment of SPF, DKIM and DMARC, written to the A..P skill
standard: metadata, foundations, environment, methodology, worked examples, tools,
validation, automation contract, safety boundary, reporting, troubleshooting,
limitations and references. The repository also ships a checker that proves the
document meets that standard, so future edits cannot quietly hollow it out.

## The problem

Every mailbox provider publishes what it thinks of a domain's mail in an
`Authentication-Results` header, and every domain owner can publish three records
that decide the answer. Reading those records is easy; judging them is not. The
common failures are all silent:

- `p=none` looks like DMARC and blocks nothing.
- `pct=10` enforces on one message in ten.
- `sp=none` leaves every sending subdomain unprotected.
- An SPF record inside the ten-query budget today returns `permerror` the day the
  next vendor is added — and receivers treat `permerror` as no authorization.
- DKIM authenticates a domain, and DMARC alignment is a separate configuration
  step that a correct-looking setup can miss entirely.

The result is a domain that "has SPF, DKIM and DMARC" and still accepts
unauthenticated mail with its own name in `From:`.

## What the skill does

| Phase | Output |
|---|---|
| Scope and authorization record | a written boundary before the first query |
| Domain and flow inventory | every From-domain that sends mail |
| SPF retrieval and term accounting | whether the record evaluates inside RFC 7208's limits |
| DKIM selector and key inventory | decoded key size, revoked and dangling selectors |
| DMARC policy and alignment analysis | whether a pass is even achievable |
| One controlled message per flow | the receiving stack's own verdict |
| Aggregate report review | sources that failed while the policy let them through |
| Classification and remediation | five defect shapes, sequenced monitoring → enforcement |

## Representative output

Real output from this repository, produced by `mailauth check SKILL.md`:

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

Per-section word counts from `mailauth stats SKILL.md`:

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
 O      146    100  Quality Assurance Checklist
 P      139     30  References
```

## Quick start

```shell
git clone https://github.com/Wsh7Ash/mailauth
cd mailauth
python -m pip install -e ".[dev]"

mailauth check SKILL.md     # exit 0, zero findings
mailauth stats SKILL.md     # per-section word counts
mailauth explain            # rule catalogue
python -m pytest -q         # 31 tests
```

Then read `SKILL.md` itself: section D for the environment, section E for the
methodology, section K before running anything against a real domain.

## The checker

`mailauth` validates any document written to the same A..P contract:

- **FM001–FM009** — frontmatter fence, sixteen required keys, kebab-case name,
  semver version, `id == name@version`, H1 presence and name agreement.
- **SEC001–SEC004** — all sixteen sections present, in order, not duplicated,
  with the exact required titles, each above a per-section word floor.
- **TXT001–TXT003** — no placeholder markers, no unclosed code fences, every fence
  language-tagged.
- **REF001–REF002** — at least five references, all on primary-source hosts.
- **SAF001** — section K actually contains authorization, scope and stop-condition
  language.

Exit codes: `0` clean, `1` at least one error, `2` unreadable input. `--json`
emits the full report for CI. There are no runtime dependencies and no network
calls: the checker reads one file.

## Architecture

```
SKILL.md ──split_frontmatter──> metadata + body
                                   │
             heading scan ─────────┼───────── fence scan
             (16 sections,         │          (balance, language tags)
              order, floors)       │
                                   └───────── reference scan
                                              (count, host allowlist)
                                   ▼
                            Report(findings) ──> exit 0 / 1
```

`analyse()` is a pure function over text, which is why the suite runs offline and
deterministically. Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- Python 3.10 or newer (standard library only for the package).
- pytest for the test suite.
- To *use* the skill: `dig` or `kdig`, `openssl`, and — only if a receiver verdict
  is needed — `swaks`. Optional: `checkdmarc`, `dkimverify`, `opendkim-testkey`,
  `parsedmarc`.

## Testing

```shell
python -m pytest -q
```

31 tests: one per rule, each mutating exactly one aspect of a synthetically valid
document, plus an integration test that runs the checker against the shipped
`SKILL.md` and asserts zero findings of either level. That integration test is the
proof that the deliverable satisfies its own contract.

## Project structure

```
mailauth/
├─ SKILL.md                 the skill: frontmatter + sections A..P
├─ src/mailauth_skill/
│  ├─ contract.py           parsing, rules, rendering
│  └─ cli.py                check / stats / explain
├─ tests/test_contract.py   31 tests
├─ examples/                synthetic zone and aggregate report
├─ docs/                    ARCHITECTURE, USAGE, PROJECT_SPEC
├─ results/                 captured checker output
├─ RESULTS.md               what was actually executed
└─ SECURITY.md              authorized-use boundary
```

## Configuration

None. There is no config file, no environment variable and no credential. The
skill's own job object (section J) is the only input contract, and it is passed by
whatever runtime invokes the agent.

## Limitations

- The checker validates structure, not correctness. A skill can be structurally
  perfect and still contain a wrong command; only review and execution catch that.
- The skill establishes configuration-level spoofability. It does not observe
  delivery, because delivery also depends on receiver reputation and filtering.
- DMARC semantics follow RFC 7489; the specification has an active revision
  process, and a receiver implementing a newer draft can differ at the margins.
- SPF term counts depend on the resolver seeing the same records the receiver sees;
  split-horizon DNS makes any static count evidence about the record, not about
  every receiver.

## Roadmap

Only what is genuinely next:

- A `--strict` mode that fails on warnings, replacing the two-line Python check in
  CI today.
- A second example skill written to the same contract, to prove the checker is
  reusable rather than bespoke.
- Optional parsing of a stored aggregate report to demonstrate section E phase 7
  against the fixture in `examples/`.

## Security

This repository sends no mail, resolves no DNS and stores no credentials. The
skill it documents requires written authorization for the assessed domain. Read
[SECURITY.md](SECURITY.md) before using the procedure on real infrastructure.

## License

MIT. See [LICENSE](LICENSE).
