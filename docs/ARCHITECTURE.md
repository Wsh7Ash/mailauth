# Architecture

## What this repository is

One artifact of substance: `SKILL.md` at the repository root. Everything else
exists to prove that artifact is complete, to explain it, or to record what was
actually run.

```
mailauth/
├─ SKILL.md                 the skill (frontmatter + sections A..P)
├─ src/mailauth_skill/      the contract checker
│  ├─ contract.py           parsing, rules, rendering
│  ├─ cli.py                check / stats / explain
│  └─ __main__.py           python -m entry point
├─ tests/test_contract.py   28 tests, one per rule plus integration
├─ examples/                synthetic zone and a sample aggregate report
├─ docs/                    architecture, usage, project spec
└─ results/                 captured checker output
```

## Why a checker exists

A long prose document degrades silently. A section gets trimmed to two lines
during an edit, a code fence loses its closing marker, a reference is replaced by
a bare hostname, and nothing fails. The checker turns those degradations into
non-zero exit codes with stable rule ids, so CI can refuse the change.

The check is deliberately structural. It answers "is every required part present
and substantive enough to be usable?" It cannot answer "is this command correct?"
— that is review, and section N of the skill says so plainly rather than implying
completeness the tool cannot provide.

## Data flow

```
SKILL.md ──split_frontmatter──> dict + body
                                   │
                 ┌─────────────────┼──────────────────┐
                 ▼                 ▼                  ▼
          heading scan       fence scan        reference scan
        (16 sections,      (balance and       (count, host
         order, floors)     language tags)     allowlist)
                 │                 │                  │
                 └─────────────────┴──────────────────┘
                                   ▼
                            Report(findings)
                                   │
                     exit 0 (no errors) / 1 (errors)
```

`analyse()` is a pure function over text. It performs no I/O, no DNS, and no
subprocess calls, which is why the test suite runs offline and deterministically.

## Frontmatter dialect

A deliberately small YAML subset: flat `key: value` pairs, inline lists
`[a, b]`, and block lists of `- item`. Nested mappings are rejected with `FM001`
rather than guessed at. A checker that half-parses YAML would report confidence it
does not have.

## Rule catalogue

| Rule | Level | Meaning |
|---|---|---|
| FM001 | error | frontmatter fence missing or malformed |
| FM002 | error | required key missing |
| FM003 | error | required key present but empty |
| FM004 | error | name is not lowercase kebab-case |
| FM005 | error | version is not semver |
| FM006 | error | id does not equal `name@version` |
| FM008 | error | no H1 title |
| FM009 | warning | H1 does not contain the skill name |
| SEC001 | error | required section missing |
| SEC002 | error | sections out of order or duplicated |
| SEC003 | error | section below its word floor |
| SEC004 | error | section title differs from the required title |
| TXT001 | error | placeholder marker in the body |
| TXT002 | error | unclosed code fence |
| TXT003 | warning | code fence without a language tag |
| REF001 | error | fewer than five reference URLs |
| REF002 | warning | reference host is not a primary source |
| SAF001 | error | section K lacks authorization/scope/stop vocabulary |

Word floors live in `contract.py` as data, next to the section list, so raising a
floor is a one-line change that the tests and CI immediately enforce.

## Extension points

- A different skill format: replace `SECTIONS` and `REQUIRED_FRONTMATTER`; the
  parser, renderer and CLI stay unchanged.
- A stricter policy: add ids to `RULE_CATALOGUE` and emit them from `analyse()`.
- CI gating on warnings: the workflow already does it with a two-line Python
  check, which is cheaper than adding a `--strict` flag nobody would remember.
