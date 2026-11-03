# Contributing

## What is worth changing

1. **A wrong command in `SKILL.md`.** This is the most valuable contribution.
   Cite the tool version, the exact command, and the output you got instead.
   Update the surrounding interpretation if the output changes the reading.
2. **A new rule in the checker.** Add the id to `RULE_CATALOGUE`, emit it from
   `analyse()`, add one test that builds a document violating it, and add a row
   to the table in `docs/ARCHITECTURE.md`.
3. **A cleared false positive.** If a rule fires on a legitimate document, add
   the document shape as a test first, then narrow the rule.

## What is not wanted

- Longer prose with no new technical content. Word floors exist to stop sections
  being stubs, not to reward padding.
- Live network calls in the package or the tests. The checker is offline by
  design; a test that resolves DNS is a test that fails on a plane.
- New dependencies. There are none, and the reason is auditability.
- Records or tooling that help someone impersonate a domain they do not own.

## Local workflow

```shell
python -m pip install -e ".[dev]"
mailauth check SKILL.md
mailauth stats SKILL.md
python -m pytest -q
```

All four must pass before a pull request. CI runs the same commands on Python
3.11 and 3.12, plus a check that fails on warnings as well as errors.

## Editing the skill

- Keep the frontmatter flat; the parser rejects nesting on purpose.
- Keep section titles exactly as they are; `SEC004` enforces them.
- Keep the identifier in sync with `name@version`; `FM006` enforces it.
- Bump `version` and `id` together, and add a `CHANGELOG.md` entry.
- Tag every code fence with a language. Untagged fences are a warning today and
  will be an error when the policy tightens.

## Commit messages

State the change and the reason: `Narrow REF002 to primary-source hosts; the old
list warned on project documentation that the skill cites deliberately`.
