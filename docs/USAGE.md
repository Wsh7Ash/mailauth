# Usage

## Install

```shell
python -m pip install -e ".[dev]"
```

The checker has no runtime dependencies. `pip install` alone is enough; the
`dev` extra adds pytest.

## Check the skill

```shell
mailauth check SKILL.md
```

Output:

```text
skill: SKILL.md
  frontmatter   16/16 keys
  sections      16/16 present
  word floors   OK
  references    21 url(s)
  body words    7xxx
  code fences   N pair(s), 0 untagged

PASS: 0 error(s), 0 warning(s)
```

Exit codes: `0` no errors, `1` at least one error, `2` unreadable file or usage
error. Warnings never change the exit code; CI adds its own check when a project
wants to gate on them too.

## Machine-readable output

```shell
mailauth check SKILL.md --json > report.json
```

The JSON carries `ok`, per-section word counts and floors, the reference list, and
every finding with its rule id and line number.

## Per-section statistics

```shell
mailauth stats SKILL.md
```

```text
sec    words  floor  title
 A        78     20  Skill Metadata
 B       268    120  Executive Overview
 ...
```

A `!` before the letter marks a section below its floor.

## Rule reference

```shell
mailauth explain
```

## Use the checker on another skill

The checker is not specific to this document. Point it at any file that follows
the same A..P contract:

```shell
mailauth check path/to/other/SKILL.md
```

## Use the skill itself

`SKILL.md` is written to be executed by an agent. Read sections D (environment),
E (methodology) and K (safety) before running anything, and section J for the job
object the agent should accept. It requires authorization for the assessed domain;
the skill is a procedure, not a permission.
