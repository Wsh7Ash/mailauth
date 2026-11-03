# Project spec

## Name

mailauth — Email Authentication Assessment

## Category

`email-security`

## Target user

A security engineer or mail administrator who has to answer, with evidence,
whether their organization's domains can be impersonated, and who has to sequence
the fix without breaking transactional or marketing mail.

## Problem

The published records (SPF, DKIM, DMARC) are individually easy to read and
collectively easy to misjudge. A domain can have all three and still be spoofable:
`p=none`, `pct=10`, `sp=none`, an SPF record over the ten-term budget, or a DKIM
key that no flow actually uses. The failure is silent because nothing errors; the
domain simply keeps accepting unauthenticated mail.

## Solution

One skill file that fixes the reasoning order: inventory flows, retrieve exact
records, account SPF's DNS budget, inventory selectors and decode keys, read the
policy and test whether alignment is achievable, then — only with authorization —
observe one receiver verdict. Findings are classified into five shapes with
different fixes, and remediation is sequenced monitoring before enforcement.

## Core workflow

1. Record authorization and scope.
2. Inventory domains and sending flows.
3. Retrieve SPF, parse it, account the term budget.
4. Inventory DKIM selectors; decode and size keys.
5. Read DMARC policy; judge alignment against real flows.
6. Optional: one controlled message per flow; read `Authentication-Results`.
7. Optional: parse aggregate reports for unknown sources.
8. Classify, grade, sequence remediation.
9. Verify after change.

## Must-have features

- Exact record retrieval including multi-string TXT framing.
- SPF term accounting that names the vendor subtree responsible.
- DKIM key size/algorithm decoded rather than inferred.
- DMARC policy read including `pct`, `sp`, `adkim`, `aspf`.
- Classification into the five shapes, each with its own fix.
- Authorization boundary, stop conditions, evidence redaction.
- A structural checker so the document cannot silently rot.

## Nice-to-have (deliberately not built)

- A live DNS client in the package. The skill uses `dig`; adding a resolver would
  make the checker network-dependent and its tests non-deterministic.
- Aggregate-report ingestion. `parsedmarc` already does this well.
- Record generation or a DMARC record builder. That is configuration management,
  a different skill.

## Stack

Python 3.10+ standard library only; pytest for tests; GitHub Actions for CI.

## Test strategy

One test per rule, each mutating exactly one aspect of a synthetically valid
document, plus an integration test that runs the checker against the shipped
`SKILL.md` and asserts zero findings of either level. The integration test is the
proof that the deliverable meets its own contract.

## Demo strategy

`mailauth check SKILL.md` and `mailauth stats SKILL.md`, with output captured into
`results/`. No screenshots, because the artifact is text and a terminal transcript
is more verifiable than an image.

## Safety considerations

The skill's subject is email impersonation, so the boundary has to be explicit:
only domains named in a written authorization, no spoofed sends, no mail to
unconsenting recipients, bounded test-message count, redacted evidence, and stop
conditions that end the run rather than escalate it.

## Definition of done

- `mailauth check SKILL.md` exits 0 with zero errors and zero warnings.
- `pytest` passes.
- README, docs, RESULTS.md and the daily report describe only observed output.
- No secrets, no credentials, no personal data in the tree.
- Published to GitHub with the default branch verified.
