# Security policy

## Scope of this repository

This repository contains a document (`SKILL.md`) and a structural checker. It
ships no network client, sends no mail, performs no DNS resolution, and has no
runtime dependencies. Running `mailauth check` reads one file.

## Authorized use

The skill describes assessing whether a mail domain can be impersonated. That
work requires written authorization from the domain owner. Nothing in this
repository grants it, and the skill's section K states the boundary explicitly:

- only domains named in a current authorization are in scope;
- no message may be sent claiming a domain you do not own, even to yourself;
- no test mail to recipients who have not agreed;
- bounded test-message count, redacted evidence, and defined stop conditions.

If you intend to use the procedure, obtain authorization first and keep the
record with your evidence.

## Reporting a problem in this repository

Open an issue describing the defect in the checker (a rule that fires when it
should not, or fails to fire when it should) or in the document (a command that
does not do what the surrounding text says). Include the input that reproduces
it and the version from `mailauth --help`.

Do not include credentials, mailbox contents, or live DNS data from domains you
do not own in a public issue.

## Handling of evidence produced with this skill

Assessments produce DNS answers (public), receiver verdict headers (may contain
addresses), and aggregate reports (contain source IPs, which are personal data in
many jurisdictions). Store counts and classifications rather than raw dumps, and
redact addresses to role labels before sharing.
