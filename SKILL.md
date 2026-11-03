---
name: email-authentication-assessment
id: email-authentication-assessment@1.0.0
version: 1.0.0
category: email-security
domain: internet mail authentication (SPF, DKIM, DMARC, ARC)
description: Determine whether a domain's SPF, DKIM and DMARC configuration actually prevents unauthenticated use of its From domain, then produce reproducible evidence and a staged remediation plan.
agent: coding or security agent with shell access and working DNS resolution, operating under written authorization for the assessed domain
knowledge:
  - SMTP envelope identities versus message header identities (RFC 5321, RFC 5322)
  - the SPF check_host evaluation model and its DNS term budget (RFC 7208)
  - DKIM canonicalization, selector keys and algorithm constraints (RFC 6376, RFC 8301)
  - DMARC alignment, policy discovery and aggregate reporting (RFC 7489)
  - ARC chain validation for forwarded mail (RFC 8617)
tools: [dig, kdig, delv, nslookup, openssl, python3, swaks, opendkim-testkey, dkimverify, checkdmarc, parsedmarc]
os: [linux, macos, windows]
permissions:
  - outbound DNS resolution
  - read access to the domain's DNS zone or provider API (preferred over live queries)
  - authorization to send test mail from the assessed domain to a mailbox the tester controls
dependencies:
  - bind9-dnsutils or knot-dnsutils for dig and kdig
  - openssl 1.1.1 or 3.x
  - python 3.10 or newer
cwe: [CWE-290, CWE-345, CWE-347, CWE-287]
owasp: [OWASP Top 10 2021 A07 Identification and Authentication Failures]
attack: [T1566, T1566.001, T1566.002, T1656, T1585.002]
references: [RFC 7208, RFC 6376, RFC 8301, RFC 7489, RFC 8617, RFC 8601]
---

# Email Authentication Assessment (SPF, DKIM, DMARC)

A single-file skill: assess whether a mail domain's published authentication policy
would actually stop an unauthenticated sender from using that domain in the `From:`
header, and produce evidence a receiving operator or the domain owner can act on.

## A. Skill Metadata

| Field | Value |
|---|---|
| Skill name | Email Authentication Assessment |
| Identifier | `email-authentication-assessment@1.0.0` |
| Version | 1.0.0 |
| Category | `email-security` |
| Domain | Internet mail authentication: SPF, DKIM, DMARC, ARC |
| Intended agent | A coding or security agent with shell access, DNS resolution, and written authorization for the assessed domain |
| Required knowledge | SMTP envelope vs header identity, SPF evaluation, DKIM signing and canonicalization, DMARC alignment and reporting, DNS basics |
| Required tools | `dig` or `kdig`, `openssl`, `python3`; optionally `swaks`, `opendkim-testkey`, `dkimverify`, `checkdmarc`, `parsedmarc` |
| OS compatibility | Linux, macOS, Windows (Git Bash or WSL for the shell examples) |
| Permissions | Outbound DNS; authorization to send test mail from the assessed domain to a mailbox you control |
| Dependencies | Standard-library Python 3.10+ for the bundled checker; no runtime third-party packages |
| CWE | CWE-290, CWE-345, CWE-347, CWE-287 |
| OWASP | OWASP Top 10 2021 A07 (identification and authentication failures) |
| MITRE ATT&CK | T1566, T1566.001, T1566.002, T1656, T1585.002 |
| Reference documentation | See section P |

The YAML frontmatter above is the machine-readable source of truth. The table
repeats it for readers who receive the file without a frontmatter-aware tool.
The bundled checker (`mailauth check SKILL.md`) enforces both.

## B. Executive Overview

SPF, DKIM and DMARC answer three different questions, and a domain only resists
impersonation when all three answers agree. SPF asks whether the connecting host
was authorized to use the envelope sender. DKIM asks whether a cryptographic
signature over selected headers and the body is valid for a stated signing
domain. DMARC is the only one of the three that binds either result to the
`From:` header a human actually sees, and it is the only one that tells a
receiver what to do when neither result aligns.

Most real-world failures are not exotic. They are a record that silently exceeds
SPF's ten-query budget, a DKIM key that was rotated without the old selector
staying published, a DMARC record at `p=none` that everyone believes is
enforcement, or an ESP whose envelope domain never aligned with the From domain
so the domain has never once passed DMARC on its own mail. Each of these produces
the same business outcome: a third party can send mail that a recipient's client
displays as the organization's own domain.

The agent's goal is narrower than "improve email security". It is to establish,
with reproducible evidence, whether an unauthenticated sender can use the
assessed domain in `From:` today, why not or why so, and what the smallest
staged change is that closes the gap without breaking legitimate mail flows.

In scope: record retrieval and parsing, SPF term accounting, DKIM selector and
key inventory from mail you are authorized to inspect, DMARC policy and
alignment analysis, aggregate-report review, controlled send tests, evidence
collection, and remediation sequencing.

Out of scope: sending mail that impersonates a domain you do not own, testing
third-party domains without authorization, content filtering or spam scoring,
mailbox compromise investigation, and deliverability tuning that is not about
authentication. This skill does not authorize any action; section K defines the
boundary that must already exist.

## C. Technical Foundations

### Two identities per message

A message carries an envelope identity and a header identity, and they are not
required to match. The envelope is what SMTP negotiates (RFC 5321): `MAIL FROM`
becomes the return-path, and the sending host names itself in `EHLO`. The header
block is what the recipient's client renders (RFC 5322): `From:`, `Reply-To:`,
`Subject:`. SPF authenticates the envelope. DMARC compares the authenticated
envelope domain against the header `From:` domain. That comparison, called
alignment, is the entire reason DMARC exists.

### SPF: an authorized-sender list evaluated by the receiver

The domain owner publishes one TXT record beginning `v=spf1` at the domain name.
Receivers evaluate it with `check_host()` (RFC 7208 section 4). Mechanisms are
evaluated left to right and the first match decides the result:

```text
all        matches any sender
include:   recursively evaluates another domain's SPF record
a          matches if the sender IP is in the domain's A/AAAA records
mx         matches if the sender IP is in the domain's MX records
ptr        reverse-DNS check; deprecated by RFC 7208 and counted as a query
ip4:       literal IPv4 address or CIDR
ip6:       literal IPv6 address or CIDR
exists:    matches if a constructed name resolves to any A record
```

Each mechanism may carry a qualifier: `+` pass (default), `-` fail, `~` softfail,
`?` neutral. Modifiers `redirect=` and `exp=` change control flow and explanation
text; unknown modifiers are ignored. Results are `none`, `neutral`, `pass`,
`fail`, `softfail`, `temperror`, `permerror`.

Three hard budgets make SPF fragile in practice, all in RFC 7208 section 4.6.4:
at most **10 DNS-querying terms** per evaluation (`include`, `a`, `mx`, `ptr`,
`exists`, and `redirect` each consume budget), at most **2 void lookups** (a
query that returns no answer), and at most **10 address records** for `a` and
`mx`. Exceeding any of them yields `permerror`, and receivers treat `permerror`
as no authorization at all. Because `include` nests, a domain can exceed the
limit purely through a vendor's own record.

Macro expansion (`%{s}`, `%{l}`, `%{o}`, `%{d}`, `%{i}`, `%{p}`, `%{v}`, `%{h}`,
with optional transformers and digits) means a record cannot always be read
literally. When a record uses macros, expand it by hand or with a checker rather
than assuming the literal text is the whole story.

When `MAIL FROM` is empty, as in a bounce, receivers check the `EHLO` identity
instead. That is why a domain that only publishes SPF for its sending IPs can
still fail on its own bounces.

### DKIM: a signature over headers and body

The signer hashes a canonicalized selection of header fields plus a hash of the
canonicalized body, then signs that with a private key. The signature travels in
`DKIM-Signature:` with tags: `v=1`, `a=` algorithm, `c=` header/body
canonicalization, `d=` signing domain, `s=` selector, `h=` signed header list,
`bh=` body hash, `b=` signature, and optionally `t=`, `x=`, `i=`, `l=`, `q=`.

Verification retrieves the public key from `<selector>._domainkey.<d>` as a TXT
record containing `v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo>`. An empty
`p=` means the key was revoked; a missing record means the signature cannot be
verified at all, which for DMARC is equivalent to a failure.

Canonicalization decides what survives transit. `simple` changes nothing.
`relaxed` lowercases the header name, unfolds continuation lines, collapses
whitespace runs to one space, strips trailing whitespace, and removes whitespace
around the colon; for the body it collapses whitespace runs, strips trailing
whitespace, and ignores empty lines at the end of the body. Both canonicalizations
ignore trailing empty lines in the body.

The `l=` tag limits how much of the body is hashed, and anything appended after
that length is unsigned. The `h=` list must include `From`; a verifier must
reject a signature that does not. RFC 8301 removed `rsa-sha1` for signing and
requires RSA keys of at least 1024 bits, with 2048 recommended.

DKIM survives forwarding only if the intermediary does not rewrite signed
content. Mailing lists that add a subject prefix or a footer break the body hash,
which is why ARC exists.

### DMARC: alignment plus an instruction

DMARC (RFC 7489) is published at `_dmarc.<domain>` as a TXT record:
`v=DMARC1; p=none|quarantine|reject; sp=; pct=; rua=; ruf=; adkim=r|s; aspf=r|s;
fo=; rf=; ri=`. The record must begin with `v=DMARC1`; `p=` is required.

A message passes DMARC when at least one of the following holds for the domain
in the single `From:` header field:

- SPF produced a `pass` for a domain aligned with the `From:` domain, or
- a valid DKIM signature carries a `d=` value aligned with the `From:` domain.

Alignment is `relaxed` by default, meaning the organizational domain (public
suffix plus one label) must match; `strict` requires an exact FQDN match. A
message with multiple `From:` domains is treated as failing.

Policy discovery walks from the exact domain to the organizational domain.
When the record is found at the organizational domain, `sp=` governs subdomains
and defaults to `p=`. `pct=` samples the fraction of failing messages that get
the quarantine or reject treatment; it does not apply to `p=none`. `rua=` names
aggregate-report destinations and `ruf=` forensic ones, each optionally suffixed
with a size limit such as `!10m`. A destination outside the reporting domain's
organizational domain must authorize the reports by publishing `v=DMARC1` at
`<destination-domain>._report._dmarc.<reporting-domain>`.

Aggregate reports are gzipped XML with a `feedback` root containing
`report_metadata`, `policy_published`, and one `record` per source IP with `row`
(count, disposition, evaluated SPF and DKIM results) and `auth_results` (the
actual DKIM domains/selectors and SPF domains observed).

### Authentication-Results and ARC

Receivers record verdicts in `Authentication-Results:` (RFC 8601), naming the
authserv-id, the SPF and DKIM results, and a `dmarc=` result with the evaluated
`header.from`. This header, from a receiver you control, is the strongest
empirical evidence available: it is the receiving stack's own judgement, not
your reading of DNS.

ARC (RFC 8617) adds three headers at each forwarding hop so a receiving system
can see an intact chain of prior authentication: `ARC-Authentication-Results`,
`ARC-Message-Signature`, and `ARC-Seal`, linked by an instance number `i=` and a
chain validation result `cv=`. ARC lets a forwarder preserve the original
authentication verdict; it does not make a broken signature valid again.

### Root causes worth naming

- SPF authorizes hosts, not the `From:` header, so an SPF `pass` on a shared ESP
  domain says nothing about the brand domain.
- Alignment is a separate configuration step from authentication; a domain can
  authenticate perfectly and align never.
- `p=none` publishes an instruction to monitor, not to block, and receivers are
  free to apply their own heuristics.
- Records decay: keys rotate, IPs change, vendors change their include trees.
  A configuration that passed last year can fail today without any edit.

## D. Prerequisites and Environment

### Operating system and shell

Linux is the reference environment. macOS ships a usable `dig` and `openssl`.
On Windows, use WSL or Git Bash; `nslookup` is present but prints less than `dig`
and hides TTL and multi-string TXT framing. All commands below are POSIX shell.

### Software

```shell
# Debian/Ubuntu
sudo apt-get install -y dnsutils openssl python3
# optional analysis helpers
sudo apt-get install -y swaks opendkim-tools
python3 -m pip install --user dkimpy checkdmarc parsedmarc

# macOS (Homebrew)
brew install bind openssl@3 python@3.12 swaks opendkim
python3 -m pip install --user dkimpy checkdmarc parsedmarc

# Fedora/RHEL
sudo dnf install -y bind-utils openssl python3 swaks opendkim
```

### Verification of the environment

```shell
dig -v
openssl version
python3 -c "import ssl, sys; print(sys.version.split()[0], ssl.OPENSSL_VERSION)"
```

Expected: a BIND version line, an OpenSSL 1.1.1 or 3.x banner, and a Python 3.10+
interpreter. A missing `dig` is not fatal, but every command in this skill that
prints raw TXT framing assumes it.

### Network requirements

Outbound UDP/TCP 53 to a resolver, and outbound TCP 25 or 587 only to a mail
server you are authorized to use. No inbound exposure is required. If the
environment forces a specific resolver, pass it explicitly with `@resolver` so
results are attributable and reproducible.

### Safe testing environment

The minimum safe setup is: two domains you control, a mailbox you own at a
third-party provider for empirical checks, and a local record of the
authorization (who approved the test, which domains, what date range). Never
point a send test at an address belonging to someone who has not agreed to
receive it.

### Query hygiene

Resolvers and authoritative servers are third-party infrastructure. Keep lookups
to the handful a diagnosis needs, cache results in a local file rather than
re-querying in a loop, and remember that repeated queries against a provider's
nameservers are visible to that provider.

## E. Detailed Operational Methodology

Run the phases in order. Each phase states what it needs, what it produces, and
what must be true before the next phase is meaningful. Phases 2 through 5 are
static and need no mail to be sent, so they can run in any environment with DNS.

### Phase 0 — Record scope and authority

**Objective:** establish, in writing, which domains and sending flows are covered.
**Preconditions:** a named approver for the domain owner and a stated window.
**Inputs:** domain list, allow/deny list, contact for the sending infrastructure.
**Procedure:** write the authorization record before the first query. Record the
approver, the domains in scope, the mailboxes permitted to receive test mail, the
maximum number of test messages, and the stop conditions from section K.
**Expected output:** a short scope note stored with the evidence set.
**Interpretation:** if the approver cannot name the domains, the scope is not yet
defined; stop and ask for the list rather than inferring it from a brand name.
**Error handling:** an ambiguous scope is a blocker, not a warning.
**Validation:** every later command must be traceable to a line in this note.
**Next decision:** proceed only when each domain is attributable to the owner.

### Phase 1 — Inventory the domains and their sending flows

**Objective:** enumerate every domain and subdomain that sends mail, and through
which provider, so that a clean SPF on the primary domain does not hide an
unauthenticated subdomain.
**Preconditions:** Phase 0 complete.
**Inputs:** apex domain, known subdomains, marketing tool list, ticketing system,
transactional ESP, CRM.
**Procedure:** collect the apex, every subdomain that appears in a `From:` header
of historical mail you can read, and the provider named in each message's
`Received` and `Return-Path` headers. Then verify each candidate with a DNS
query rather than assuming from the name:

```shell
for d in example.com mail.example.com news.example.com; do
  printf '%-24s ' "$d"
  dig +short TXT "$d" | tr '\n' ' ' | cut -c1-120
  echo
done
```

**Expected output:** one TXT line per domain, either an SPF record or nothing.
**Interpretation:** a subdomain with no SPF record and no DMARC inheritance is a
spoofable surface even when the apex is perfect.
**Error handling:** `dig` returning nothing at all usually means NXDOMAIN; confirm
with `dig +noall +comments` before concluding the name does not exist.
**Validation:** cross-check the list against at least one real message per flow.
**Next decision:** any domain that sends mail and returns no SPF record goes on
the findings list immediately.

### Phase 2 — Retrieve and parse SPF

**Objective:** obtain the exact record text as a receiver would see it, including
multi-string framing.
**Preconditions:** Phase 1 list.
**Inputs:** domain names.
**Procedure:**

```shell
dig +noall +answer TXT example.com
dig +short TXT example.com
```

The first form prints the raw TXT presentation format, which shows whether the
record is split across multiple 255-octet character-strings. Receivers concatenate
those strings with no separator, so a record split mid-token is still valid but
a record split with an added space is not the record the author intended.

**Expected output:** exactly one record beginning `v=spf1`. Zero records means no
SPF. Two or more records beginning `v=spf1` is a permanent error per RFC 7208 and
must be reported as such, not merged by hand.
**Interpretation:** read mechanisms left to right; the first match wins. A
terminal `-all` is enforcement, `~all` is soft enforcement, `?all` is neutral and
provides no protection, and `+all` authorizes the entire internet.
**Error handling:** if the record uses macros, expand them for a known sending IP
before judging the terminal mechanism.
**Validation:** confirm the retrieved text with a second resolver:
`dig +short TXT example.com @1.1.1.1` and `@8.8.8.8`.
**Next decision:** proceed to budget accounting; a record that looks correct is
still unauthoritative if it exceeds the query limit.

### Phase 3 — Account for the SPF DNS budget

**Objective:** prove whether the record evaluates within RFC 7208's limits.
**Preconditions:** Phase 2 record.
**Inputs:** the record text, plus each included domain's record.
**Procedure:** count DNS-querying terms. Every `include:`, `a`, `mx`, `ptr`,
`exists:`, and a `redirect=` each consume one unit of the 10-unit budget; an
`include` brings its whole subtree with it. Walk the tree explicitly:

```shell
for d in _spf.provider.example mail.example.com; do
  echo "== $d"
  dig +short TXT "$d"
done
```

A checker automates the walk and reports the total:

```shell
python3 -m checkdmarc example.com --timeout 8
```

**Expected output:** a total of 10 or fewer, with 2 or fewer void lookups.
**Interpretation:** 10 is the ceiling, not a target. A record at 10 has no room
for a new vendor and will break the day one is added. Void lookups above 2 are a
permanent error on their own, even with a small term count.
**Error handling:** if the checker and a hand count disagree, trust the hand count
and document the discrepancy; implementations differ on whether `redirect` is
counted, and a receiver's implementation is the one that matters.
**Validation:** re-run the count after any vendor record changes.
**Next decision:** over budget means the domain currently returns `permerror` on
some paths, which is a finding independent of DMARC.

### Phase 4 — Inventory DKIM selectors and keys

**Objective:** establish which selectors are live, whether their keys are valid
and adequately sized, and whether any selector is revoked or dangling.
**Preconditions:** at least one message from each flow, with its headers intact.
**Inputs:** `DKIM-Signature` header values from authorized mail.
**Procedure:** read `d=` and `s=` from each signature, then query the key:

```shell
dig +short TXT selector1._domainkey.example.com
```

Decode the published key and read its size:

```shell
rec=$(dig +short TXT selector1._domainkey.example.com | tr -d '"' | tr -d ' ')
key=$(printf '%s' "$rec" | sed -n 's/.*p=\([^;]*\).*/\1/p')
printf '%s' "$key" | base64 -d | openssl pkey -pubin -inform DER -noout -text | head -2
```

`opendkim-testkey` performs the same check in one step:

```shell
opendkim-testkey -d example.com -s selector1 -vvv
```

**Expected output:** `Public-Key: (2048 bit)` or larger, and `opendkim-testkey`
reporting the key as OK.
**Interpretation:** 1024-bit keys are permitted by RFC 8301 but are below current
practice; a key record with `p=` empty means the selector was revoked, so any
message still signed with it fails. A selector that no longer resolves means the
key was withdrawn while mail still carries signatures referencing it.
**Error handling:** a CNAME at the selector is valid delegation, not an error; it
adds a DNS dependency that must be checked separately.
**Validation:** verify with a real message through `dkimverify < message.eml` and
confirm the signature reports `good`.
**Next decision:** any flow with no valid selector is a DP (DKIM) finding.

### Phase 5 — Read the DMARC policy and judge alignment

**Objective:** determine the effective policy for each sending domain and whether
the domain can actually align.
**Preconditions:** Phases 2 and 4 results.
**Inputs:** DMARC TXT at `_dmarc.<domain>` and at the organizational domain.
**Procedure:**

```shell
dig +short TXT _dmarc.example.com
dig +short TXT _dmarc.example.org
```

**Expected output:** a record beginning `v=DMARC1` with an explicit `p=`.
**Interpretation:** apply the policy to observed mail. A message passes only if an
aligned SPF pass or an aligned DKIM pass exists. With a shared ESP, the envelope
domain is the provider's, so SPF cannot align unless the provider offers a custom
return-path on your domain; DKIM with `d=example.com` is then the only path to a
pass. `p=none` means the receiver reports but does not block, which is why a
domain "with DMARC" can still be spoofed successfully.
**Error handling:** a record at the organizational domain with `sp=none` leaves
subdomains unprotected even when the apex rejects.
**Validation:** confirm with a real message's `Authentication-Results` header from
a receiver you control, which reports `dmarc=pass` or `dmarc=fail` with the
evaluated `header.from`.
**Next decision:** if no record exists, the finding is "no policy"; if a record
exists but nothing aligns, the finding is "policy that cannot be satisfied".

### Phase 6 — Controlled empirical test

**Objective:** convert static reasoning into an observed receiver verdict.
**Preconditions:** authorization to send, a mailbox you control, a small message
limit.
**Inputs:** the sending host or ESP, one recipient address, one message body.
**Procedure:** send one ordinary message through the legitimate flow:

```shell
swaks --to test-inbox@your-domain.example \
      --from sender@example.com \
      --server smtp.example.com:587 \
      --tls --auth LOGIN --auth-user sender@example.com \
      --header "Subject: authentication check" \
      --body "Controlled test, single message."
```

Then read the full headers at the receiving mailbox and extract the verdicts:

```text
Authentication-Results: mx.receiver.example;
  spf=pass smtp.mailfrom=example.com;
  dkim=pass header.d=example.com header.s=selector1;
  dmarc=pass header.from=example.com
```

**Expected output:** `dmarc=pass` for legitimate mail.
**Interpretation:** one failing mechanism with the other passing is normal in a
forwarding path and is exactly what alignment is for. Two failures is a
configuration defect.
**Error handling:** a message that never arrives is a delivery problem, not an
authentication result; do not record it as a failure. A `temperror` means the
receiver could not complete the check; retry once, later.
**Validation:** repeat with one message per sending flow, no more.
**Next decision:** any flow with `dmarc=fail` on its own legitimate mail is a
blocking finding, because enforcement would break it.

### Phase 7 — Review aggregate reports

**Objective:** see what receivers actually observed, across sources, rather than
what one test message produced.
**Preconditions:** a `rua=` destination you can read, with at least a few days of
history.
**Inputs:** aggregate XML reports (gzipped attachments or provider dashboards).
**Procedure:** parse reports into per-source rows and separate legitimate flows
from unknown sources:

```shell
parsedmarc --input reports/ --output results/ --silent
```

**Expected output:** per-day counts keyed by source IP, with `dkim` and `spf`
results and the header-from domain.
**Interpretation:** a source IP that fails both mechanisms and is not a known
vendor is either an unknown legitimate sender or an impersonation attempt; the
report proves the domain's policy let it through, which is the impact statement.
**Error handling:** reports from a destination outside the domain require the
`_report._dmarc` authorization record; absence produces no reports at all, which
is easy to misread as "no failures".
**Validation:** reconcile the report window against the test message timestamps.
**Next decision:** unknown sources with volume justify escalation in severity.

### Phase 8 — Findings, severity and remediation order

**Objective:** turn observations into a defensible report and a change sequence
that does not break legitimate mail.
**Preconditions:** Phases 1 to 7 evidence.
**Inputs:** evidence set, flow inventory, provider capabilities.
**Procedure:** grade each finding by what an unauthenticated sender gains, not by
which record is missing. Order remediation so monitoring precedes enforcement:
publish or fix `rua`, reach aligned passes on every flow, then ramp policy.
**Expected output:** findings with CWE mapping, evidence, and a staged plan.
**Interpretation:** enforcement applied before alignment exists converts a
spoofing problem into a delivery outage.
**Error handling:** when a provider cannot align, the fix is provider-shaped
(custom return-path, dedicated subdomain) rather than a DNS edit.
**Validation:** each finding must cite a command output captured today.
**Next decision:** proceed to Phase 9 only after a change is published.

### Phase 9 — Verify after change

**Objective:** confirm the change took effect from the receiver's perspective.
**Preconditions:** change published and TTL elapsed.
**Inputs:** the same queries and the same test flow as before.
**Procedure:** re-run Phases 2 to 6 and diff the results against the baseline
capture.
**Expected output:** identical records except the intended change, and a
`dmarc=pass` on every flow.
**Interpretation:** a record that has not propagated is not a failed fix. Check
TTL before concluding anything.
**Error handling:** negative caching at the resolver can hold the old answer;
query the authoritative server directly to separate propagation from caching.
**Validation:** keep the before/after pair as the verification artifact.
**Next decision:** close the finding only when the observed verdict changed.

### Decision tree

```text
Is a DMARC record published for the From domain?
  no  -> finding: no policy (spoofable From), severity by mail volume
  yes -> does it parse and is p= present?
           no  -> finding: malformed policy, receivers ignore it
           yes -> does at least one mechanism align on real mail?
                    no  -> finding: policy cannot be satisfied; enforcing breaks mail
                    yes -> what does p= say?
                             none      -> finding: monitoring only; spoofing still delivers
                             quarantine/reject -> check pct, sp, and subdomain coverage
```

## F. Practical Technical Examples

All domains below use the reserved `example.com`/`example.org` names from
RFC 2606. Values are illustrative; the commands are real and the observed output
shape is what a receiver returns.

### F1. Basic: one domain, one sender, correct configuration

```shell
$ dig +short TXT example.com
example.com. 300 IN TXT "v=spf1 ip4:192.0.2.10 -all"
$ dig +short TXT _dmarc.example.com
example.com. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
$ dig +short TXT mail._domainkey.example.com
mail._domainkey.example.com. 300 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBg..."
```

Reading: one SPF record, two DNS-querying terms (none, in fact: `ip4:` is not a
query), terminal `-all`, DMARC at `p=reject` with a reporting address, and a key
that decodes to 2048 bits. A test message through this configuration returns
`dmarc=pass` with both `spf=pass` and `dkim=pass`. This is the reference case; any
deviation found later is a finding.

### F2. Intermediate: shared ESP, correct DKIM, broken SPF alignment

```text
Return-Path: <bounce@em1234.provider.example>
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=provider; ...
From: Example <news@example.com>
```

SPF passes for `em1234.provider.example` because the provider authorized its own
sending IPs. DMARC evaluates the `From:` domain, `example.com`, and finds no
aligned SPF pass. The message still passes DMARC, because the DKIM signature
carries `d=example.com` and verifies. This is the correct design, and it is also
the fragile one: rotate the DKIM key without publishing the new selector and the
domain loses its only aligned path, at which point enforcement starts blocking
its own newsletters.

### F3. Advanced: enforcement that is not enforced

```shell
dig +short TXT _dmarc.example.com
"v=DMARC1; p=quarantine; pct=10; sp=none; adkim=s; aspf=s"
```

Three separate weaknesses in one line. `pct=10` applies quarantine to one message
in ten, so nine in ten spoofed messages are delivered as if no policy existed.
`sp=none` explicitly declines to protect subdomains, which is where staging and
ESP-hosted senders usually live. `adkim=s` and `aspf=s` demand exact-FQDN
alignment, which many ESP flows cannot satisfy because the signing domain is a
subdomain of the brand domain. The correct read is not "DMARC is configured" but
"policy exists and covers roughly a tenth of traffic, on one label".

### F4. Edge case: multiple SPF records

```shell
dig +short TXT example.com
"v=spf1 include:_spf.provider.example ~all"
"v=spf1 ip4:198.51.100.0/24 -all"
```

Two records is a permanent error (RFC 7208), not an additive configuration. Some
receivers pick the first, some return `permerror`; both outcomes are wrong for the
owner and the ambiguity itself is the finding. The fix is a single record holding
the union of mechanisms, which almost always pushes the term count closer to the
limit and must be re-accounted afterwards.

### F5. Edge case: the record that is over budget

```text
v=spf1 include:_spf.a.example include:_spf.b.example include:_spf.c.example
       include:_spf.d.example include:_spf.e.example include:_spf.f.example ~all
```

Six includes look modest, but each vendor's record commonly contains two to four
nested includes of its own. The total routinely lands at 11 or 12, producing
`permerror` for every message, which most receivers treat as "no SPF". `checkdmarc`
reports the count and the offending subtree; the remedy is flattening or per-vendor
subdomains, not removing a vendor.

### F6. Edge case: revoked and dangling selectors

```shell
$ dig +short TXT old._domainkey.example.com
old._domainkey.example.com. 300 IN TXT "v=DKIM1; k=rsa; p="
$ dig +short TXT 2023._domainkey.example.com
# (no answer)
```

`p=` empty is a deliberate revocation; a signature naming that selector must fail.
A selector that does not resolve at all means mail still carries signatures whose
key no longer exists. Neither is exploitable by itself, but both indicate a
rotation process without a verification step, which is how a live flow silently
loses its aligned DKIM path.

### F7. False positive: `dmarc=pass` with `spf=fail`

A forwarded message commonly shows `spf=fail` (the forwarder's IP is not in the
original domain's SPF) and `dkim=pass` (the body hash survived because the
forwarder did not rewrite signed content), so DMARC passes. Reporting this as a
spoofing success would be wrong. The finding, if any, is that the forwarder does
not implement ARC, which matters only for flows that rewrite content.

### F8. False positive: a reporting domain you do not control

An `rua=` address at a third-party monitoring vendor looks like data leaving the
organization. It is a normal and RFC-sanctioned arrangement, authorized by the
vendor's `_report._dmarc` record. It becomes a finding only when the vendor is
unapproved by policy, or when the authorization record is missing and reports are
silently dropped.

### F9. Failure condition: enforcement before alignment

The most damaging real-world sequence is raising `p=` to `quarantine` on a domain
whose only aligned mechanism is a DKIM key that one ESP flow does not use. The
spoofing surface closes and that flow's mail starts landing in spam, usually
discovered days later from a business complaint rather than from monitoring. The
pair of evidence to capture before any change is: a `dmarc=pass` for every flow
in the inventory, and a non-zero `rua` volume reporting those passes.

## G. Tools and Commands

Every tool below is a real, maintained program. Flags are the ones documented for
the version ranges noted; verify with `<tool> --help` on the machine you are on
rather than trusting this table blindly, because flags do drift between releases.

### G1. `dig` (BIND 9 dnsutils)

Purpose: query authoritative and recursive DNS and print TXT records with their
framing. Source: ISC BIND, distributed by every major Linux distribution and by
Homebrew (`brew install bind`). Example and interpretation:

```shell
dig +noall +answer TXT example.com
dig +short TXT example.com
dig +noall +answer +comments TXT example.com
dig +dnssec TXT _dmarc.example.com
```

`+noall +answer` prints the answer section with TTL and class; `+short` prints
just the data, which is convenient but hides multi-string framing; `+comments`
shows rcode, so NXDOMAIN is distinguishable from an empty answer; `+dnssec` sets
the DO bit and shows RRSIG records when the zone is signed. Limitations: `dig`
does not validate DNSSEC (use `delv` for that), and it resolves through the
system resolver by default, so a cached answer may be older than it looks. Pass
`@server` to attribute results to a specific resolver.

### G2. `kdig` (Knot DNS utils)

Purpose: an alternative resolver client with cleaner multi-line TXT output and
TLS support. Source: Knot DNS project (`apt install knot-dnsutils`). Useful for
confirming that a result is not a quirk of BIND's presentation:

```shell
kdig +short TXT _dmarc.example.com
kdig +tls TXT example.com @1.1.1.1
```

Limitation: not installed by default on most systems; and like `dig` it does not
validate signatures.

### G3. `delv` (BIND 9)

Purpose: perform DNSSEC validation and report secure/insecure/bogus. Source:
BIND 9.12 and later, same package as `dig`.

```shell
delv TXT _dmarc.example.com
```

Expected output includes `fully validated` on a signed zone, or `unsigned answer`
on an unsigned one. Interpretation: an unsigned DMARC record can be replaced by
an on-path attacker, so DNSSEC is the integrity control; absence is a hardening
observation, not an authentication bypass by itself.

### G4. `openssl`

Purpose: decode a published DKIM key and read its size and algorithm.

```shell
rec=$(dig +short TXT mail._domainkey.example.com | tr -d '"' | tr -d ' ')
key=$(printf '%s' "$rec" | sed -n 's/.*p=\([^;]*\).*/\1/p')
printf '%s' "$key" | base64 -d | openssl pkey -pubin -inform DER -noout -text | head -3
```

Expected: `Public-Key: (2048 bit)` and a modulus. Interpretation: the `p=` value
is base64 of a DER SubjectPublicKeyInfo, which is why `-pubin -inform DER` is the
correct decode. Limitations: `openssl pkey` on some 1.0.x builds rejects the
input; use a 1.1.1+ or 3.x binary.

### G5. `opendkim-testkey`

Purpose: fetch the selector's public key and check that it parses and matches an
optional local private key. Source: OpenDKIM (`apt install opendkim-tools`).

```shell
opendkim-testkey -d example.com -s mail -vvv
```

Expected: a line reporting the key as OK with its size. Interpretation: a failure
here means signatures with that selector cannot verify, regardless of what the
signing software believes. Limitation: it reads the resolver configuration from
the system and can be affected by a stale cache; add `-C` if your build supports
it to bypass the cache.

### G6. `dkimverify` (dkimpy)

Purpose: verify signatures on a stored message, end to end, including canonicalization.

```shell
python3 -m pip install --user dkimpy
dkimverify < message.eml
```

Expected: `<signature ok>` per valid signature, with the signing domain and
selector. Interpretation: `body hash did not verify` means the body was modified
after signing; `no key for signature` means the selector does not resolve.
Limitation: it verifies only what is in the file; it does not tell you whether the
receiver's stack agreed.

### G7. `checkdmarc`

Purpose: parse SPF and DMARC for a domain, count SPF terms, report alignment and
policy problems in a machine-readable form.

```shell
python3 -m pip install --user checkdmarc
checkdmarc example.com --timeout 8
```

Expected: JSON on stdout with `spf`, `dmarc`, `valid_domains`, and a list of
`warnings` and `errors`. Interpretation: `SPF record lookup limit exceeded` is a
`permerror` condition; `DMARC policy is p=none` is reported as a warning. Limitation:
it is a static checker; it cannot know which hosts legitimately send for the domain.

### G8. `parsedmarc`

Purpose: parse DMARC aggregate and forensic reports into JSON or a database, so
per-source failures become visible.

```shell
python3 -m pip install --user parsedmarc
parsedmarc --input reports/ --output results/ --silent
```

Expected: one JSON file per report plus a summary. Interpretation: aggregate rows
are counts, not individual messages, so a single failing source with `count=400`
represents 400 messages in that window. Limitation: it needs real report files;
there is no offline substitute for a domain that publishes no `rua`.

### G9. `swaks`

Purpose: send one controlled test message through a specific server with TLS and
authentication.

```shell
swaks --to you@your-domain.example --from sender@example.com \
      --server smtp.example.com:587 --tls --auth LOGIN \
      --auth-user sender@example.com --header "Subject: test" --body "one message"
```

Expected: a transcript ending in `250 OK` per recipient. Interpretation: a 5xx at
`MAIL FROM` is usually a policy rejection, not an authentication failure; read the
SMTP reply text before drawing conclusions. Limitation: sending is a state change
at a third party; keep it to the number of messages the authorization allows.

### G10. Tool selection

Use `dig` for retrieval, `checkdmarc` for accounting, `openssl` or
`opendkim-testkey` for keys, `dkimverify` for a stored message, `swaks` only when
an empirical verdict is required, and `parsedmarc` only when reports exist. Do not
install a tool that is missing without recording that it was unavailable; a
skipped check is a declared gap, not a pass.

## H. Vulnerability Discovery and Validation

### H1. Attack surface identification

The surface is every domain that (a) appears in a `From:` header of mail the
organization sends, and (b) has no aligned, enforced policy. Enumerate it from
three directions: DNS (records exist), mail history (headers show what is used),
and provider inventory (the ESP console lists sending domains). Any domain found
by one method and missing from another is worth a second look.

### H2. Reconnaissance without touching the target

All of Phases 2 to 5 are read-only DNS queries against public data. They are
still traffic: keep them minimal, do not enumerate large subdomain lists, and do
not query a provider's authoritative servers in a loop. If the assessment has
access to the zone file or the DNS provider's API, prefer that source and treat
live queries as confirmation only.

### H3. Weakness identification

Classify each observation into one of five shapes, because they have different
fixes and different severities:

```text
no-policy           no DMARC record at or above the From domain
unsatisfiable       policy exists; no flow can produce an aligned pass
unenforced          p=none, or pct<100, or sp=none over the sending subdomains
broken-mechanism    SPF permerror/over-budget, or DKIM key revoked/missing
hygiene             DNSSEC absent, 1024-bit key, no rua, no MTA-STS
```

### H4. Test-case development

Each test case is a claim plus the observation that would falsify it. Examples:
"an unauthenticated host can use this domain in From: and be delivered" is
falsified by an enforced aligned policy; "the domain's own newsletters pass
DMARC" is falsified by a `dmarc=fail` row in an aggregate report for that flow.
Write the falsifier before running the check, or the check becomes a search for
confirmation.

### H5. Controlled testing

Never send from an address you do not control, never send to a recipient who has
not agreed, and never attempt to make a third-party receiver deliver a spoofed
message as proof. The acceptable proof of spoofability is configuration-level:
an enforced aligned policy is absent, therefore the receiver has nothing to
enforce. Where policy-level proof is insufficient, the empirical substitute is a
single message from the legitimate flow showing `dmarc=pass`, plus the published
policy showing what would happen to a message with no aligned pass.

### H6. Reproducibility

Capture the command, the timestamp, the resolver used, and the raw output for
every claim. A record that changes between two runs is either propagation or a
provider edit; both are information. Store the captures as text files, not
screenshots, so they can be diffed.

### H7. Evidence collection

Minimum set per finding: the DNS answer with TTL, the parsed value, the policy
that applies, the observed receiver verdict if one exists, and the timestamp.
Redact mailbox addresses and any message content that is not required to make the
point (section K).

### H8. Impact validation

State impact in terms the owner recognizes: which mail domain can be impersonated,
to which recipients, and what the impersonation enables (invoice fraud, credential
phishing, executive impersonation). Avoid claiming message delivery you did not
observe; absence of enforcement is the defect, delivery is an inference and must
be labelled as one.

### H9. False-positive elimination

Before reporting, rule out: inherited policy from the organizational domain (a
subdomain with no record may still be covered), a DMARC pass through DKIM after an
SPF failure in a forwarding path, a `rua` address at an approved vendor, and a
provider-side enforcement layer that applies policy before DMARC evaluation. Each
of those turns an apparent gap into a documented design.

### H10. Root-cause analysis

The cause is rarely "someone forgot". It is usually a process gap: no owner for
the DNS record, no monitoring of aggregate reports, a vendor onboarding step that
adds an include without re-accounting the budget, or a key rotation runbook that
publishes the new selector after the switch instead of before it. Name the process,
because the process is what the remediation has to change.

## I. Advanced Techniques

### I1. Subdomain and ESP delegation risk

A staging subdomain that points its DKIM selector at a decommissioned ESP is a
soft takeover path: whoever claims that ESP tenant can sign as the subdomain. Check
whether selector CNAMEs still resolve to a provider the owner no longer uses.

### I2. Key reuse across domains

One key pair published under selectors on several domains means a compromise of one
host signs for all of them. Look for identical `p=` values across selectors; report
as hygiene with a blast-radius note.

### I3. Body-length and expiry tags

`l=` leaves everything beyond a byte offset unsigned; appended text is a classic
phishing vector that still verifies. `x=` sets a signature expiry, and a missing
`x=` means the signature is valid as long as the key exists. Neither is a defect by
itself, but both widen the window in which a captured message is reusable.

### I4. Replay of a captured signed message

A valid signed message can be re-sent to a different recipient at the same domain
and still verify, because DKIM signs content, not envelope or recipient. This is
why DKIM alone is not anti-replay; note it when the threat model includes internal
impersonation.

### I5. Organizational-domain alignment shortcuts

With relaxed alignment, a signature from any subdomain of the same organizational
domain aligns. That is intended, but it means a single compromised subdomain's
signing key can produce mail that passes DMARC for the brand. Inventory subdomains
as part of the key inventory, not as an afterthought.

### I6. Sampling evasion

`pct=` below 100 is a probability, not a control. An attacker who sends enough
messages gets delivery by volume. Report `pct` as the effective coverage fraction
and do not describe such a domain as "protected".

### I7. ARC chains in forwarding

When a mailing list rewrites content, the original DKIM breaks. ARC preserves the
prior verdict if every hop seals correctly; a broken chain (`cv=fail`) is worse
than no chain because some receivers discount the whole path. Test with a forward
you control through a list that implements ARC.

### I8. DNSSEC as the integrity layer

Without DNSSEC, `_dmarc` and selector records are replaceable by an on-path
attacker who can spoof DNS. Validate with `delv` and report unsigned zones as
hardening, with the caveat that DNSSEC does not protect the SMTP hop.

### I9. Adjacent transport controls

MTA-STS (RFC 8461) and TLS reporting (RFC 8460) protect the SMTP hop against
downgrade; they are outside DMARC's scope and should be reported separately, never
folded into a DMARC finding.

### I10. When to escalate to a lab

If a claim depends on receiver-specific behaviour (how a particular provider treats
`permerror`, or whether it honours `pct`), reproduce it against a local MTA and a
local receiver you control rather than asserting provider behaviour from memory.

## J. Automation and AI Agent Integration

### J1. Input schema

The agent accepts one job object and refuses anything outside it.

```json
{
  "job_id": "2026-11-03-example",
  "authorization": {
    "approver": "name and role",
    "reference": "ticket or email id",
    "window_start": "2026-11-03T09:00:00Z",
    "window_end": "2026-11-03T17:00:00Z"
  },
  "domains": ["example.com", "news.example.com"],
  "excluded_domains": [],
  "test_mailbox": "dmarc-test@your-domain.example",
  "max_test_messages": 3,
  "allow_send": false,
  "resolver": "1.1.1.1"
}
```

`allow_send` defaults to false. With it false the agent runs Phases 1 to 5 and 7
only and reports the empirical phase as not performed.

### J2. Required context

The agent needs: the domain list, the authorization record, the resolver to use,
and whether it may send mail. It must not infer the domain list from a brand name,
and must not expand scope because a subdomain "looks related".

### J3. Execution workflow

1. Validate the job object; reject missing authorization or empty domain list.
2. For each domain: retrieve SPF, _dmarc, and organizational-domain DMARC.
3. Account SPF terms; flag over-budget and void-lookup conditions.
4. If message headers are supplied, inventory selectors and verify keys.
5. Compute the policy classification from section H3.
6. If `allow_send` and the mailbox is authorised, run Phase 6 once per flow.
7. Emit findings with evidence references and a remediation order.

### J4. Decision logic

```text
no DMARC record anywhere        -> no-policy, severity high when mail volume exists
record but p=none               -> unenforced, severity medium-high by volume
p>none but no aligned pass      -> unsatisfiable, severity high, fix before enforcing
SPF permerror or over budget    -> broken-mechanism, severity medium (fails open to none)
DKIM selector revoked/missing   -> broken-mechanism, medium, flow-specific
hygiene only                    -> low, separate from the above
```

### J5. Tool selection rules

Prefer the cheapest tool that answers the question: DNS text for retrieval, a
stdlib parser for structure, `checkdmarc` only when term accounting needs its
walk, `swaks` only when a receiver verdict is required and authorized. If a tool
is missing, record it as a gap; never simulate its output.

### J6. Output schema

```json
{
  "job_id": "2026-11-03-example",
  "domains_evaluated": 2,
  "findings": [
    {
      "domain": "example.com",
      "class": "unenforced",
      "title": "DMARC record present at p=none",
      "evidence": ["dig _dmarc.example.com @1.1.1.1 2026-11-03T09:12Z"],
      "cwe": "CWE-290",
      "severity": "medium",
      "remediation": "publish rua, reach aligned pass on all flows, then quarantine"
    }
  ],
  "not_performed": ["empirical send test (allow_send=false)"],
  "gaps": ["no aggregate reports supplied for the last 30 days"]
}
```

### J7. Validation checkpoints

After retrieval: every domain has a recorded answer, including NXDOMAIN. After
accounting: the term count is reproducible by hand from the captured records.
After classification: each finding names the observation that falsifies it. Before
output: every finding cites at least one capture.

### J8. Error recovery

Timeouts and `SERVFAIL` are retried once against a second resolver and then
recorded as `temperror`-shaped gaps. A `permerror` is never retried into a pass.
If the authorization window has closed, the agent stops and reports partial results
rather than continuing.

### J9. Logging and evidence

The agent writes one line per query to a JSONL log: timestamp, domain, record type,
resolver, and a hash of the answer. Raw answers are stored beside the log. Nothing
in the log contains mailbox credentials.

### J10. Human approval checkpoints

Two checkpoints are mandatory: before any message is sent, and before any
recommendation that changes policy from monitoring to enforcement. The second
exists because enforcement without alignment is an outage, and the person who owns
the mail flow should acknowledge the inventory before the switch.

### J11. What the agent must not do

The agent must not test a domain it cannot tie to the authorization record, must
not attempt delivery of a spoofed message,must not brute-force selector names at volume, and must not present an inference (such as "this would be delivered") as an
observation.

## K. Security, Authorization and Operational Safety

### K1. Authorization before the first query

Every action in this skill requires a written authorization that names the
approver, the domains, the permitted test mailboxes, and the date window. A brand
relationship, a shared parent company, or public DNS does not constitute
authorization to assess a domain. Record the authorization reference in the
output so a later reader can check the boundary without asking.

### K2. Scope validation

The agent validates every domain against the authorization list before it resolves
anything, and refuses any domain whose organizational domain is not on that list.
Excluded domains stay excluded even when they resolve to infrastructure that looks
related. Subdomains are in scope only when the authorization says so explicitly.

### K3. Target restrictions

Never send mail that claims to be from a domain you do not own, even to a mailbox
you control. Never send to a recipient who has not agreed. Never test a third-party
provider's DMARC implementation by attempting delivery through it. Mail is not an
anonymous protocol in practice: the receiving side can see the sending IP, and an
unexpected spoof attempt is indistinguishable from a real attack.

### K4. Rate limits

DNS: keep to the queries a diagnosis needs, cache answers locally, and avoid
loops over selector dictionaries. Mail: honour `max_test_messages` from the job
object, which defaults to one per sending flow. Selector enumeration is bounded
by the selectors observed in authorized messages, not by a wordlist.

### K5. Non-destructive testing

The assessment reads DNS and, when authorized, sends a small number of ordinary
messages. It does not change records, does not rotate keys, does not add reporting
addresses, and does not attempt to make a message be delivered that a policy would
otherwise block. Every recommendation is a proposal for the owner to apply.

### K6. Sensitive data handling

Messages inspected for selectors contain real correspondence. Extract only the
`DKIM-Signature` and `Authentication-Results` headers; do not copy bodies,
subjects, or recipient addresses into the evidence set. Aggregate reports contain
source IPs, which are personal data in many jurisdictions; store counts and
classifications, not raw dumps, unless the owner asks otherwise.

### K7. Credential protection

SMTP credentials used for a test message are passed through the environment or an
agent, never on the command line, never in a captured transcript, and never in a
report. If a credential appears in any artifact, treat it as compromised, revoke
it, and note the incident in the report.

### K8. Evidence redaction

Redact mailbox addresses to a role label such as `test-mailbox`, redact internal
hostnames that reveal infrastructure, and keep the DNS answers verbatim because
they are public data. A finding must remain reproducible after redaction; if it
would not, the redaction removed something load-bearing and the evidence needs a
second pass.

### K9. Stop conditions

The assessment stops immediately, and reports what was found so far, when any of
the following occurs: the authorization window closes; a domain is found that is
not on the authorization list; the owner asks to pause; a test message is
delivered to an address that was not approved; a credential is exposed in an
artifact; or the number of permitted test messages is exhausted. Stopping is a
normal outcome and is recorded as such, never as a failure of the target.

### K10. Reporting obligations

If the assessment finds evidence of active impersonation (an unknown source
sending as the domain with volume in aggregate reports), notify the owner through
the channel named in the authorization within the agreed window, before the full
report is written. Do not contact the sending infrastructure or the receiving
provider directly without the owner's agreement.

## L. Reporting and Documentation

### L1. Required fields

Every finding carries: title, one-sentence summary, affected asset (the exact
domain and record name), scope confirmation with the authorization reference,
severity with its basis, CWE mapping, technical explanation, reproduction steps,
evidence references, security impact, remediation, and a verification procedure.

### L2. Title shape

Name the defect and the asset, not the tool: "DMARC policy for example.com is
p=none, so unauthenticated mail from the domain is not blocked" beats "DMARC
issue found".

### L3. Severity basis

Grade on what an unauthenticated sender gains. No policy at all on a domain that
sends customer-facing mail is materially worse than `p=none` on a domain that sends
nothing. Include the observed mail volume from aggregate reports as the
quantifier, and state the CVSS vector if the program requires one, computing the
score with an official calculator rather than quoting a number from memory. The
typical vector shape for this class is network-reachable with user interaction and
impact on integrity, for example `AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N`; the score
must be computed, not asserted.

### L4. Evidence block

For each claim, cite the command, the resolver, the timestamp, and the raw answer.
A reader must be able to re-run the same command against the same resolver and get
the same bytes, or see the change and understand why.

### L5. Remediation shape

Sequence, do not list. Publish `rua` and confirm reports arrive; fix alignment on
every flow until each shows an aligned pass; raise policy to `quarantine` with
`pct` staged; move to `reject`; then tighten `sp`, `adkim` and `aspf`. Name the
owner of each step, because DNS changes usually belong to a different team than
the mail flow.

### L6. Verification section

The report states the exact commands that will prove the fix: the `_dmarc` query,
the SPF term count, the selector query, and the `Authentication-Results` line from
a fresh test message after propagation.

## M. Troubleshooting and Edge Cases

### M1. No answer for a TXT query

Distinguish three cases before concluding anything: NXDOMAIN (the name does not
exist), NOERROR with an empty answer (the name exists, no TXT at that owner), and
SERVFAIL (the resolver failed). `dig +noall +comments` prints the status line.
Reporting "no DMARC" for a SERVFAIL is a false positive.

### M2. Record looks truncated

TXT character-strings are limited to 255 octets and are concatenated by consumers
with no separator. `dig +short` can join or split them in ways that mislead;
always read `dig +noall +answer` for a long SPF record and reassemble by hand
before judging it.

### M3. Conflicting answers across resolvers

Two resolvers returning different records usually means propagation in progress
or split-horizon DNS. Query the authoritative server directly
(`dig +norecurse @ns1.example.com TXT example.com`) to see the source of truth,
and re-check after the TTL.

### M4. `checkdmarc` disagrees with a hand count

Implementations differ on whether `redirect` counts toward the ten-term budget and
on how nested includes are attributed. Document both numbers, state which one the
receiver is likely to enforce, and prefer the conservative reading for a finding.
If the disagreement is about a vendor subtree, query the vendor's own `_spf` record
and count it manually.

### M5. `openssl` cannot decode the key

Common causes: the record was copied with quotes or whitespace, the key is not
DER SubjectPublicKeyInfo but a raw PKCS#1 blob from an old signer, or the base64
was wrapped by the DNS presentation format. Strip quotes and spaces, decode with
`base64 -d`, and if `openssl pkey` still fails try `openssl rsa -pubin -inform DER`.

### M6. `dkimverify` says the body hash failed

Either the message was modified after signing (a list footer, a subject tag, a
signature appended by a gateway) or the canonicalization you assumed is not the
one in `c=`. Re-run with the canonicalization the header names, and compare the
received body against the signed body before blaming the signer.

### M7. Test message never arrives

Check the SMTP transcript first: a 5xx at `RCPT TO` is a policy rejection, a 4xx
is a temporary failure, and a 250 with no delivery points at the receiving side's
filtering. None of these is an authentication verdict, and none should be recorded
as one.

### M8. `dmarc=fail` on legitimate mail only from one flow

Usually the flow signs with a subdomain selector while `adkim=s` requires the
exact From domain, or the flow's ESP uses its own envelope domain without a
custom return-path. Read `header.d` and `smtp.mailfrom` in the
`Authentication-Results` line: the values identify the flow unambiguously.

### M9. Reports exist but contain nothing

A `rua` destination at another organizational domain without the
`<dest>._report._dmarc.<source>` authorization record receives no reports, and the
owner sees silence. Check the authorization record before concluding that no mail
is being sent.

### M10. Version and platform differences

`nslookup` on Windows does not show TTL or multi-string framing. `dig` on macOS is
an older BIND build that lacks some flags. `openssl 3.x` renames several commands.
When a command fails, check `<tool> --help` before assuming the technique is wrong,
and record the version in the evidence set.

## N. Limitations and Known Issues

- This skill establishes configuration-level spoofability. It does not observe
delivery unless an empirical test is authorized, and delivery also depends on
receiver-side reputation and filtering that no DNS record controls.
- SPF term accounting depends on the resolver seeing the same records the receiver
sees. Split-horizon DNS, geo-DNS and provider-side rewriting can make a static
count wrong; the count is evidence about the record, not about every receiver.
- DKIM verification validates signatures, not intent. A valid signature says the
domain's key signed the content, nothing about whether the sender was authorized
in a business sense.
- DMARC semantics follow RFC 7489 as published. The specification has an active
revision process; where a receiver implements a newer draft, behaviour at the
margins (subdomain discovery, reporting) can differ. Verify the current status at
the IETF datatracker before asserting normative detail in a report.
- Aggregate-report analysis is only as good as the report coverage. Absence of a
failing source in reports is not evidence that no spoofing occurred.
- The bundled contract checker validates document structure, not technical
correctness. A skill can be structurally perfect and still contain a wrong
command; only review and execution catch that.
- No tool named here is bundled with this repository, and none is required for the
checker to run.

## O. Quality Assurance Checklist

Before delivering an assessment, confirm each line.

```text
[ ] authorization record exists, is quoted in the report, and covers every domain tested
[ ] every domain was resolved at least twice, and the resolver is named
[ ] SPF term count is reproducible by hand from captured records
[ ] multiple v=spf1 records were reported as permerror, not merged
[ ] DKIM key size and algorithm were decoded, not inferred from the record text
[ ] DMARC policy was read, including pct, sp, adkim and aspf
[ ] alignment was evaluated against real flows, not assumed from a DNS record
[ ] at least one receiver verdict was read for a legitimate flow, or its absence is declared
[ ] unperformed checks are listed as gaps, not omitted
[ ] every claim cites a capture with a timestamp
[ ] no message body, recipient address or credential appears in the evidence
[ ] remediation is sequenced monitoring -> alignment -> enforcement, with owners
[ ] the verification procedure is included and re-runnable
```

## P. References

RFCs and standards:

- RFC 7208, Sender Policy Framework (SPF) for Authorizing Use of Domains in Email: https://www.rfc-editor.org/rfc/rfc7208.html
- RFC 6376, DomainKeys Identified Mail (DKIM) Signatures: https://www.rfc-editor.org/rfc/rfc6376.html
- RFC 8301, Cryptographic Algorithm and Key Usage Update to DKIM: https://www.rfc-editor.org/rfc/rfc8301.html
- RFC 7489, Domain-based Message Authentication, Reporting, and Conformance (DMARC): https://www.rfc-editor.org/rfc/rfc7489.html
- RFC 8617, The Authenticated Received Chain (ARC) Protocol: https://www.rfc-editor.org/rfc/rfc8617.html
- RFC 8601, Message Header Field for Indicating Message Authentication Status: https://www.rfc-editor.org/rfc/rfc8601.html
- RFC 5321, Simple Mail Transfer Protocol: https://www.rfc-editor.org/rfc/rfc5321.html
- RFC 8461, SMTP MTA Strict Transport Security (MTA-STS): https://www.rfc-editor.org/rfc/rfc8461.html
- RFC 8460, SMTP TLS Reporting: https://www.rfc-editor.org/rfc/rfc8460.html

Weakness and technique mapping:

- MITRE CWE-290, Authentication Bypass by Spoofing: https://cwe.mitre.org/data/definitions/290.html
- MITRE ATT&CK T1566, Phishing: https://attack.mitre.org/techniques/T1566/
- MITRE ATT&CK T1656, Impersonation: https://attack.mitre.org/techniques/T1656/
- NIST SP 800-177 Rev. 1, Trustworthy Email: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-177r1.pdf

Tool documentation:

- OpenDKIM project: http://www.opendkim.org/
- dkimpy verification library: https://launchpad.net/dkimpy
- checkdmarc: https://github.com/domainaware/checkdmarc
- parsedmarc: https://github.com/domainaware/parsedmarc
- dmarc.org overview: https://dmarc.org/
- Python SSL module: https://docs.python.org/3/library/ssl.html
