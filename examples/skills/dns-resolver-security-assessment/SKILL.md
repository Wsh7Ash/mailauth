---
name: dns-resolver-security-assessment
id: dns-resolver-security-assessment@1.0.0
version: 1.0.0
category: network-protocol-security
domain: dns-resolution
description: Authorized assessment of a recursive resolver's resistance to answer forgery and cache corruption, covering transaction identifier and source port entropy, bailiwick enforcement, DNSSEC validation state, cache snooping and open recursion.
agent: single-file skill, self-contained, no network egress until the section D authorization gate is satisfied
knowledge: RFC 1035 message format, RFC 5452 forgery resistance, RFC 2181 trust levels, RFC 4033 to 4035 DNSSEC, RFC 7873 cookies, RFC 2308 negative caching, Kaminsky-class cache poisoning
tools: [dig, kdig, dnspython, python3, tcpdump]
os: [linux, darwin]
permissions: [network-egress-to-scoped-resolver-only, no-packet-crafting-outside-engagement-lab]
dependencies: [bind9-dnsutils, python3.10, dnspython]
cwe: [CWE-350, CWE-345]
owasp: [WSTG-CONF-01]
attack: [T1557, T1565]
references: [RFC1035, RFC5452, RFC2181, RFC4035, CWE-350]
---

# DNS Resolver Security Assessment

A single-file procedure for answering one question with evidence: can an attacker who cannot see the traffic make this resolver accept an answer that the domain owner never published, and if not, what specifically stops them.

## A. Skill Metadata

- **Name:** `dns-resolver-security-assessment`
- **Version:** 1.0.0. Semver; a change to the procedure's required observations is a major bump.
- **Category:** network-protocol-security. **Domain:** dns-resolution.
- **Applicability:** recursive resolvers you operate or are authorized to assess — self-hosted Unbound, BIND, PowerDNS Recursor, Knot Resolver, dnsmasq, a cloud resolver you can address directly, or a forwarder that recurses on your behalf.
- **Not applicable:** authoritative-only servers (a different assessment: zone transfer, lame delegation, DNSSEC signing), and any resolver you can only reach through a third party's network.
- **Expected runtime:** 2–4 hours for fingerprint, entropy sampling and the DNSSEC matrix on one resolver; the forgery-resistance conclusion additionally requires either a test authoritative server you control or a configuration review, which the skill treats as two different evidence grades.
- **Deliverable:** a per-resolver verdict for each of six properties, with the query transcript, the measured distributions, and an explicit statement of which conclusions rest on measurement and which on configuration reading.
- **OWASP mapping note:** the WSTG reference in the metadata is a loose mapping (network infrastructure configuration). DNS resolver behaviour is not covered by the WSTG test cases in any depth; the RFCs are the governing sources, and section P cites them first for that reason.

## B. Executive Overview

A recursive resolver is a cache that believes whoever answers first. It sends a query for `www.example.com` to some server it has never spoken to before, and accepts the reply if the reply carries the right transaction identifier (TXID, 16 bits), arrives from the right address and port, and asks about the right name. An off-path attacker who can guess those values, and who can send packets with a forged source address, wins the race and installs an answer in the cache. Every client that later asks the resolver for that name gets the attacker's address, for as long as the TTL allows.

That is the whole threat, and the defences are all about making the guess expensive and the acceptance narrow:

1. **Entropy.** RFC 5452 requires source port randomisation in addition to TXID randomisation; 16 + 16 bits is 32 bits, about four billion guesses. Guessable ports, a fixed TXID, or a predictable sequence collapse that to something an attacker can brute-force within one TTL.
2. **Bailiwick enforcement.** A reply from the `com` servers may only assert data inside `com`. A resolver that accepts a `A` record for `www.bank.example` inside a reply it requested for `example.com`'s nameservers has no trust boundary at all, and one poisoned reply can take over an unrelated domain.
3. **DNSSEC validation.** A validating resolver checks the RRSIG chain from the root's trust anchor down to the answer's zone. This converts forgery from "hard" to "cryptographically infeasible" for signed zones — but only for signed zones, and only if validation is actually on for the path in question.
4. **Source-address and reachability controls.** An open resolver is an amplifier; a resolver reachable from the whole internet is a target. Response Rate Limiting and query ACLs do not stop poisoning, but they shrink the population an attacker can work against.
5. **Cache hygiene.** Negative caching, minimum TTL enforcement, and refusal to cache out-of-bailiwick glue decide how long a successful forgery persists and whether a single reply can seed many names.

This skill assesses those five areas as six separable properties, because they fail independently and have different fixes:

| Property | Question | Fix when it fails |
|---|---|---|
| Entropy | can TXID and port be predicted? | randomise both, upgrade the resolver |
| Bailiwick | is out-of-zone data discarded? | upgrade or reconfigure |
| DNSSEC | is a bogus answer refused? | enable validation, install trust anchor |
| Exposure | is recursion open to the internet? | ACL, RRL, split-horizon |
| Cache behaviour | can a third party read or extend the cache? | disable snooping, cap TTLs |
| Transport | does it survive fragmentation and fall back to TCP? | tune EDNS buffer, enforce cookies |

Two honesty rules govern the whole document. First, **a resolver's resistance to forgery cannot be proven by querying it** — you cannot measure entropy from outside without controlling the authoritative server it talks to, and you cannot send forged replies at all without either a lab or a licence to spoof. Second, **a DNSSEC test result is evidence about one name at one moment**; the answer depends on the zone's signatures, the chain's current state, and the resolver's cache, all of which change.

So the skill is explicit about evidence grades. `measured` means you sent queries and recorded replies. `observed` means you saw behaviour consistent with a property without isolating it. `read` means you inspected configuration or documentation. `unverified` means you did neither. Every finding must carry one of those four labels, and a report that upgrades `read` to `measured` in its summary is wrong even if the conclusion happens to be correct.

Run nothing before section D. The queries in this skill are individually harmless, but they are queries to infrastructure that may be someone else's, and the entropy phase requires sending traffic to a resolver at a rate that a shared service will notice. The authorization gate exists to make that traffic deliberate.

## C. Technical Foundations

### C.1 The resolution path and where trust is placed

A stub resolver asks a recursive resolver. The recursive resolver, if it has no cached answer, walks down from the root: it asks a root server for the `com` delegation, then a `com` server for the `example.com` delegation, then `example.com`'s authoritative server for the record. Each step is a separate query to a server the resolver has not authenticated in any way beyond "it answered from the address the delegation named".

The delegation itself carries two things: NS records naming the child's servers, and glue address records for those servers when they are inside the child zone (necessary to avoid a circular dependency). Glue is the sharp edge. A `com` server's reply for `example.com` may include addresses for `ns1.example.com`, which is *inside* `example.com` — data the `com` server is not authoritative for but must supply anyway. A resolver that treats glue as trustworthy data for anything other than reaching that nameserver has created a cache-poisoning primitive out of a necessary protocol feature.

### C.2 Message format and the identifier the attacker must guess

An RFC 1035 message has a 16-bit ID, flags, four section counts (question, answer, authority, additional), and then the sections. The response must match the query on: ID, question name (case-insensitively), question type, question class, and — for a strict resolver — the source address and port the query was sent from. Related but distinct fields are the `RA` (recursion available), `AD` (authenticated data) and `CD` (checking disabled) bits in the flags word, which the assessment uses as evidence rather than as controls.

The ID is 16 bits. The source port is another 16 bits when the resolver randomises it. RFC 5452 is precise about why both are required: with 16 bits alone, an attacker sending 65,536 guesses has a 63% chance of a hit on a single query, and can simply retry on the next one. With 32 bits of entropy and a rate limit of, say, 10,000 forged packets per second, the same attacker needs on the order of days per attempt, by which time the query has long since been answered legitimately.

### C.3 The Kaminsky technique, and why the 2008 fix is still the test

The 2008 attack does not try to forge the answer to `www.target.example`. It asks for `random.target.example`, which forces the resolver to ask `target.example`'s nameservers for a delegation it does not have, and then floods the resolver with forged *authority* records naming an attacker-controlled nameserver for `target.example`. One accepted reply does not poison one name; it moves the delegation, and every subsequent name under that zone goes to the attacker.

The fix was source port randomisation plus stricter question matching, and the attack's modern form is a measurement question: how many bits does an off-path attacker have to guess, and how many guesses can they make before the legitimate answer arrives?

### C.4 DNSSEC, in the shape the assessment needs

A signed zone publishes DNSKEY records and signs each RRset with RRSIG. The parent publishes a DS record that commits to a digest of the child's KSK. A validating resolver walks that chain from a configured trust anchor (normally the root's KSK, or the IANA root anchor) down to the answer.

Four outcomes matter, and a competent resolver must distinguish all four:

- **Secure** — signatures validate from the anchor; the answer is trustworthy.
- **Insecure** — the zone is unsigned (no DS at the parent); the answer is accepted but unauthenticated.
- **Bogus** — the zone is signed but a signature failed, or the chain is broken; the resolver must return SERVFAIL, not the data.
- **Indeterminate** — the resolver could not determine the state (network failure, unsupported algorithm); SERVFAIL is the required behaviour.

The `AD` bit is the resolver's claim that it validated. It is only meaningful from a trusted resolver, because a stub can set it; a test that reads `AD` from a forwarder you do not control is reading that forwarder's opinion, not a validation result.

### C.5 Why "it validates DNSSEC" is not a single property

Validation can be enabled globally and disabled per zone (`validate-except`), per view, or for specific algorithm families (a resolver with an old algorithm list will treat a modern-signature zone as insecure rather than bogus). It can be configured to trust a local anchor in addition to the root. It can be disabled by the `CD` bit on the inbound query, which asks the resolver to skip checking and return data anyway — a legitimate feature used by validating stubs, and a complete bypass if an attacker can set it and the resolver honours it from an untrusted client.

The assessment therefore tests a matrix, not a flag: a known-signed zone, a known-unsigned zone, a deliberately broken signature (from a zone you control, or from a public test domain that exists for this purpose), and the same queries with `CD=1`.

### C.6 Cache behaviour is part of the attack surface

A cache is shared state with an access-control question attached. Three behaviours matter. **Snooping** — if any client can query for a name and learn whether it was recently resolved, the cache becomes an oracle for what other users on that resolver are doing (RFC 8482 and the general privacy literature treat this as a real exposure). **Negative caching** — NXDOMAIN and NODATA are cached too (RFC 2308), so a forged negative answer denies a name for its negative TTL, which is an availability attack that looks like a typo. **TTL handling** — a resolver that honours an absurd TTL from an authoritative server holds a poisoned or stale answer far longer than the zone owner intended; a resolver that clamps TTLs to a floor reduces its own exposure.

### C.7 Transport details that change results

EDNS(0) advertises a UDP buffer size. A resolver that advertises 4096 and receives a fragmented response is exposed to fragmentation-based attacks and to middlebox drops; one that falls back to TCP on truncation is doing the right thing. DNS cookies (RFC 7873) give the resolver a lightweight way to check that a reply comes from a party that has seen its query. DNS over TLS and over HTTPS move the encryption boundary, but they do not change what the resolver must do internally, and a validating resolver behind an encrypted transport is still the component being tested.

### C.8 What this class is not

A resolver that answers queries from the internet is not automatically vulnerable — being open is an abuse and amplification problem (a different finding, with a different fix) rather than a poisoning problem. A DNSSEC-signed zone with a weak key is a zone-operator issue. A network that permits source-address spoofing is the precondition for off-path forgery and is itself a finding, but it belongs to the network assessment, not to the resolver's configuration.

The distinction matters because the fixes have different owners, and a report that conflates them sends the wrong team to the wrong console.

## D. Prerequisites and Environment

### D.1 Authorization gate

Every line below must have a written answer before the first query:

- **Permitting document** naming the resolver operator and the exact addresses under test.
- **Resolver addresses**, including every instance behind an anycast or load-balanced address, or an explicit statement that only the address you were given is in scope.
- **Whether recursion may be exercised from outside the operator's network.** Testing open recursion from the internet is the point of one phase and is also the phase most likely to look like abuse; get it in writing.
- **Query rate and total budget.** A resolver under test is production infrastructure; a few queries per second for a few minutes is a different risk from a sustained loop.
- **Window and emergency contact**, including who can stop the test and how.
- **Prohibited effects**, at minimum: no source-address spoofing outside an isolated lab, no amplification testing, no zone transfer against a zone you do not own, no load testing.

If a line is missing, ask in writing. Section K converts this into stopping rules.

### D.2 Two evidence paths, declared up front

Decide before starting which path the engagement supports, and record the choice:

- **Measurement path** — you control an authoritative server that the resolver will query, so you can observe the resolver's queries (TXID distribution, source ports, query case) and send it controlled responses. This is the only way to measure entropy and bailiwick behaviour. It needs a domain, a server, and the resolver operator's agreement that the resolver may reach it.
- **Configuration path** — you have read access to the resolver's configuration and version, and may read rather than measure. Conclusions carry the `read` grade and the report must say so.

Most engagements support only the second. That is not a reason to skip the first in the report; it is a reason to state the grade.

### D.3 Client environment

- `dig` from BIND 9 utilities for transcripts, because its output is stable and quotable; `+norecurse`, `+dnssec`, `+cdflag`, `+tcp`, `+bufsize=512` are all needed, and `+noall +comments +question +answer` keeps evidence small.
- `kdig` from Knot DNS when you need `+tls`, `+https`, or precise cookie control.
- `dnspython` for anything scripted: it exposes the message object, so you can read the flags word, the counts, and the RRSIG expiry directly rather than parsing text.
- `tcpdump` for your own packets only, to confirm what you actually sent (`-i any -n udp port 53 -c 50 -w own.pcap`).
- A resolver under test that you can reach on port 53 over UDP and TCP. If only TCP is reachable, say so: UDP is where the attack lives.

Never point these tools at a resolver outside the scope line because it happens to answer. An open resolver on the internet is not an invitation.

### D.4 Readiness checklist

1. Resolver addresses and the scope statement recorded in the engagement log.
2. A local authoritative test zone prepared, if the measurement path is available.
3. A control domain known to be signed, one known to be unsigned, one known to be broken, and their current states noted with a timestamp.
4. Query budget and rate written into the job object (section J).
5. Capture directory created with a naming convention that includes the resolver address and the phase.

## E. Detailed Operational Methodology

### Phase 1 — Restate scope and record the target set

Write the addresses, the permitted query rate, and the evidence path (measurement or configuration) into the engagement log. No traffic. This phase exists so that every later packet is attributable to a documented permission.

### Phase 2 — Fingerprint the resolver

Purpose: establish which software and version you are testing, whether recursion is open, and which EDNS features are supported.

```bash
dig @resolver.example version.bind CH TXT +short
dig @resolver.example hostname.bind CH TXT +short
dig @resolver.example id.server CH TXT +short
dig @resolver.example +norecurse example.com A +noall +comments
```

Interpretation: a version string is a gift — map it to the vendor's security advisories before anything else, because an unpatched resolver from before the port-randomisation work is a finding regardless of what else you observe. A refused or empty `version.bind` is good practice, not a defect. The `+norecurse` probe tells you whether the resolver answers from cache for a non-recursive query, which is also the basis of the snooping phase.

Open recursion: query a name you control that is not cached, from outside the operator's network, and see whether it resolves. If it does, record it as `observed` open recursion, with the query and response as evidence. Do not proceed to sustained querying from outside the network.

### Phase 3 — Entropy assessment

Purpose: determine how many bits an off-path attacker must guess.

**Measurement path.** Point a test zone's NS record at your own authoritative server, then ask the resolver for a series of names under that zone (each unique, so nothing is cached). Your server logs each incoming query: the TXID, the source address and port, and the exact case of the query name. Fifty queries are enough for a distribution; two hundred is better.

What to compute: distinct TXIDs, distinct source ports, whether ports are sequential, whether ports fall in a narrow band, whether TXIDs are sequential or derived from a counter, and whether the query name's case varies (0x20 encoding). Report the entropy estimate as bits, not as an adjective, and state the sample size. Two hundred samples with 190 distinct TXIDs is consistent with 16 bits of randomisation; the same sample with 3 distinct TXIDs is a fixed identifier and a finding.

**Configuration path.** Read the resolver's version and its randomisation settings. BIND's `use-v4-udp-ports`/`avoid-v4-udp-ports` ranges, Unbound's port selection, and any setting that pins the source port matter. Record as `read` and say so.

Error handling: if your authoritative server never receives the query, the resolver is either answering from cache, blocked from reaching you, or answering from a forwarder. Force cache misses with unique labels, and check the resolver's egress path with the operator.

### Phase 4 — Bailiwick and glue handling

Purpose: test whether out-of-zone data in a reply is discarded.

With your own test zone (or a lab resolver), return an answer for `attacker.example` that also contains, in the additional section, an `A` record for `victim.example` (a domain you control separately, standing in for a third party). Query the resolver for `victim.example` afterwards. If it returns the address from your additional section without ever asking `victim.example`'s nameservers, the resolver cached out-of-bailiwick data and the property fails.

A weaker but non-destructive variant, when you cannot control an authoritative server: query a domain whose delegation includes glue and check whether the resolver's answer for a *sibling* name reflects data that only the parent could have supplied. This is `observed`, not `measured`.

Error handling: a resolver that answers from cache because a previous test already populated the name will look like a failure. Use a fresh label per attempt and record the query timestamp.

### Phase 5 — DNSSEC validation matrix

Purpose: determine whether the resolver enforces validation, and whether the enforcement can be turned off by the client.

Run four queries, each with `+dnssec`, and record status, `AD` bit and answer presence: a currently signed zone (expect NOERROR, `AD` set), an unsigned zone (expect NOERROR, no `AD`), a known-broken-signature zone or your own deliberately broken zone (expect SERVFAIL), and the broken one again with `+cdflag` (expect NOERROR with data, if the resolver honours `CD` from this client).

```bash
for q in signed.example unsigned.example broken.example; do
  dig @resolver.example "$q" A +dnssec +noall +comments +answer | sed -n '1,12p'
done
dig @resolver.example broken.example A +dnssec +cdflag +noall +comments +answer
```

Interpretation: a resolver that returns data for the broken zone, without `AD`, is non-validating — it may still be forwarding `AD` from upstream, which the next check distinguishes. A resolver that returns SERVFAIL for the broken zone and data for the signed one is validating. A resolver that returns SERVFAIL for *everything* with `+dnssec` is probably unable to reach the trust anchor, which is a different and equally reportable defect.

Error handling: public test domains change state. Verify the expected state of each control domain on the day of the test with a validating resolver you trust, and record that verification alongside your result.

### Phase 6 — Cache exposure and negative caching

Snooping: for a name you have just resolved through the resolver, send the same query with `+norecurse`; a cached answer returned to a non-recursive query is cache exposure to whoever can reach the resolver. Repeat for a name you control that a second client resolved, to show the oracle rather than a single hit.

Negative caching: query a non-existent name under a zone you control, note NXDOMAIN, then create the name and query again within the negative TTL. If the resolver keeps returning NXDOMAIN for the remainder of that TTL, negative caching is behaving as specified — that is correct behaviour and not a finding, but it is the mechanism a forged negative answer would use, so it belongs in the report's threat model. Record the negative TTL the resolver reports in the SOA minimum field.

### Phase 7 — Transport behaviour

Test UDP with a small buffer (`+bufsize=512`) against a name with a large answer, and observe truncation and TCP fallback. Test EDNS presence with `+noedns`. Test cookies if the resolver supports them: `kdig +cookie @resolver.example example.com`. Then test the encrypted path if it is offered, and record whether validation results are the same over TLS as over UDP — a resolver that validates on one path and not the other is a split-brain configuration worth reporting.

### Phase 8 — Confirm, consolidate, and clean up

For each property, assign one of `measured`, `observed`, `read`, `unverified`, and write the single observation that supports it. Where two phases disagree, the stronger grade wins only if it isolates the property; otherwise report the disagreement, because a resolver that validates for one client and not another is a real configuration defect that a single grade would hide.

Clean up: remove test records from your authoritative server, allow the test names to expire from the resolver's cache (or ask the operator to flush them), and confirm that the resolver's normal behaviour is unchanged with a control query. Record the cleanup in the engagement log.

## F. Practical Technical Examples

### F.1 A quotable transcript

```text
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41377
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;www.example.com.               IN      A
;; ANSWER SECTION:
www.example.com.        300     IN      A       203.0.113.10
```

`ad` in the flags line, with the `do` bit in the OPT pseudosection, is the evidence that a validating resolver returned an authenticated answer. Save the whole block, not the one-line `+short` output, because the flags are the finding.

### F.2 Measuring TXID and port distribution

```python
import collections, dns.resolver

seen_id, seen_port = collections.Counter(), collections.Counter()
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["192.0.2.53"]
for index in range(200):
    qname = f"probe-{index}.test.example"
    try:
        resolver.resolve(qname, "A", lifetime=2.0, raise_on_no_answer=False)
    except Exception:
        pass  # NXDOMAIN and timeouts are both expected; the log on our server is the data
print("samples", sum(seen_id.values()))
```

The script's own counters are illustrative; the authoritative measurement is the query log on the server that receives the probes. Read that log, not this output, and state the sample size in the report.

### F.3 Distinguishing validating from forwarding

Ask a resolver you control to be a forwarder for a validating upstream, then point the test resolver at it and repeat the broken-signature query. If the upstream SERVFAILs and the test resolver returns NOERROR, the test resolver is not validating and is trusting `AD` from upstream. This is the single most common misdiagnosis in this assessment, and the fix (enable validation on the resolver, do not just chain it to a validator) is different from what a superficial reading would suggest.

### F.4 A realistic false positive

A tester queries `broken.example`, receives NOERROR with an `AD` bit, and reports that DNSSEC validation is bypassed. In fact the query reached a resolver whose cache already held the answer from before the zone's signatures were broken, and the `AD` bit was cached with it. The exclusion is to use a unique name per attempt and to confirm the zone's current state independently on the same day. A cache does not care that the zone changed; the report must.

### F.5 Proving bailiwick failure without spoofing

If the resolver is a lab instance, run your own authoritative server for `test.example`, and in the additional section of a legitimate reply include an address for `victim.test`. Then query `victim.test` through the resolver. A resolver that answers with your injected address has cached data from outside the zone it asked about, and the failure is demonstrated with ordinary queries and no forged source addresses — which is what makes the test acceptable on a shared network.

## G. Tools and Commands

| Purpose | Command | Note |
|---|---|---|
| Version probe | `dig @resolver version.bind CH TXT +short` | absence is good practice |
| Recursion check | `dig @resolver +norecurse example.com A` | cached answer to a non-recursive query is snooping evidence |
| Validation | `dig @resolver signed.example A +dnssec +noall +comments` | read the `ad` flag, not just the address |
| CD bypass | `dig @resolver broken.example A +dnssec +cdflag` | data returned means `CD` is honoured |
| TCP fallback | `dig @resolver +tcp big.example TXT` | compare with UDP result |
| Cookies | `kdig +cookie @resolver example.com` | RFC 7873 support |
| Encrypted path | `kdig +tls @resolver example.com` | compare validation over TLS |
| Packet truth | `tcpdump -i any -n 'udp port 53' -c 50 -w own.pcap` | your own packets only |
| Scripted | `python` with `dnspython` | read flags and counts from the message object |

Tool discipline: `dig` prints what it parsed, which may differ from what arrived. When a result is surprising, keep the pcap for that query and read the wire bytes, because a mismatch between wire and output is itself a finding about the client, not the resolver. Do not use `+trace` against a resolver under test — it performs the resolution from your host, so it measures your network rather than the resolver.

Two habits belong in the engagement log for every transcript. Record the address actually queried, from the `;; SERVER:` line, because a stub configuration that silently redirects to a local forwarder produces transcripts that look authoritative and are measuring the wrong machine. Keep the exact invocation beside its output as well: a reader reproducing a claim needs the flags (`+dnssec`, `+cdflag`, `+norecurse`, `+tcp`) as much as the result, since each flag changes which question the resolver is being asked.

## H. Vulnerability Discovery and Validation

### H.1 Evidence grades, and what each one licenses you to claim

| Grade | Meaning | Permitted claim |
|---|---|---|
| `measured` | you controlled the peer or the resolver and observed the property directly | "the resolver does X" |
| `observed` | behaviour consistent with the property, not isolated from alternatives | "the resolver behaves as if X" |
| `read` | configuration or vendor documentation states the property | "the configuration sets X" |
| `unverified` | neither | "not tested" — never omit the row |

A finding may combine grades only by stating both. "Port randomisation is configured (`read`) and 187 distinct source ports were seen across 200 probes (`measured`)" is a sentence that survives review. "The resolver is not vulnerable to cache poisoning" is not a claim this assessment can support at any grade, because no external test proves the absence of a race condition.

### H.2 The observation that supports each property

| Property | Observation that proves it | Observation that does not |
|---|---|---|
| Entropy | distribution of TXIDs and source ports logged by your authoritative server | a single query that "looked random" |
| Bailiwick | your injected out-of-zone record returned by the resolver without a query to that zone's servers | an out-of-zone record present in a reply you received (that is the server's reply, not the cache) |
| DNSSEC validation | SERVFAIL for a currently-broken signed zone, NOERROR with `ad` for a signed zone, on the same day | an `ad` bit alone, which a forwarder can pass through |
| Exposure | a successful recursive resolution from outside the operator's network | an open port 53 |
| Cache behaviour | a `+norecurse` query answered from cache, for a name another client resolved | a fast answer, which may be a local cache hit by the stub |
| Transport | truncation followed by a TCP query carrying the full answer | a UDP answer that happened to fit |

### H.3 False positives, each with its exclusion

- **"The resolver returned data for a broken zone."** Either the zone is no longer broken, or the answer was cached before the break. Exclusion: unique name per attempt, independently confirm the zone state on the day, and record both.
- **"The resolver is open."** A query from inside the operator's network proves nothing about the internet. Exclusion: run the same query from an address outside, within the permitted window, and record the source address used.
- **"The resolver cached our injected record."** The record may have been in the reply the resolver legitimately requested. Exclusion: query a *sibling* name the injected record did not cover, and check whether the resolver asks the real authority.
- **"Validation can be bypassed with `CD`."** `CD` from a trusted client is a documented feature; from an untrusted client it is a defect. Exclusion: state which client set the bit and from where.
- **"The cache is poisoned."** A local stub cache, a forwarding chain, or the tester's own resolver may be answering. Exclusion: query the resolver directly by address, bypassing your stub configuration, and record the full `;; SERVER:` line.

### H.4 When the honest verdict is untestable

Three situations justify it, and each must be written as a statement about the test: no authoritative server you control and no access to configuration (entropy and bailiwick become `unverified`); the permitted surface excludes queries from outside the operator's network (exposure becomes `unverified`); or the resolver is a managed service whose configuration you cannot read and whose internals you cannot observe (most properties become `unverified`, and the report should say which questions the operator must answer instead).

## I. Advanced Techniques

### I.1 Query-name case randomisation (0x20)

A resolver that randomises the case of the query name adds roughly one bit per letter of entropy, and a strict resolver compares the case of the reply's question section with what it sent. Measure it from your authoritative server's log: if `wWw.ExAmPle.CoM` arrives in varying case and the resolver rejects a reply that returns the name in a different case, the property is present. Report it as a supplement to TXID and port entropy, never as a replacement, because RFC 5452 does not treat case as a substitute.

### I.2 Fragmentation and the buffer-size advertisement

A resolver advertising a 4096-byte UDP buffer invites fragmented responses, which are dropped by many middleboxes and reassembled by others, creating both a denial-of-service surface and a parsing surface. Test it by querying a name with a large answer set over UDP and recording whether the response is fragmented (`tcpdump -vv` shows the fragment flags) and whether the resolver retries over TCP. The recommended posture is a modest advertisement and prompt TCP fallback.

### I.3 NSEC walking

For a signed zone using NSEC rather than NSEC3, a resolver will happily perform a sequence of queries that enumerates the zone's names. This is a property of the zone, not of the resolver, but the resolver is the amplifier: it will answer every step of the walk from cache or by recursion. Report it against the zone owner, and note that a resolver configured to rate-limit identical-question streams reduces the amplification without hiding the zone's design choice.

### I.4 Zone transfer against a resolver

A recursive resolver does not serve zones, so an `AXFR` against it should fail. If it succeeds, you have found an authoritative role on the same address, which changes the assessment entirely and is worth its own finding. Test it only against zones you own.

### I.5 Split-brain and anycast behaviour

Query the same name repeatedly against an anycast address and compare answers, `ad` bits and version strings across responses. Divergent validation state across instances means one instance was configured and the others were not, and a client's security depends on which instance the routing sent it to. This is one of the most commonly missed findings in managed estates, and it is found by repetition rather than by any single query.

### I.6 Forwarder trust

If the resolver forwards to an upstream, the upstream's behaviour is part of the resolver's effective security. Ask the operator which upstreams are configured, then test whether the resolver accepts `AD` from them without validating, whether it forwards `CD`, and whether it applies its own cache TTL policy. A forwarding chain is not automatically weaker, but it moves the trust boundary and the report must place it.

### I.7 DNS rebinding, adjacent but distinct

A resolver that honours very low TTLs and does not pin answers lets a browser be rebound to an internal address. The resolver's contribution is TTL handling and cache policy; the browser's is address pinning. If the engagement includes an internal application, this belongs in scope, and the test is a TTL-0 record on a domain you control, resolved twice, with the two answers compared.

## J. Automation and AI Agent Integration

### J.1 What the agent may do

An agent may run phases 2, 3 (collection only), 5, 6 and 7: fingerprint, sampling, the validation matrix, cache probes and transport checks. It may not decide that a resolver is secure, may not send forged responses, and must not vary the query rate beyond the job object. The judgement calls — whether a bailiwick result is a failure, whether an `ad` bit came from upstream — require reading the transcript, and a model that summarises instead of quoting will get them wrong.

### J.2 Job object

```json
{
  "resolver": "192.0.2.53",
  "authorization_reference": "engagement-2026-11-03-dns",
  "allowed_phases": [2, 3, 5, 6, 7],
  "max_queries": 400,
  "rate_per_second": 2,
  "signed_control": "signed.example",
  "broken_control": "broken.example",
  "stop_on": ["timeout_streak", "servfail_storm", "unexpected_recursion"],
  "evidence_path": "measurement"
}
```

A phase not listed is not run, and the cap is enforced by the runtime, not by the model's sense of proportion.

### J.3 Skeleton with the guardrails in code

```python
import json, time
import dns.resolver

JOB = json.load(open("job.json", encoding="utf-8"))
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = [JOB["resolver"]]
resolver.timeout = 2.0
resolver.lifetime = 4.0
sent, timeouts = 0, 0

for index in range(200):
    if sent >= JOB["max_queries"] or timeouts >= 10:
        break
    qname = f"probe-{index}.test.example"
    try:
        resolver.resolve(qname, "A", raise_on_no_answer=False)
        timeouts = 0
    except dns.resolver.Timeout:
        timeouts += 1
    except dns.resolver.NXDOMAIN:
        pass
    sent += 1
    time.sleep(1.0 / JOB["rate_per_second"])
print(json.dumps({"sent": sent, "timeouts": timeouts}))
```

The ten-timeout threshold is a stop condition made mechanical: a resolver that stops answering is either under stress or blocked from reaching your test zone, and continuing would add load without adding evidence.

### J.4 Review gates for agent output

Reject any agent claim that does not quote a `dig` transcript or a log line, does not name the evidence grade, or reports an `ad` bit without the status code that accompanied it. A model asked whether a resolver validates will often answer from the presence of `+dnssec` in the command it just ran; the reviewer's job is to check that the query actually targeted a zone whose signature state was known that day.

## K. Security, Authorization and Operational Safety

This section is the boundary. Every step above presumes a written **authorization** naming the resolver operator, the exact addresses, the permitted query rate and the time window; the **scope** line must cover any address you address packets to, including anycast members and forwarders you discover. Nothing in this document authorises testing a resolver because it answered a query.

**Stopping rules.** Stop, notify the contact in the permitting document, and record the time when any of the following happens:

1. The resolver stops answering your control queries, or a timeout streak reaches the threshold in the job object.
2. A colleague, monitor, or the contact reports resolver distress, or you observe SERVFAIL for names unrelated to your test.
3. You receive responses for a name you did not query, which suggests another client's traffic is reaching you.
4. Your query count or window limit is reached.
5. The contact invokes the stop procedure, for any reason, including one you think is mistaken.

**Prohibited outright.** Source-address spoofing outside an isolated lab; sending forged DNS responses to any resolver you do not own; amplification or reflection testing; zone transfers against zones you do not own; sustained querying from outside the operator's network; and any query whose purpose is to read another user's resolution history rather than to demonstrate that such reading is possible.

**Privacy.** A cache-snooping test proves an oracle exists. It must use names you control, resolved by accounts you control. Never query a name belonging to a real person or a real internal service to show what the cache remembers; the proof is that your own probe is answerable non-recursively.

**Cleanup.** Remove test records, let caches expire or ask the operator to flush the names you created, and confirm normal service with a control query. Record the cleanup, because an operator who later finds unexpected cached names deserves to know where they came from.

## L. Reporting and Documentation

Six parts, in this order:

1. **Claim per property** — one sentence each, with the evidence grade attached.
2. **Resolver inventory** — addresses, software and version, anycast members, forwarders, and the date and time of each observation.
3. **Transcripts** — the `dig` output for each control query, trimmed to the header, question and answer sections, with the command that produced it.
4. **Measured distributions** — sample size, distinct TXIDs, distinct ports, and the entropy estimate in bits, or an explicit statement that no measurement was possible.
5. **Remediation by owner** — resolver operator (validation, ACL, TTL policy), network team (egress filtering to prevent spoofing), zone owner (signing, NSEC3, key rollover).
6. **Coverage and grades** — which phases ran, which were skipped, and the grade table for all six properties.

Keep the bundle small: one transcript per property, the pcap for any surprising result, and the log extract that supports the entropy claim. A report that attaches two hundred `dig` outputs has hidden the six that matter.

## M. Troubleshooting and Edge Cases

**Everything returns SERVFAIL.** Check the resolver's egress and trust anchor before concluding anything. A resolver that cannot reach the root or has an expired anchor fails every DNSSEC query, which looks like strict validation and is actually an outage. Test a plain unsigned name: if that also SERVFAILs, the resolver is broken, not strict.

**`ad` is set even for unsigned zones.** Either a forwarder is setting it, or the resolver trusts a local anchor that covers the zone. Ask the operator for the anchor list; do not infer intent from the bit.

**No queries arrive at your test nameserver.** Cache, egress ACL, or a forwarder. Use a unique label per query, confirm the resolver can reach your address with the operator, and check whether your authoritative server is reachable from the resolver's network at all.

**Ports look random but TXIDs do not.** That is still a finding: 16 bits of entropy is guessable within a TTL by a determined attacker, and the combination is what RFC 5452 requires. Report the two distributions separately rather than averaging them into a single "looks fine".

**Results differ per query against the same address.** Anycast or a load-balanced pair. Repeat each test five times, report the per-instance result if you can distinguish instances, and never report the best or worst instance as if it were the resolver.

**`+norecurse` returns an answer you did not expect.** Some resolvers answer non-recursive queries from cache by design, some refuse. Both are defensible; what matters is whether an arbitrary client can use the resolver as a cache oracle. State which behaviour you observed and from which client address.

**The operator says validation is on and your test says otherwise.** The most common cause is a `validate-except` list, a per-view configuration, or a forwarder chain in which the last hop validates and the first does not. Ask for the configuration excerpt and reconcile the two claims in the report rather than choosing a winner.

## N. Limitations and Known Issues

- No external test can prove a resolver is resistant to cache poisoning. This assessment measures entropy, checks bailiwick behaviour in a lab, and reads configuration; the absence of a finding is not a proof of safety.
- Entropy estimates from 200 samples have wide error bars. Report the sample size and the raw counts so a reader can judge, rather than a single "32 bits" figure the data does not support.
- DNSSEC conclusions depend on the state of the control zones on the day of the test. A zone that is signed today may be unsigned next month, and vice versa.
- Anycast and managed services may present different behaviour per instance; a single-address assessment covers the address, not the fleet.
- The resolver's upstream is often outside the engagement's scope, so a forwarding chain's behaviour may be reportable only as a trust boundary, not as a tested property.
- Nothing in this document was executed against a live third-party resolver while writing it. Commands follow the cited RFCs and the documented behaviour of `dig`, `kdig` and `dnspython`; a tester must validate them against their own lab first.

## O. Quality Assurance Checklist

- [ ] Permitting document names every resolver address, including anycast members.
- [ ] Query rate, total budget, window and contact recorded.
- [ ] Evidence path (measurement or configuration) declared before the first query.
- [ ] Control zones' current states verified independently on the day of testing.
- [ ] Entropy reported as counts and sample size, not as an adjective.
- [ ] Bailiwick tested with a sibling name, not with the record in your own reply.
- [ ] `CD` behaviour attributed to a named client and source address.
- [ ] Anycast divergence tested by repetition, not assumed absent.
- [ ] No query touches a name belonging to a real person or service.
- [ ] Test records removed and caches flushed or expired.
- [ ] Every property carries an evidence grade; `unverified` rows are present.
- [ ] Remediation assigned to the right owner for each property.

## P. References

- RFC 1035, Domain names, implementation and specification — https://www.rfc-editor.org/rfc/rfc1035.html
- RFC 2181, Clarifications to the DNS specification, trust levels and glue — https://www.rfc-editor.org/rfc/rfc2181.html
- RFC 5452, Measures for making DNS more resilient against forged answers — https://www.rfc-editor.org/rfc/rfc5452.html
- RFC 4033, DNS security introduction and requirements — https://www.rfc-editor.org/rfc/rfc4033.html
- RFC 4034, Resource records for the DNS security extensions — https://www.rfc-editor.org/rfc/rfc4034.html
- RFC 4035, Protocol modifications for the DNS security extensions — https://www.rfc-editor.org/rfc/rfc4035.html
- RFC 7873, Domain name system cookies — https://www.rfc-editor.org/rfc/rfc7873.html
- CWE-350, Reliance on reverse DNS resolution for a security decision — https://cwe.mitre.org/data/definitions/350.html
- CWE-345, Insufficient verification of data authenticity — https://cwe.mitre.org/data/definitions/345.html
- MITRE ATT&CK T1557, Adversary-in-the-Middle — https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1565, Data Manipulation — https://attack.mitre.org/techniques/T1565/
- dnspython documentation and source — https://github.com/rthalley/dnspython
- Knot DNS documentation, kdig and cookie tooling — https://www.knot-dns.cz/docs/
- Python socket module, for raw query construction — https://docs.python.org/3/library/socket.html
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/

