---
name: http-desync-smuggling-assessment
id: http-desync-smuggling-assessment@1.0.0
version: 1.0.0
category: web-application-security
domain: http-message-framing
description: Authorized assessment procedure for HTTP request smuggling and desynchronization across proxy chains, covering CL.TE, TE.CL, TE.TE, CL.0, H2.CL and H2.TE classes with confirmation and containment rules.
agent: single-file skill, self-contained, no network egress until the section D authorization gate is satisfied
knowledge: RFC 9110 semantics, RFC 9112 HTTP/1.1 framing, RFC 9113 HTTP/2 framing, CWE-444 interpretation conflict, chunked transfer coding, connection pool reuse
tools: [curl, openssl, python3, h11, smuggler, burp-request-smuggler, tcpdump]
os: [linux, darwin]
permissions: [network-egress-to-scoped-host-only, no-write-outside-engagement-directory]
dependencies: [python3.10, curl, openssl]
cwe: [CWE-444, CWE-436]
owasp: [WSTG-INPV-15]
attack: [T1190, T1557]
references: [RFC9112, RFC9110, RFC9113, CWE-444, OWASP-WSTG-INPV-15]
---

# HTTP Desync Smuggling Assessment

A single-file procedure for establishing whether two HTTP hops disagree about where one message ends and the next begins, and for converting that disagreement into evidence an owner can act on without exposing another user's data.

## A. Skill Metadata

- **Name:** `http-desync-smuggling-assessment`
- **Version:** 1.0.0 (semver; breaking changes to the procedure bump the major).
- **Category:** web-application-security. **Domain:** http-message-framing.
- **Applicability:** any request path where a client-facing hop forwards requests to a second hop over a reused connection. Not applicable to a single-hop service with no intermediary.
- **Expected runtime:** 1–3 hours for topology and class triage on one endpoint; the confirmation ladder in section H adds 30–60 minutes per candidate.
- **Deliverable:** a per-endpoint verdict of confirmed, not-confirmed, or untestable, each with the byte-exact request, the observed response or timing, and a statement of what an attacker would and would not gain.
- **What this is not:** not a generic web scanner run, not a denial-of-service procedure, and not a licence to read another person's traffic. Section K governs the last point and is not optional.

## B. Executive Overview

Every HTTP message carries its own length in a header: either `Content-Length`, which counts bytes, or `Transfer-Encoding: chunked`, which frames the body as a series of size-prefixed chunks. When two software components in the same request path read those two headers and reach different conclusions, the boundary between message *n* and message *n+1* exists twice, at two different offsets. The component at the back of the chain then parses the tail of the attacker's first request as a *new* request — one that was never subjected to the front end's authentication, authorization, rate limiting, or WAF rules, because the front end never saw it as a request at all.

That is the whole vulnerability class in one sentence, and it is why the impact is almost always larger than the triggered symptom. A single probe may return nothing but a 400 or a two-second delay. The interesting consequence appears on the *next* request over the same connection, which may belong to a different user.

This skill treats the class as six separately-testable mechanisms rather than one bug:

1. **CL.TE** — the front end honours `Content-Length`, the back end honours `Transfer-Encoding`.
2. **TE.CL** — the reverse.
3. **TE.TE** — both honour `Transfer-Encoding`, but one of them fails to recognise the second header as chunked because of obfuscation, so it falls back to `Content-Length`.
4. **CL.0** — the front end believes the request has no body (or ignores the declared length) and forwards the body bytes anyway.
5. **H2.CL** — an HTTP/2 front end accepts a `content-length` that contradicts the DATA frame lengths, and the downgrade to HTTP/1.1 preserves the lie.
6. **H2.TE** — an HTTP/2 front end forwards a `transfer-encoding: chunked` header, which RFC 9113 forbids and which the HTTP/1.1 back end then obeys.

The classes are tested independently because they fail independently. A deployment that rejects a duplicated `Content-Length` may still be vulnerable to TE.TE obfuscation; a hop that strips `Transfer-Encoding` on the HTTP/1.1 path may still forward it on an HTTP/2 downgrade.

A completed assessment answers four questions per endpoint. Does a framing disagreement exist? Which two components disagree, and about which header? Is the back-end connection pooled, so that the consequence reaches a party other than the tester? And what is the smallest non-destructive observation that proves it — usually a timing difference or a synthetic marker reflected back, not exfiltration of a real request.

Do not run any part of this procedure outside a path where a written authorization names the hosts, the methods, the permitted test volume, and an emergency contact. Section D converts that requirement into a checklist; section K converts it into stopping rules.

## C. Technical Foundations

### C.1 How a receiver determines message length

RFC 9112 section 6.3 gives an ordered algorithm, and almost every desync exists because one implementation deviates from it:

1. If the message is a response to `HEAD`, a 1xx, a 204, or a 304, there is no body regardless of headers.
2. If `Transfer-Encoding` is present and its final coding is `chunked`, the body is chunked.
3. If `Transfer-Encoding` is present and its final coding is *not* `chunked`, the server must respond 400 and close the connection (RFC 9112 section 6.1). Request framing is then unreliable for the rest of that connection.
4. If both `Transfer-Encoding` and `Content-Length` are present, the `Content-Length` must be removed before forwarding, or the message rejected. A hop that forwards both hands the ambiguity downstream by design.
5. If neither is present, the request body length is zero.

Two further requirements matter for testing. A server that receives a `Content-Length` that is not a valid non-negative decimal integer *must* reject it with 400; a server that receives multiple `Content-Length` values that disagree *must* reject it. Each of these is a place where implementations quietly do something else — take the first value, take the last, ignore the header, or parse a leading numeric prefix and discard the rest.

### C.2 Chunked framing, precisely

The chunked coding is a sequence of chunks, each `chunk-size` in hexadecimal, optionally followed by `;` and chunk extensions, then CRLF, then that many bytes, then CRLF. It terminates with a zero-size chunk, CRLF, an optional trailer section, and a final CRLF.

Three properties of that grammar are the raw material for smuggling. **Chunk extensions** are ignored by parsers that understand them, and are a place to hide a `Transfer-Encoding` token that a naive filter will see and a lenient parser will not. **The size is hexadecimal**, so a desynchronized body can begin with a plausible-looking size line that the next hop treats as a request line or a header. **The trailer section** is a second header block whose headers many implementations discard but still *parse*, which changes where the message ends.

### C.3 The desync primitive

Give the front end a request it forwards as N bytes while the back end parses M bytes, where M is less than N. The remaining N−M bytes stay in the back end's receive buffer, positioned before whatever the front end sends next. If the back end keeps the connection open — as any pool does — those leftover bytes are parsed as the start of the following request.

The attacker controls what those leftover bytes are, because they are the tail of the attacker's own body. Writing a complete, well-formed request there means the back end executes an attacker-authored request that the front end never inspected. Smuggling is therefore not primarily an injection bug; it is an *authorization-boundary* bug that produces request injection as its mechanism.

### C.4 Why connection reuse decides severity

If the back end opens a fresh connection per request, a desync affects only the attacker's own next request and is usually a self-inflicted error. If the back end uses a pool — the normal case behind any load balancer or reverse proxy — the poisoned bytes may be delivered to any request that draws that connection, including another user's. The observable symptom for the victim is a 400, a wrong response, or a redirect to a path they did not request; the observable symptom for the attacker may be nothing at all.

Consequently, "is the connection reused?" is not a detail. It is the difference between a nuisance and a cross-user data-exposure finding, and it must be measured (section E, phase 2) rather than assumed.

### C.5 HTTP/2 and the downgrade

HTTP/2 has no chunked coding: bodies are DATA frames with lengths carried outside the payload, and RFC 9113 section 8.2.2 lists `Transfer-Encoding` among the connection-specific headers that a compliant endpoint must reject or strip. A `content-length` field is permitted but must agree with the sum of the DATA frame lengths; RFC 9113 states that a mismatch is a stream error.

The risk is created by the *conversion* layer, which is extremely common: an HTTP/2 front end terminating TLS and speaking HTTP/1.1 to the origin. If that converter forwards a `content-length` it should have validated, or forwards a `transfer-encoding: chunked` it should have rejected, the origin applies HTTP/1.1 rules to a message the client never framed that way. H2.CL and H2.TE are therefore tests of the converter, not of HTTP/2 itself, and they are frequently the only class that works against a modern encrypted edge.

### C.6 Detection signals

There are exactly three usable observables, in increasing strength:

- **Timing.** A chunked body whose declared size exceeds the bytes actually sent leaves the back end waiting for more data until a timeout. A front end that used `Content-Length` forwards it immediately. The result is a deterministic delay of roughly the read timeout (commonly 5–10 seconds) on a request that should return in milliseconds. Timing is cheap, non-destructive, and prone to false positives from ordinary slow endpoints, so it opens the investigation and never closes it.
- **Differential response.** The same logical request, sent twice with framing varied, produces different status codes or different body lengths from the same endpoint. Stronger than timing, but a difference can also come from caching, rate limiting, or a WAF, so it needs a control.
- **State effect.** A synthetic request smuggled into the next request slot is observed to execute — for example, a marker header appears in the response to a subsequent request the tester sends, or a request to a non-existent path returns the synthetic path's response. This is the only signal that proves exploitability, and it is the point at which the tester must stop (section H) rather than press on toward another user's traffic.

### C.7 Impact classes, in the order an owner will care

- **Front-end control bypass.** Authentication, IP allowlisting, path-based authorization, and WAF rules all live at the front end. A smuggled request reaches the back end without passing any of them.
- **Cache poisoning and cache deception.** A smuggled request can cause the front end to store a response under a key another user will request, or to serve a private response to a shared cache.
- **Credential and session capture.** If the poisoned slot is filled by a *victim's* request rather than the tester's, the back end may answer the victim's request to the attacker's connection, or store the victim's request where the attacker can retrieve it. This is the highest-impact outcome and the one that most requires restraint: it is demonstrated with synthetic accounts, never with real traffic.
- **Availability.** A poisoned connection can wedge the back end's parser and produce sustained 400s for other clients. Any test that might produce this must be bounded (section K).

### C.8 What the class is not

A request that merely contains two `Content-Length` headers and is rejected with 400 is not a finding; rejection is the correct behaviour. A response-splitting bug inside an application (CRLF injection into a header value) is a different class with a different fix. A CDN that normalizes and re-frames every request may make the origin immune regardless of the origin's own code — which is worth reporting as a compensating control, not as a finding.

## D. Prerequisites and Environment

### D.1 Authorization gate (satisfy before the first packet)

Do not proceed until every line below has a written answer that you can point at:

- **Permitting document.** A signed engagement letter, a program policy, or a scoped written instruction that names the organization and the assets. A verbal go-ahead is not a permitting document.
- **Host list.** Exact hostnames or addresses, including every hop between you and the origin. If the intermediary is a third-party CDN, confirm whether testing *through* it is permitted, because the traffic reaches both parties.
- **Method and volume ceiling.** Requests per second, total request budget, and whether `POST` bodies of the sizes your probes need are acceptable.
- **Time window.** Start and end time, including the timezone.
- **Emergency contact and stop procedure.** A name, a channel, and the instruction that ends the test immediately when invoked.
- **Prohibited effects.** At minimum: no traffic capture involving real users, no cache poisoning of a live key, no request that could wedge a production pool for other clients beyond the drain described in phase 9.

If any line is missing, the correct action is to request it in writing. Section K restates this as a stopping rule because it is the single most common way this class of test becomes an incident.

### D.2 Topology requirement

The class only exists where a message is forwarded. Establish that a second hop exists before writing a payload: compare the `Server`, `Via`, `X-Cache`, `X-Served-By`, `CF-Ray`, `X-Amz-Cf-Id` and `Date` headers on a normal response, and check whether TLS terminates at a different certificate or IP family than the application claims. An endpoint that answers `Server: gunicorn` with no intermediary header may still sit behind an internal proxy, so confirm by behaviour (phase 2) rather than by header alone.

### D.3 Client environment

Most HTTP clients normalize exactly the ambiguity under test, which is why a finding produced with a browser is usually a false negative. Use byte-exact tooling:

- `curl --http1.1 --raw --no-buffer` with `-H` per header, and note that curl will still merge some duplicate headers.
- `openssl s_client -connect host:443 -servername host -quiet` piped a hand-written request, which is the only reliable way to send two `Content-Length` headers and odd casing.
- Python `socket` or the `h11` library when a scripted loop is needed. `h11` is a strict HTTP/1.1 state machine, so use `h11.Connection(h11.CLIENT)` and `send`/`next_event` to observe precisely what the peer accepted.
- For HTTP/2, a client that does not validate `content-length`, or a small manual frame writer, because mainstream clients refuse to send a contradictory length.

Disable proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) for these runs; a local intercepting proxy that re-frames requests will silently remove the condition you are testing. If a proxy is required for TLS inspection, verify with a control request that it forwards duplicate headers verbatim.

### D.4 Readiness checklist

1. One endpoint selected, with a normal request captured byte-exact and its response status, length and timing recorded.
2. A control request defined: identical to the probe but with unambiguous framing, so every difference has a baseline.
3. A unique marker string generated per session (for example `desync-7f3a91`) recorded in the engagement log and used only by this test.
4. Synthetic accounts only. Never a real customer's session, cookie or identifier.
5. The drain procedure rehearsed once on a non-production host if one exists.

## E. Detailed Operational Methodology

### Phase 1 — Confirm the boundary and the permitted surface

Restate the host, path, method and volume ceiling from section D in the engagement log, then proceed. This phase produces one line of written text and no traffic. Its purpose is that every later request is attributable to a documented permission.

### Phase 2 — Characterize the hop chain and connection reuse

Purpose: decide whether a desync can reach a party other than the tester, and how many hops must be probed.

Methods, in order of reliability:

1. **Header evidence.** Send one `GET` and record the full response header set. Conflicting `Server` values, a `Via` header with a pseudonym, `X-Cache` on a path that should not be cached, and a `Date` skew of more than a second between hops all indicate a proxy.
2. **Connection reuse.** Open a TCP connection, send two requests back to back without waiting, and observe whether both are answered on the same socket. Then send one request, wait, and send a second after an idle period to measure the keep-alive timeout. A back end that closes after one request cannot carry a poisoned byte into another user's slot.
3. **Timeout fingerprint.** Send a chunked request declaring more bytes than you send, with no terminating zero chunk, and measure how long the connection stays open before closing. The length of that silence is the back-end read timeout, and it is the measurement every timing probe in phases 4–7 will compare against.
4. **Version support.** Offer `HTTP/2` via ALPN, then request the same path over HTTP/1.1, and compare response bytes for the same input. A difference in normalisation between the two paths is what H2.CL and H2.TE exploit.

Expected output: a short table of hop, software signature (if disclosed), reuse behaviour, idle timeout, read timeout, and supported versions.

Error handling: if the connection is reset on the malformed probe, treat that as a *rejection* observation and record it — a hop that closes the connection on ambiguous framing is a control, and it belongs in the report.

### Phase 3 — Capture the baseline transaction

Record the exact request bytes and the exact response bytes for the endpoint's normal behaviour, including status line, all headers, body length and elapsed time. Every later claim is a difference from this capture. Do not skip this because the endpoint is "obviously fine": the baseline is what makes a 6-second response meaningful instead of merely slow.

### Phase 4 — CL.TE

Hypothesis: the front end frames by `Content-Length`, the back end by `Transfer-Encoding`.

Send a request that carries both, where `Content-Length` covers the whole body and the body itself ends with a chunked zero terminator that the front end never treats as significant:

```http
POST /search HTTP/1.1
Host: scoped.example
Content-Length: 13
Transfer-Encoding: chunked
Connection: keep-alive

0

SMUGGLED
```

Interpretation: the front end forwards all 13 bytes and considers the request complete. The back end reads `Transfer-Encoding: chunked`, consumes `0` as the terminating chunk, and treats the following blank line and `SMUGGLED` as the beginning of the next request. Two valid observations follow: a response delay if the back end waits for a chunk that never arrives, and — with a well-formed smuggled request in place of the marker — a state effect on the next request slot.

Error handling: a 400 from the front end means it rejects the pair; try the same bytes with the headers in the other order, with `Transfer-Encoding` first, and with lowercase header names before concluding the hop is safe. A 400 generated after a long pause usually comes from the back end and indicates the front end forwarded the pair — that is a positive signal, not a failure.

### Phase 5 — TE.CL

Hypothesis: the front end frames by `Transfer-Encoding`, the back end by `Content-Length`.

Send a chunked body whose declared chunk size is larger than the bytes you provide, followed by a smuggled request prefix, with a short `Content-Length` that the back end will honour:

```http
POST /search HTTP/1.1
Host: scoped.example
Content-Length: 4
Transfer-Encoding: chunked
Connection: keep-alive

5c
GPOST /admin HTTP/1.1
Host: scoped.example
X-Marker: desync-7f3a91
Content-Length: 15

0

```

Interpretation: the front end reads a 0x5c-byte chunk and forwards everything; the back end reads 4 bytes as the body and parses the remainder as a new request. The exact chunk size must be recomputed for every payload — an off-by-one changes the parsed request into garbage, and a garbage request usually produces a 400 that looks identical to a rejection.

Error handling: if the back end answers 400 immediately with no delay, the front end and back end may agree on `Content-Length`; retry with the `Content-Length` value larger than the body to test the opposite skew, and record both results.

### Phase 6 — TE.TE obfuscation matrix

Hypothesis: both hops honour `Transfer-Encoding`, but one fails to recognize the header because of obfuscation and falls back to `Content-Length`.

Run each variant below as a separate request against the same endpoint, one header pair at a time:

```text
Transfer-Encoding: chunked
Transfer-Encoding: xchunked

Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-Encoding: Chunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked

Transfer-Encoding: chunked;q=1
```

Notes that prevent wasted attempts: a space before the colon is rejected by strict parsers (which is the point), mixed casing tests case-insensitive comparison, and a final coding that is not `chunked` should cause a 400 under RFC 9112 but often causes a silent fallback. Because the matrix is combinatorial, bound it: at most two unknown variants per request and a hard cap of twenty requests per endpoint, then report what was not covered rather than continuing indefinitely.

### Phase 7 — CL.0

Hypothesis: the front end treats the request as having no body (because of an internal route rule, a `GET` with a body, or a hop that strips `Content-Length`) and forwards the body bytes anyway, so the back end parses them as the next request.

Send a `GET` or a bodyless-allowed method with a body and a `Content-Length`, then observe whether the *following* request on the same connection returns a response that corresponds to your body rather than to its own path. If it does, the front end never framed the body as a body. This class is common where the front end routes by path prefix and the back end is a framework that accepts bodies on every method.

### Phase 8 — H2.CL and H2.TE

Hypothesis: the HTTP/2 termination layer forwards a `content-length` inconsistent with the DATA frames, or forwards `transfer-encoding: chunked`, into the HTTP/1.1 origin.

Procedure: over an HTTP/2 connection, send headers including `content-length` set to the value your smuggled HTTP/1.1 request needs, then a DATA frame containing that request plus padding to the declared length. For H2.TE, include `transfer-encoding: chunked` in the header list. A compliant endpoint rejects both with `PROTOCOL_ERROR`; a vulnerable converter forwards them.

Error handling: many clients will not emit these headers at all. If your client refuses, that is a client limitation, not a server control — record it as untested over HTTP/2 rather than as a pass.

### Phase 9 — Confirm, bound the impact, and drain

Confirmation ladder (detail in section H): timing, then differential, then a synthetic state effect observed on your own next request. Stop at the first rung that produces a reproducible observation; do not continue toward a victim's traffic.

Drain, in this order, and record that you did it:

1. Stop sending probes to the endpoint.
2. Send a small number of well-formed requests over fresh connections, each with a short timeout, to consume any bytes left in the pool. Do not reuse the connection you poisoned.
3. Wait one keep-alive interval, then confirm normal behaviour with the baseline request from phase 3.
4. If the endpoint still returns errors attributable to your probe, notify the contact in the permitting document immediately — that is the stop condition, and it takes precedence over completing the assessment.

## F. Practical Technical Examples

### F.1 Byte-exact probe with openssl

```bash
printf 'POST /search HTTP/1.1\r\nHost: scoped.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nG' \
  | openssl s_client -connect scoped.example:443 -servername scoped.example -quiet 2>/dev/null \
  | head -c 400
```

`printf` with explicit `\r\n` is required; a here-document written on Windows or through an editor that normalizes line endings converts CRLF to LF and the probe stops testing anything. Verify the bytes with `xxd | head` before sending the real one.

### F.2 Timing measurement with a control

```bash
for i in 1 2 3; do
  /usr/bin/time -f "probe %e" curl --http1.1 --raw -s -o /dev/null \
    -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' \
    --data-binary $'0\r\n\r\nG' https://scoped.example/search
done
```

Run the control (same endpoint, ordinary `POST`, no ambiguous headers) interleaved with the probe. A probe that takes 6 seconds while three controls take 40 milliseconds is a signal; a probe that takes 6 seconds while the control takes 5.8 seconds is a slow endpoint. Interleaving is what makes the difference attributable.

### F.3 A synthetic state effect, without touching another user

If the front end forwards a request whose body becomes the next request, then *your own* next request on that connection will be displaced. Observe it with a marker:

```http
POST /search HTTP/1.1
Host: scoped.example
Content-Length: 4
Transfer-Encoding: chunked
Connection: keep-alive

5c
GET /desync-7f3a91 HTTP/1.1
Host: scoped.example
Content-Length: 0

0

```

Then, on the same socket, send `GET /` and read the response. If the response is the 404 for `/desync-7f3a91` rather than the page for `/`, the back end consumed your smuggled request as the next message. The marker proves authorship; a response you did not cause would not contain it. This is the strongest non-destructive confirmation available, and it touches no one else's request.

### F.4 A realistic false positive, and why it is not a finding

A tester sends the CL.TE probe above to an endpoint and sees a 502 after 30 seconds, twice, and concludes smuggling. The control request to the same path also returns 502 after 30 seconds, because the upstream is down. Without the control, a dead back end is indistinguishable from a desync. A second false positive: the front end answers 400 quickly, the tester reads "400" as "the back end rejected the smuggled chunk", when in fact a 400 produced *by the front end* means the front end parsed and rejected the pair before forwarding — the exact opposite conclusion.

### F.5 HTTP/2 downgrade probe shape

```python
import h2.connection, h2.config, socket, ssl

ctx = ssl.create_default_context()
sock = ctx.wrap_socket(socket.create_connection(("scoped.example", 443)), server_hostname="scoped.example")
conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
conn.initiate_connection()
sock.sendall(conn.data_to_send())
headers = [
    (":method", "POST"), (":path", "/search"), (":authority", "scoped.example"),
    (":scheme", "https"), ("content-length", "52"),
    ("transfer-encoding", "chunked"),
]
conn.send_headers(1, headers, end_stream=False)
conn.send_data(1, b"0\r\n\r\nGET /desync-7f3a91 HTTP/1.1\r\nHost: scoped.example\r\n\r\n", end_stream=True)
sock.sendall(conn.data_to_send())
```

A compliant peer responds with a stream error for the `transfer-encoding` header. A peer that accepts it has a conversion-layer defect, and the HTTP/1.1 origin is the component that must be probed next.

## G. Tools and Commands

| Purpose | Command | Note |
|---|---|---|
| Byte-exact send | `openssl s_client -quiet` plus `printf` | only reliable way to keep duplicate headers |
| Scripted HTTP/1.1 | `python -c` with `socket` or `h11` | `h11` reports exactly which framing it accepted |
| Curl probe | `curl --http1.1 --raw --no-buffer` | still merges some duplicate headers |
| Timing | `/usr/bin/time -f %e` or `curl -w '%{time_total}'` | always interleave a control |
| Capture | `tcpdump -i any -s0 -A 'tcp port 443' -w knock.pcap` | records your own bytes only |
| Class sweep | `python3 smuggler.py -u https://scoped.example/ -t 10` | `defparam/smuggler`; read its output as leads, not findings |
| Interactive | Burp Suite HTTP Request Smuggler extension | "Turbo Intruder" for single-packet timing |
| HTTP/2 | `h2` package, or `nghttp -v` | `nghttp` validates `content-length` on send |

Rules for using these tools on an engagement: `smuggler.py` and the Burp extension both enumerate many variants quickly, which is exactly what a rate ceiling exists to bound. Set their concurrency to one or two, cap total requests, and treat every lead they produce as unconfirmed until the section H ladder reproduces it with a hand-written request you understand line by line. A tool that reports "vulnerable" on a 400 is reporting a status code, not a desync.

Record the exact version of every tool used (`curl --version`, `smuggler.py --help`, the Burp extension version, the installed `h11` release) in the engagement log. A re-test conducted with a different client can produce a different answer against an unchanged server, because client-side header normalisation differs between releases; the version line in the report is what lets an owner reproduce your result rather than argue about it.

## H. Vulnerability Discovery and Validation

### H.1 The confirmation ladder

A desync claim must climb one rung at a time, and each rung must reproduce before the next is attempted. The ladder exists because the cheapest observations are also the ones most easily explained away, and because the expensive ones can expose other people's traffic.

**Rung 1 — timing.** The probe produces a delay that is (a) at least three times the control, (b) reproducible on at least three of five attempts, and (c) consistent with the back-end read timeout measured in phase 2 rather than with a round number such as exactly 30 or 60 seconds, which usually means a gateway timeout.

**Rung 2 — differential response.** The same endpoint, same body, only framing varied, returns a different status or a body length that differs by exactly the number of bytes you appended. The byte-exact length match is the part that distinguishes a desync from cache noise: if the extra bytes moved from body to body, the lengths shift by a predictable amount.

**Rung 3 — synthetic state effect.** Your own next request on the same connection is displaced by the request you smuggled, and the marker string you generated appears in the response you receive. This is proof of exploitability. Stop here.

### H.2 Proving it without a victim

The marker technique in section F.3 is the whole method: smuggle a request for a path that exists only in this session's log, then observe your own next request answered as if it were that path. No other session is involved, no real data is read, and the evidence is a response containing a string that could only have come from your probe.

If the back end answers your displaced request with an error page rather than a 404 for the marker, that is still evidence — provided the error carries the marker path. What does not count is a generic 400 with no marker: that could be caused by your malformed body alone.

### H.3 Rules that keep a positive result a finding

- One variable per attempt. Change the header pair, not the header pair and the body and the path.
- A control on the same endpoint within the same minute, so endpoint health is excluded.
- At least two independent confirmations, from different rungs, before writing "confirmed" anywhere.
- The byte-exact request in the evidence file, not a description of it.
- An explicit statement of what was *not* tested, including every class the request budget did not reach.

### H.4 Common false positives, each with its exclusion

| Observation | Innocent explanation | Exclusion |
|---|---|---|
| 5–10 s delay on probe only | back end slow on malformed input | control with same body, sane framing |
| 400 from probe | front end correctly rejected the pair | a second variant that the front end accepts |
| next request shows probe's response | an HTTP cache served a stored entry | repeat with `Cache-Control: no-store` on both requests, and a unique path per attempt |
| intermittent effect | a load balancer routing to one of several back ends | repeat twenty times, report the hit rate rather than "works" |
| connection reset | front end closed on ambiguity — a control, not a bug | check whether the reset precedes or follows forwarding |

### H.5 When to call it untestable

Three conditions justify "untestable" rather than "not vulnerable": the permitted surface excludes the methods the probe needs; the client cannot emit the framing (HTTP/2 header validation, for example); or the endpoint opens a fresh connection per request so no state can persist. Each of these is a statement about the test, not about the target, and must be written that way.

## I. Advanced Techniques

### I.1 Desync to cache poisoning

If a smuggled request targets a path the front end caches, and the back end's response to it is stored under the key the front end assigned to the *outer* request, the front end can be made to store a response of your choosing under a key another user will request. Test it with a synthetic path and a benign body, confirm the store with `X-Cache: hit`, then purge by requesting a cache-busting variant and reporting the finding instead of demonstrating the poisoning on a live key. The impact claim is that the key *could* be poisoned; the proof does not require poisoning anyone's page.

### I.2 Request tunnelling

The tunnelling technique uses a request whose response the front end delays (a slow endpoint, or a body it forwards in pieces) to create a window in which a second request can be smuggled and its response read before the outer response arrives. It is the mechanism behind the highest-impact demonstrations of this class, and also the one most likely to place a real user's request on your connection. Any use of it must be limited to two synthetic sessions you control, agreed in writing, and it stops on the first byte of a request you did not author.

### I.3 Client-side desync

A browser can be made to desync itself when it reuses a connection to a vulnerable origin: a `fetch` with a crafted body leaves bytes in the browser's own connection pool, and the browser's next request — for any path on that origin — is prefixed by them. This turns a server-side framing bug into a same-origin request-injection primitive, and its usual use is to reach endpoints that require no attacker-controlled request at all. Test with a dedicated browser profile, a synthetic account, and a page you serve yourself.

### I.4 Obfuscation variants worth trying before concluding a hop is safe

Line folding of the header value, a tab after the colon, trailing spaces before the CRLF, a chunk extension containing a second token (`5;ext=chunked`), a `Transfer-Encoding` value with a leading comma, and a header name with a non-ASCII homoglyph that one parser normalizes and another does not. Each is a parser-differential test; each must be sent byte-exact, because every editor and HTTP library in the chain will otherwise normalize the difference away.

### I.5 Response-side equivalent

Response splitting across a hop (a back end that frames its response with chunked where the front end expects `Content-Length`) can produce a similar prefix-injection effect in the other direction. It is out of scope for most web engagements but is the correct explanation when the odd behaviour appears in a response you did not request.

## J. Automation and AI Agent Integration

### J.1 What may be automated, and what may not

An agent may automate phases 1 through 7: it may enumerate endpoints, send the timing matrix, and compare responses. It may not automate a rung-3 confirmation that involves a second session, cannot be trusted to decide that a 400 is a positive signal, and must never be the component that decides to continue past a stop condition.

### J.2 Job object

```json
{
  "target": "https://scoped.example",
  "methods": ["POST"],
  "max_requests": 120,
  "rate_per_second": 1,
  "classes": ["CL.TE", "TE.CL"],
  "marker": "desync-7f3a91",
  "stop_on": ["5xx_spike", "unexpected_marker", "connection_wedge"],
  "authorization_reference": "engagement-2026-11-03-a"
}
```

The job object is the automation boundary: a class not listed is not tested, a request beyond the cap is not sent, and a stop condition is honoured by the runtime rather than by the model's judgement.

### J.3 Skeleton with the guardrails in the code, not in the prompt

```python
import json, socket, ssl, time

JOB = json.load(open("job.json", encoding="utf-8"))
LOG = open("attempts.jsonl", "a", encoding="utf-8")
sent = 0


def send(raw: bytes, timeout: float = 12.0) -> tuple[int, float]:
    global sent
    if sent >= JOB["max_requests"]:
        raise SystemExit("request budget exhausted")
    sent += 1
    started = time.monotonic()
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.create_connection(("scoped.example", 443), timeout=timeout),
                         server_hostname="scoped.example") as sock:
        sock.sendall(raw)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    elapsed = time.monotonic() - started
    status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0
    LOG.write(json.dumps({"status": status, "elapsed": round(elapsed, 3),
                          "bytes": len(data), "class": "probe"}) + "\n")
    time.sleep(1.0 / JOB["rate_per_second"])
    return status, elapsed
```

Every attempt is logged as one JSON line before the next is sent, so a run that trips a stop condition still leaves a complete record. A fresh connection per attempt is deliberate: pooling your own connections is how a test poisons its own results.

### J.4 Review gates for agent output

Reject any agent-produced claim that does not include the request bytes, the control result, the elapsed times of both, and the hit rate across repeats. A language model asked to interpret a 400 will often describe it as the back end rejecting a smuggled request; the reviewer's job is to check which hop emitted it by reading the `Server` header of the rejection.

## K. Security, Authorization and Operational Safety

This section is a boundary, not advice. The procedure above is only lawful and only safe inside a written **authorization** that names the hosts, methods, volume and window; every step presumes that document exists and that the **scope** in it covers the exact host you send to, including intermediaries you did not choose.

**Stopping rules.** Stop immediately, notify the engagement contact, and record the time when any of the following occurs:

1. A response contains a marker, cookie, path or body you did not author, or any indication that another session's request reached your connection.
2. The endpoint begins returning 5xx for requests that are not yours, or a health check you are permitted to make fails.
3. A connection stays open past three times the measured read timeout, suggesting a wedged parser.
4. Your request count reaches the job ceiling, or the elapsed time reaches the window end.
5. The emergency contact invokes the stop procedure for any reason, including one you disagree with.

**Data handling.** Capture only your own bytes. If your capture tool records a request you did not author, delete the capture, record that deletion, and report the event — do not read it, quote it, or use it as evidence. Never place a real session cookie in a probe; use synthetic accounts provisioned for the engagement.

**Containment.** After every run, drain the pool as described in phase 9, confirm baseline behaviour, and leave the endpoint as you found it. Cache entries created by your probes must be purged or reported, and test records must be removed.

**Prohibited outright.** Denial-of-service testing, request flooding to force a pool exhaustion, capturing credentials that are not yours, and any step that requires reading another user's traffic to prove the point. If the finding cannot be proven without those, the finding is reported as confirmed-mechanism, unproven-impact, and the limitation is stated in the report.

## L. Reporting and Documentation

A report for this class has six parts, in this order:

1. **Claim in one sentence** — which hop disagrees with which about which header, and what an attacker gains.
2. **Affected endpoint and hop chain**, with the evidence for each hop.
3. **Reproduction** — the byte-exact request in a fenced block, the control request, and the observed response or timing for both, with timestamps.
4. **Impact, bounded** — what was proven (for example, a smuggled request executes without front-end authorization) and what was inferred but not proven (for example, that a pooled connection would deliver a victim's request).
5. **Remediation**, in the order that actually removes the class: reject ambiguous framing at every hop, strip `Content-Length` when `Transfer-Encoding` is present, reject `Transfer-Encoding` on HTTP/2 ingress, use HTTP/2 end to end where possible, and disable back-end connection reuse as an interim control.
6. **Coverage and gaps** — classes tested, classes untested, request count, and whether the end-to-end version was available.

Keep the evidence bundle to the requests that prove the claim. Ten near-identical probes bury the two that matter, and every extra capture is another artifact that must be handled carefully.

## M. Troubleshooting and Edge Cases

**No timing difference at all.** Check that your client reuses the connection — a per-request client cannot observe the delay, because the back end's wait ends when the socket closes. Then check that you are hitting the same back end twice: a load balancer across several origins dilutes the signal, so run the probe twenty times and look at the distribution rather than a single attempt.

**The probe returns 200 immediately with a truncated body.** The front end may have normalized the request before forwarding. Compare the bytes at the origin by sending the same request directly to the origin address if it is in scope; if it is not, report the front-end normalization as a compensating control and leave the origin untested.

**Every probe returns 400.** Determine which hop produced it from the response's own headers and body. A front-end 400 means the pair was rejected before forwarding, which is correct behaviour and not a finding. A back-end 400 after a delay means the front end forwarded something the back end could not parse, which is a lead worth one more variant.

**HTTP/2 only, no HTTP/1.1 listener.** The CL.TE and TE.CL classes do not apply directly; H2.CL and H2.TE apply to the downgrade converter behind the edge, and the edge itself may be immune while the origin is not. Record which layer was tested.

**Intermittent positive results.** Report a hit rate, not a verdict. One hit in twenty attempts is a real condition on a pooled deployment and a flaky artifact on a single-connection one; the repeats tell you which. Never report "confirmed" from a single observation.

**The connection resets mid-body.** Some front ends reset rather than reject on ambiguity, which is a control worth recording. Others reset because a WAF rule matched your payload; check whether a benign request with the same headers but an empty body also resets.

**Long delay then a valid-looking response.** Some proxies buffer and retry. A retry delivers your request twice, which can look like a smuggled request executed twice; distinguish by using a marker that increments, so a duplicate is visible as a repeated value rather than a new one.

## N. Limitations and Known Issues

- This procedure establishes a framing disagreement between hops. It cannot enumerate every hop, and an internal proxy you cannot see may be the component that is actually safe or unsafe.
- Timing observations depend on network conditions; a cellular link or a region with high jitter can turn a 200 ms signal into noise. Interleaved controls mitigate this, not eliminate it.
- The technique requires a reusable back-end connection to have cross-user impact. On a deployment that closes after every request, the same defect is a self-inflicted error and must be reported at that lower severity.
- The obfuscation space is effectively unbounded. A clean result on the matrix in phase 6 is evidence about those variants, not proof of immunity.
- Caching, request smuggling and application-level CRLF injection produce similar symptoms and different fixes; misattribution here leads to a wasted remediation cycle.
- Nothing in this document has been executed against a live third-party service as part of writing it. Commands are derived from the cited specifications and the documented behaviour of the named tools; a tester must validate them against their own lab.

## O. Quality Assurance Checklist

- [ ] Permitting document names every host, including intermediaries.
- [ ] Volume ceiling, window and emergency contact recorded in the engagement log.
- [ ] Baseline request and response captured byte-exact, with timings.
- [ ] Control request defined and run interleaved with each probe class.
- [ ] Unique marker generated per session and recorded.
- [ ] Read timeout measured before any timing probe is interpreted.
- [ ] Connection reuse confirmed before any cross-request claim is made.
- [ ] Each class tested is recorded as tested, with its result, or explicitly skipped.
- [ ] No capture contains a request the tester did not author.
- [ ] Drain performed and baseline re-confirmed after the final probe.
- [ ] Report states what was proven separately from what was inferred.
- [ ] Remediation addresses framing at every hop, not only at the edge.

## P. References

- RFC 9112, HTTP/1.1 message syntax and routing, section 6 framing and 6.3 body length — https://www.rfc-editor.org/rfc/rfc9112.html
- RFC 9110, HTTP semantics — https://www.rfc-editor.org/rfc/rfc9110.html
- RFC 9113, HTTP/2, section 8.2 for connection-specific header fields — https://www.rfc-editor.org/rfc/rfc9113.html
- RFC 9114, HTTP/3 — https://www.rfc-editor.org/rfc/rfc9114.html
- CWE-444, Inconsistent Interpretation of HTTP Requests — https://cwe.mitre.org/data/definitions/444.html
- CWE-436, Interpretation Conflict — https://cwe.mitre.org/data/definitions/436.html
- MITRE ATT&CK T1190, Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1557, Adversary-in-the-Middle — https://attack.mitre.org/techniques/T1557/
- OWASP Web Security Testing Guide, HTTP splitting and smuggling — https://owasp.org/www-project-web-security-testing-guide/
- Python `ssl` module documentation — https://docs.python.org/3/library/ssl.html
- h11, a pure-Python HTTP/1.1 state machine — https://github.com/python-hyper/h11
- smuggler, HTTP desync enumeration tool — https://github.com/defparam/smuggler
- Burp Suite HTTP Request Smuggler extension — https://github.com/portswigger/http-request-smuggler

