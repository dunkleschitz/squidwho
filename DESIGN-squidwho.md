# squidwho — hazard-first design review

**Status:** BUILD APPROVED (2026-11-09).
**Question:** which `http_access` line allows or denies a request
with source IP S, destination host H, port N, method M (and URL U)
— and which `acl` lines decided it?
**Shape:** `squidwho --src IP --dst HOST --port N --method M
[--url URL] [--at DATETIME] [--dst-ip IP] [--local ADDR:PORT]
[--conf FILE]...` over one or more squid.conf files. Flags
(who-family standard): `--json`, `--quiet`, `--version`, plus
`--list-acls` and `--list-rules`.
**Pinned from:** the Squid configuration manual (cfgman) for
Squid 5.10 / 6.9 / 7.0, read 2026-11-09 — `acl` directive page
(ACL type list, `[fast]`/`[slow]` tags, regex `-i`/`+i` flags,
`time` day abbreviations, quoted-file values), `http_access`
directive page (no-match default, no-rules default), the
`include` directive (list of files, quoting + wildcards, nesting
cap to 16 levels); the Squid wiki `SquidFaq/SquidAcl` (first-match
semantics, AND-within-a-line / OR-across-lines, same-name rules,
dstdomain dot semantics and the splay-tree overlap quirk,
no-match reverses the last rule); *Squid: The Definitive Guide*
§6.2 (single-pass parse — ACLs must be defined before use; OR
across values in one ACL); Amos Jeffries, squid-users 2012-06-20
(http_access tested at request receipt from TCP + HTTP request
details only; per-directive-type rule lists are independent);
Squid source `ACLTimeData.cc` (time-spec parse: `h1:m1` must be
less than `h2:m2`, reversed range is a parse error). Semantics
pinned to the Squid 4.x–7.x range; version-gated differences are
called out where they appear. No Squid binary exists on this box
(`squid` is not installed) and no live experiments were run, so
every claim below is `[documented]` (cfgman / wiki / book),
`[docs-inferred]` (follows from a documented rule), or
`[hypothesized]` (best-supported guess, flippable) — never
`[observed]`. There is no live-agreement test to skip-guard
against: `squid -k parse` validates syntax but dumps no access
decisions (see Thinness verdict), so fixture trees are the only
oracle, exactly as the manual text is the only authority. Claims
are tagged throughout. A claim that turns out wrong must flip
the design, not get quietly absorbed.

## Thinness verdict: APPROVED, and no native holder answers the question

1. **`squid -k parse` validates; it does not adjudicate.** A
   config check answers "does this parse", never "would source
   10.0.0.5 reaching example.com:443 with CONNECT be allowed,
   and which line decided it" [documented — the cfgman describes
   `-k parse` as a configuration parse; the ROADMAP search passes
   found no access-query mode].
2. **The documented debug path is live restart + log spelunking.**
   `debug_options 28,3` (section 28 = ACL evaluation) plus a
   daemon restart plus `cache.log` reading is the prescribed way
   to learn why a request got `TCP_DENIED` — it answers the
   question only after the fact, only for a request that actually
   happened, and only by restarting the proxy [documented —
   wiki/SquidFaq, operator guides]. It cannot answer a
   hypothetical, and it cannot run against a config that is not
   deployed.
3. **grep cannot do first-match under three-valued conditions.**
   The winner is the first `http_access` line whose ACLs all
   match, where a term can be *undecidable* statically (SQ10–
   SQ12); grep prints all the lines and adjudicates none of
   them, and it cannot see that the no-match default is the
   *reverse* of the last rule's action (SQ06) — the single most
   counter-intuitive rule in the file, and the one that makes a
   config ending in `http_access allow …` silently allow
   everything unmatched.

If the build cannot reproduce SQ06 (reverse-of-last default),
SQ10 (three-valued lines), and SQ12 (unmodeled dynamism as a
blocker, not a skip) against fixture trees, it does not ship —
those three are the tool's reason to exist.

## Pinned semantics

### Files and lines

- squid.conf is a flat, section-less directive file: one
  directive per line, `#` to end of line is a comment,
  backslash-newline continues a line, values may be quoted
  (`"..."`) [documented]. v1's tokenizer must handle all
  three, or real-world blocklists (`acl bad dstdomain
  "…/bad.txt"`) break.
- **SQ19 — loading model:** `include` takes a list of files;
  quoting and wildcards are supported; includes nest to a
  hard-coded depth of 16 levels [documented]. Included files are
  expanded **in place**, in the order listed; a wildcard expands
  in lexical order [docs-inferred — the cfgman says wildcards
  are supported and does not state an order; lexical is the
  only deterministic reading, and the build pins it]. Relative
  include paths resolve against the including file's directory
  [docs-inferred — the cfgman does not state a base; the
  config-directory reading is the AA10 lesson applied, and the
  tool says so in a finding whenever a relative include is
  followed]. Depth beyond 16 → fatal finding (exit 2), mirroring
  the real loader's cap. A missing include file → fatal finding
  (exit 2): the real daemon refuses the config, so a verdict
  over a half-loaded tree would be a manufactured answer.
  `--conf` may be repeated; files are concatenated in the order
  given (a v1 convenience — Squid itself takes one config file;
  the tool banners the concatenation in coverage). Default
  discovery when `--conf` is absent: `/etc/squid/squid.conf`
  if it exists; else exit 2 with the searched path named —
  never a silent guess at another tree.
- **SQ20 — external files for ACL values:** an ACL definition
  may take a quoted filename instead of inline values
  (`acl name type "/path/file"`) [documented]. File contents:
  one value per line; empty lines and `#` comments ignored
  [docs-inferred from the cfgman file syntax, which the manual
  states generally for "reading configuration option parameters
  from external files"]. Resolution: relative paths resolve
  against the config file's directory, with a finding whenever
  one is followed (SQ19's rule, same reason).
  - File readable → values expanded in place, each carrying
    provenance (`acl-file:<path>:<line>`); the ACL is evaluable.
  - File missing/unreadable → that ACL is **unmodeled**: any
    rule term using it is UNKNOWN (SQ10), and the finding
    names the file. Never treated as an empty value list (an
    empty list would read as "never matches" — a manufactured
    FALSE, the worst output this tool can produce).
- Directive names are matched case-sensitively as written in
  the cfgman (lowercase) [hypothesized — the manual never
  states directive case rules; a differently-cased `acl` or
  `http_access` line is an unparseable-line finding (SQ21),
  not a silent miss, so being wrong here is loud, not
  wrong-answer quiet].

### SQ01 — The rule list: first match wins, AND within, OR across [documented]

`http_access allow|deny [!]aclname ...` [documented]. Rules are
checked in the order written; list searching terminates as soon
as one rule matches [documented — wiki, Definitive Guide,
Jeffries 2012]. Within one rule, **all** ACL elements must
match (AND logic); across rules, OR logic — each rule is tried
in turn [documented]. `!` negates one ACL element. A rule with
**no** ACL elements matches unconditionally (`http_access deny`
alone is a catch-all) [docs-inferred — the cfgman usage line
shows the ACL list as trailing and optional, and stock configs
rely on bare `http_access deny all` rather than bare
`http_access deny`; a bare rule with no ACLs is treated as
unconditional-TRUE, and the build pins this with a fixture].

- Each directive type has its own independent rule list: an
  `http_reply_access` line between two `http_access` lines does
  not disturb the `http_access` order [documented — Jeffries
  2012]. v1 keeps one ordered list per directive type and
  evaluates only `http_access` (SQ23).
- The `acl` definitions are **global** (no sections): any
  `http_access` line may reference any ACL defined anywhere
  above it in the loaded file order (SQ02).

### SQ02 — ACL definition: define before use, same-name merges, same-name-different-type is fatal [documented + docs-inferred]

- "Squid makes only one pass through the access control lines.
  Thus, you must define the ACL elements (with an `acl` line)
  before referencing them in an access list" [documented —
  Definitive Guide §6.2]. A rule referencing an ACL defined
  **later** in the file is a config the real daemon refuses to
  start. v1: finding + verdict UNKNOWN if the rule could
  decide the query (SQ17's treatment — the config serves
  nothing as written, so no ALLOW/DENY is honest).
- "You can't give the same name to two different types of ACL
  elements. It will generate a syntax error" [documented —
  wiki]. Same name + **same** type, repeated: the values
  **accumulate** into one ACL — it matches if **any** of its
  values matches (OR across values and across the lines)
  [docs-inferred — the wiki's prohibition is type-scoped, and
  the value-OR rule is documented for a single ACL's values;
  the build pins the merge with a fixture]. A same-name
  different-type redefinition → fatal finding for rules using
  it (verdict UNKNOWN if it could decide), warning otherwise.
- ACL names are matched case-sensitively [hypothesized — the
  cfgman never states ACL-name case rules; a rule referencing
  `Localhost` when `localhost` is defined is a dangling
  reference (SQ17), not a silent miss].
- The stock config's built-in ACLs are ordinary definitions,
  not magic: `acl all src all` is the default value of the
  `acl` directive [documented — cfgman default], and the
  recommended minimum defines `manager`, `localhost`,
  `to_localhost`, `SSL_ports`, `Safe_ports`, `CONNECT`
  [documented — cfgman Suggested Config]. v1 treats them as
  whatever the loaded file defines; if a fixture file omits
  them, they do not exist (no implicit built-ins beyond what
  the file says — the one exception is `all`, which v1
  pre-defines as `src all` iff the file never defines it,
  matching the cfgman default, and says so in coverage).

### SQ03 — The evaluable ACL-type set (v1's whole world)

An ACL type is evaluable in v1 **iff** it is in this table and
its values are literal (no DNS-dependent value, no converter —
Squid has none). Everything else is SQ12, by construction, not
by oversight.

| Type | Value from the query | Notes |
|---|---|---|
| `src` | `--src` | SQ10; IP / CIDR / netmask / range `a-b` / `all`; hostname values → SQ12 (DNS). Absent `--src` → UNKNOWN-valued. |
| `dst` | `--dst-ip`, else the `--dst` host if it is a literal IP | SQ10; `[slow]` — Squid DNS-resolves the URL host [documented]. No `--dst-ip` and a hostname `--dst` → UNKNOWN-valued. |
| `dstdomain` | `--dst` host | SQ08. |
| `dstdom_regex` | `--dst` host | SQ15; `-i` flag. |
| `url_regex` | the composed URL (SQ09) | SQ15; `-i` flag; unanchored search. |
| `urlpath_regex` | path + `?query` of the composed URL | SQ15; `-i` flag; empty for CONNECT. |
| `port` | `--port` | SQ10; single ports and `lo-hi` ranges; `0` = no port (SQ10). |
| `myport` / `localport` | `--local ADDR:PORT` | Evaluable only when `--local` is given; else UNKNOWN-valued. Both name the local socket port; `myport` is the legacy spelling [documented]. |
| `localip` / `myip` | `--local ADDR:PORT` | Evaluable only when `--local` is given; else UNKNOWN-valued. |
| `method` | `--method` (default `GET`) | SQ10; exact string match [hypothesized case rule — see SQ10]. |
| `proto` | derived from `--url` scheme, else `--proto`, else `HTTP` | Values `HTTP`/`HTTPS`/`FTP`/…; `cache_object` never matches a real request → FALSE [docs-inferred]. |
| `time` | `--at` datetime, else now | SQ11; local time; bannered. |

Recognized-but-unmodeled types (SQ12, inventoried, never
approximated): `proxy_auth`, `external`, `ident`, `arp`,
`src_as`, `dst_as`, `maxconn`, `srcdomain` / `srcdom_regex`
(reverse lookup of the client IP — `[slow]`, DNS),
`peername`, `snmp_community`, `referer_regex`, `browser`,
`req_header`, `rep_header`, `req_mime_type`,
`rep_mime_type`, `note`, `tag`, `random`, `eui64`,
`connmark`, `urllogin`, `ssl::` / `tls::` families (peeked
certificate state), and any type outside the cfgman list for
the pinned versions. The recognizer is generous (any cfgman
type name → clean SQ12 term); a type name that is not in the
cfgman list at all is an unparseable-line finding (SQ21).

### SQ04 — Value OR-logic inside one ACL [documented]

"When checking for a match, the multiple values use OR logic.
In other words, an ACL element is *matched* when any one of
its values is a match" [documented — wiki, Definitive Guide].
This holds across inline values, repeated same-name lines
(SQ02), and file-expanded values (SQ20): one ACL matches iff
**any** value matches. Negation (`!name`) inverts the whole
ACL's verdict after the OR.

### SQ05 — http_access evaluation is request-only [documented]

`http_access` lines "are tested as soon as the HTTP request is
received. Using only the TCP connection and HTTP request details
(no HTTP reply details)" [documented — Jeffries 2012]. There is
no reply-side poisoning analogue to HAProxy's HA13: no
`http_access` verdict can be changed by anything that happens
after the request is received. What *can* precede it is
`ssl_bump` peek/stare processing on CONNECT tunnels — out of
scope v1 (SQ23), inventoried in coverage.

### SQ06 — The no-match default: reverse of the last rule; no rules → deny [documented]

"If none of the configured rules match, then Squid *reverses*
the action of the last configured rule. For example, if the last
configured `http_access` action was 'allow', then Squid denies
access" [documented — wiki]. "If no `http_access` rules are
configured at all, Squid denies access" [documented — wiki].
And the cfgman: "If there are no 'access' lines present, the
default is to deny the request" [documented]. Consequences:

- No matching rule + last rule `allow` → verdict **DENY**,
  decider `implicit-default (reverse of last rule: allow)`,
  exit 1.
- No matching rule + last rule `deny` → verdict **ALLOW**,
  decider `implicit-default (reverse of last rule: deny)`,
  exit 0. This is the footgun the tool exists to surface:
  a config ending in `http_access deny …` with no trailing
  `deny all` silently allows everything unmatched — the
  verdict line must name the reversed rule's file:line, and a
  finding must flag the missing explicit catch-all.
- No `http_access` lines at all → verdict **DENY**, decider
  `implicit-default (no http_access rules)`, exit 1.
- The reversal is a *rule*, not a fallback the tool may
  simplify to "deny": a fixture pins the allow-by-reversal
  case, and the README must state it in one paragraph.

### SQ07 — URL composition (what the regex and domain ACLs actually see) [documented + docs-inferred]

The query supplies `--src`, `--dst`, `--port`, `--method`, and
optionally `--url`. v1 composes the request URL as Squid sees
it:

- If `--url` is given, it is parsed (scheme, host, port, path,
  query, userinfo). Explicit `--dst` / `--port` / `--method`
  override the parsed components, with a finding noting the
  override. `--url` without a scheme is a usage error (exit 2).
- If `--url` is absent, the URL is composed from the parts:
  scheme from `--proto` (default `http`), host `--dst`,
  port `--port` (omitted from the composed URL when it is the
  scheme default: 80 http / 443 https / 21 ftp), path `/`.
- **CONNECT:** for `--method CONNECT`, Squid's request URL is
  the authority form `host:port` — there is no path, no scheme
  [docs-inferred — CONNECT request-targets are authority-form
  per RFC 9112, and Squid's `url_regex`/`dstdomain` handling of
  CONNECT targets follows from it; the build pins the
  authority-form composition with a fixture]. `urlpath_regex`
  therefore tests against the empty string for CONNECT (a
  pattern such as `^$` matches; any non-empty pattern does
  not). `dstdomain` tests the authority host; `url_regex`
  tests `host:port`.
- `url_regex` searches the **whole** composed URL
  [documented]; `urlpath_regex` searches the path + `?query`
  only, "leaves out the protocol and hostname" [documented —
  wiki]. Neither is anchored unless the pattern anchors
  itself.
- The composed URL is shown in the output (text and JSON) so a
  wrong composition is visible, not silent.

### SQ08 — dstdomain matching: exact host vs whole domain, case-insensitive [documented + docs-inferred]

- `www.example.com` matches the **exact host**
  `www.example.com` only; `.example.com` matches the **entire
  domain** `example.com`, including `example.com` alone
  [documented — wiki, Squid 2.4+ syntax].
- Hostnames are matched case-insensitively (DNS names are
  case-insensitive; Squid lowercases the comparison)
  [docs-inferred — the cfgman never states dstdomain case
  rules; the build pins case-insensitive matching and the
  tag flips if a live contradiction appears].
- One trailing dot on the query host is stripped before
  matching (`example.com.` is the same DNS name)
  [hypothesized — a normalization the tool applies and
  banners; if Squid does not strip it, the verdict could
  differ on a trailing-dot query, and the banner says so].
- **The splay-tree overlap quirk:** "there is also subtle
  issues if your dstdomain ACLs contains matches for both an
  exact host in a domain and the whole domain … Depending on
  how your data is ordered this may cause only the most
  specific of these (e.g. *www.example.com*) to be used"
  [documented — wiki]. v1 evaluates the **union** (the
  documented intent: any listed value matching is a match,
  SQ04) and emits a finding whenever one value in an ACL is a
  subdomain of another value in the same ACL, naming both —
  the operator is warned that the live daemon may behave more
  narrowly than the union, and the finding is the honest
  middle. The build pins the union with a fixture and names
  the quirk in the README Limitations.
- **IP-based URLs:** "For dstdomain and dstdom_regex a reverse
  lookup is tried if a IP based URL is used and no match is
  found. The name 'none' is used if the reverse lookup fails"
  [documented — cfgman]. So a `dstdomain` term against an
  IP-literal `--dst` is UNKNOWN (the reverse name is
  unknowable statically) — **unless** the ACL carries the
  `-n` flag, which suppresses the lookup, in which case the
  term is FALSE [docs-inferred — `-n` appears on the cfgman
  type line as the no-lookup flag; the build pins both
  branches]. The literal pattern `none` matches an IP URL
  whose reverse lookup fails — unknowable statically, so a
  `none` pattern against an IP host is UNKNOWN, never FALSE.

### SQ09 — (folded into SQ07)

### SQ10 — IP/port/method matching and three-valued rules [documented + design rule]

- `src` values: IP addresses, CIDR (`10.0.0.0/8`), netmask
  notation (`10.0.0.0/255.0.0.0`), ranges (`addr1-addr2`),
  and the keyword `all` (matches every address)
  [documented — cfgman]. IPv4 and IPv6 both supported
  (`ipaddress` stdlib). A hostname value needs DNS at runtime
  → that value is unmodeled: the ACL term is UNKNOWN if the
  hostname value could match (i.e. the ACL contains any
  hostname value — the tool cannot prove it doesn't match
  the query IP, so the whole ACL is UNKNOWN-valued, with a
  finding naming the hostname) [design rule — the HA11
  lesson: never treat an unresolvable value as non-matching].
- `dst` values use the same forms against the destination IP
  (SQ03). `dst` is `[slow]` because Squid DNS-resolves the URL
  host [documented]; v1 never performs DNS (read-only, no
  network — a DNS lookup would make the answer depend on the
  resolver, not the file).
- `port` values: single ports and `lo-hi` ranges [documented].
  Port `0` "matches requests that have no explicit and no
  default destination port" [documented — cfgman 7.0]. v1:
  port 0 matches iff no `--port` was supplied and no
  `--url` port and the scheme has no default port; otherwise
  FALSE. `--port` absent with a scheme default (http/80)
  → the port is the scheme default (SQ07), not 0.
- `method` values are compared exactly as written
  [hypothesized case rule — the cfgman never states method
  case rules; HTTP methods are uppercase by convention and
  Squid's stock config writes them uppercase; v1 matches
  case-sensitively and the README names the uncertainty. A
  live contradiction flips the tag, not the exact-match rule].
- **Three-valued rules:** every ACL term evaluates to TRUE,
  FALSE, or UNKNOWN (unmodeled type — SQ12; missing input —
  `--src` absent, `--dst-ip` absent, `--local` absent; IP-host
  reverse lookup — SQ08). Combination is Kleene three-valued
  logic, per rule (AND across the rule's terms):
  - AND: FALSE dominates; else UNKNOWN dominates; else TRUE.
  - `!`: UNKNOWN stays UNKNOWN.
  A rule matches **iff** its AND is TRUE (SQ01). A rule whose
  AND is UNKNOWN is a **blocker**: it might have decided the
  request. The walk (SQ13) stops at the first TRUE rule; an
  UNKNOWN rule before any TRUE rule makes the verdict UNKNOWN
  and names that rule as the blocker (the real request might
  have taken it). This is the honesty core: a statically
  unknowable term degrades the verdict exactly when it could
  change the winner, and is harmlessly absorbed (with a
  finding) when another term in the same rule already decides
  it (FALSE in the AND).
- Predefined-value notes: `src all` / `dst all` are TRUE for
  any query [documented — `all` keyword]; a `time` ACL with no
  day/time spec after the type is a parse finding (SQ21).

### SQ11 — time ACLs: evaluable against a stated instant, never silently "now" [documented + design rule]

- Syntax: `acl name time [day-abbrevs] [h1:m1-h2:m2]` [documented
  — cfgman]. Day abbreviations: S Sunday, M Monday, T Tuesday,
  W Wednesday, H Thursday, F Friday, A Saturday [documented].
  `h1:m1` must be less than `h2:m2` — a reversed range is a
  parse error in Squid's own parser [documented — ACLTimeData.cc
  "Reversed time range"]. Multiple day/time specs on one ACL
  line accumulate (OR) [docs-inferred from the linked-list
  parse in ACLTimeData.cc].
- A spec with days but no time matches all day on those days;
  a spec with a time but no days matches that time every day
  [docs-inferred — the parser defaults weekbits to all-week
  when no day token is present].
- The instant evaluated is `--at <ISO datetime>` when given
  (a date and time, or a bare time meaning today), else the
  machine's current local time. **The default is bannered on
  every run that uses it:** Squid evaluates `time` against the
  proxy host's clock, and this machine may not be that host —
  a time-decided verdict with no `--at` carries the
  `[time-is-now-local]` banner, and `--at` is the reproducible
  form. A `time` ACL is never evaluated against a guessed
  timezone: `--at` with an explicit offset is honored; a naive
  `--at` is read as local time, stated in the output.
- The `weekdays` / `weekends` day tokens appear in Squid's time
  parser source (`ACL_WEEKDAYS`) but are not in the cfgman
  text: **build-time verification note** — the build must
  confirm from the Squid source whether bare `weekdays` /
  `weekends` tokens parse, and map them (MTWHF / SA) only if
  confirmed; until then an unknown day token is an
  unparseable-line finding (SQ21), never a guess.
- Time ranges never wrap midnight in one spec (reversed =
  parse error); an overnight window is written as two specs
  (`22:00-24:00` + `00:00-06:00`) [docs-inferred from the
  h1<h2 rule; the build pins the two-spec form].

### SQ12 — Unmodeled dynamism: bannered, UNKNOWN-poisoning, never approximated

The following, appearing as a term in a rule of the selected
walk, make that term UNKNOWN (SQ10) and are listed in the
output's unmodeled inventory:

- `proxy_auth` (any form, including `REQUIRED`) — credential
  state is runtime-only.
- `external` ACLs and their `external_acl_type` helpers —
  arbitrary helper programs, unknowable from the file.
- `ident`, `arp`, `src_as` / `dst_as`, `maxconn`, `peername`,
  `snmp_community`, `connmark`, `eui64`, `note`, `tag`,
  `random` — identity, network, or runtime state.
- `srcdomain` / `srcdom_regex` — reverse DNS of the client IP
  (`[slow]`); `dstdomain`/`dstdom_regex` reverse fallback for
  IP URLs (SQ08).
- `referer_regex`, `browser`, `req_header`, `rep_header`,
  `req_mime_type`, `rep_mime_type`, `urllogin` — the CLI takes
  no header/body inputs for these, and inventing them would
  manufacture verdicts.
- `ssl::` / `tls::` certificate/state fetches and `ssl_bump`
  step state (SQ23).
- Any hostname value inside a `src`/`dst` ACL (SQ10).
- Any ACL whose value file is missing/unreadable (SQ20).

Recognition rule (the AA13 lesson, restated): the ACL parser
is *generous in recognition, strict in evaluation* — any
criterion whose type name is in the cfgman list but unmodeled
is a clean SQ12 term; a type name that is not in the cfgman
list at all is SQ21 (unparseable) and poisons harder.

### SQ13 — The walk: first TRUE rule wins, else the SQ06 default [documented]

Per the loaded `http_access` list, in file order:

1. Evaluate rules in order (three-valued, SQ10): the first
   whose AND is **TRUE** wins; its file:line is the decider,
   and its action (allow/deny) is the verdict. Rules after it
   are reported as unevaluated-by-order (shadowed by the
   winner); rules before it are evaluated-false (with the
   deciding term shown); an UNKNOWN rule before any TRUE rule
   makes the verdict UNKNOWN and names that rule as the
   blocker.
2. No TRUE rule and no UNKNOWN blocker → the SQ06 default
   (reverse of the last rule, or deny if no rules).
3. A rule whose action is `allow` but whose ACL list is empty
   matches unconditionally (SQ01) — a bare `http_access allow`
   is a decider, not a no-op.

### SQ14 — (folded into SQ01/SQ13; reserved)

### SQ15 — Regex is an approximation, and says so [design rule]

- Squid regexes are POSIX extended regexes in the default
  build [documented that Squid uses the system regex library;
  which dialect a given binary used is not in the file]. v1
  translates patterns to Python `re` where the syntax
  coincides, and: patterns using constructs Python `re`
  cannot express or expresses differently (`[[:alpha:]]`
  classes are translated; backreferences in *matching* are
  fine; anything the translator rejects) make the term
  UNKNOWN, never a guess. Every verdict whose decider trace
  rests on a regex term carries the `[regex-approx]` banner.
  A regex the translator *accepts* silently differing from
  POSIX semantics is the known residual risk, named here and
  in the README Limitations.
- Regexes are case-sensitive by default; `-i` makes the
  following patterns case-insensitive, `+i` returns to
  sensitive, per pattern, until the next flag [documented —
  cfgman]. Flags are per-ACL-line state, tracked in order.
- Matching is **search** (unanchored), not full-match
  [documented — "means to search the entire URL for the
  regular expression"]. `url_regex` searches the composed
  URL (SQ07); `urlpath_regex` searches path + `?query`;
  `dstdom_regex` searches the destination host.

### SQ16–SQ24 — Structural findings

- **SQ16 duplicate ACL name, different type:** (SQ02) — the
  real daemon refuses the config; v1 reports the finding and
  treats the ACL as unmodeled (SQ12) for rules using it.
- **SQ17 dangling references:** a rule referencing an ACL
  never defined, or defined only *after* the rule (SQ02) —
  config-invalid finding; if the dangling rule is the
  would-be winner or blocker, verdict UNKNOWN; a dangling
  reference in a rule that is already decided FALSE by another
  term is a warning only (Kleene absorption, SQ10).
- **SQ18 (reserved for environment expansion):** squid.conf
  has no `${VAR}` expansion in the HAProxy sense; values are
  literal. If a future version adds one, this number is the
  hook. (No finding class is defined here; do not invent one.)
- **SQ19** loading model (see Files and lines, above).
- **SQ20 coverage on every run.** Output always lists: files
  read (with byte/line counts, include expansion noted),
  ACLs defined (name, type, value count, provenance),
  rules evaluated-false / shadowed / blocked, unmodeled
  inventory (SQ12 terms, SQ20 missing files), and
  skipped/unparseable lines with counts. A verdict over a
  partially read config is never presented as complete.
- **SQ21 unparseable lines poison the selected walk.** A line
  that matches no known directive shape, an `acl` line with
  an unknown type, a `time` spec with a reversed range or an
  unknown day token, or a malformed `http_access` line →
  verdict UNKNOWN, citing file:line (an unrecognized line
  could be a rule v1 doesn't know). Recognized-but-unevaluated
  directives (the long tail: `http_port`, `cache_dir`,
  `cache_peer`, `auth_param`, `refresh_pattern`, …) are
  parsed-or-skipped cleanly and never poison — the recognizer
  must be generous (any directive name in the cfgman index
  → skip the line), the router strict. `cache_peer_access`,
  `always_direct` / `never_direct`, `miss_access`,
  `http_reply_access`, `adapted_http_access`, `delay_access`,
  and `cache`/`no_cache` lines are inventoried in coverage
  (SQ23) and never poison.
- **SQ22 `--list-acls` / `--list-rules`:** the map a human
  greps for today. `--list-acls`: every ACL in load order,
  with type, value count, value-file provenance, and
  evaluable/unmodeled status. `--list-rules`: every
  `http_access` rule in order, with action, terms, and the
  file:line of the rule — plus the SQ06 default the list
  implies, stated explicitly.
- **SQ23 verdicts cover http_access only — the coverage
  banner.** Every output states: verdicts cover
  `http_access` only. `cache_peer_access` (parent/peer
  selection), `always_direct`/`never_direct`, `miss_access`,
  `http_reply_access`, `adapted_http_access`, `delay_access`,
  and `ssl_bump` step rules are listed as present-but-not-
  verdicted, with counts. If the config contains **no**
  `http_access` lines at all, the run still exits 1 with
  `DENY` per SQ06 (no-rules default) — never a bare "no
  answer".
- **SQ24 verdict vocabulary (exact):** `ALLOW` (decider:
  `http_access` file:line / `implicit-default`), `DENY`
  (same deciders), `UNKNOWN` (blocker cited). There is no
  other output vocabulary for the verdict line; `--quiet`
  prints the verdict line only.

## CLI, exits, and output contract

```
squidwho --src IP --dst HOST [--port N] [--method M]
         [--url URL] [--proto PROTO] [--at DATETIME]
         [--dst-ip IP] [--local ADDR:PORT] [--conf FILE]...
squidwho --list-acls [--conf FILE]...
squidwho --list-rules [--conf FILE]...
```

- `--src` and `--dst` are required for an access query (exit 2
  if absent); `--method` defaults to `GET`; `--port` optional
  (absent → scheme default per SQ07, or UNKNOWN-valued port
  terms if no scheme default applies); `--url` optional
  (supplies dst/port/path/proto; explicit flags override,
  SQ07); `--proto` defaults from `--url` scheme else `HTTP`;
  `--at` optional (SQ11); `--dst-ip` optional (SQ03/SQ10);
  `--local` optional (SQ03).
- `--conf` repeatable (SQ19); default `/etc/squid/squid.conf`.
- `--list-acls` / `--list-rules`: inventory modes (SQ22);
  exit 0 with ≥1 item listed, exit 1 with none.
- Exit 0: verdict `ALLOW` rendered (by rule or by SQ06
  reversal — labeled), or an inventory mode with ≥1 item.
  Exit 1: verdict `DENY` or `UNKNOWN`, or an inventory mode
  with nothing listed. Exit 2: usage error, missing config,
  include depth exceeded / missing include file (SQ19), or a
  `--url` without a scheme.
- Output order (text): verdict line; decider citation
  (file:line of the winning `http_access` rule, or the
  implicit-default rule + the last rule's file:line); the
  composed URL; the rule trace (evaluated-false rules with
  the deciding term and its value, shadowed rules, UNKNOWN
  blockers); findings; unmodeled inventory; coverage.
  `--json` renders the same structure (verdict, decider,
  composed URL, trace, findings, coverage) machine-readably.
- Read-only by construction: opens config, include, and ACL
  value files for reading only, never executes squid, never
  opens a socket, never performs DNS, never writes.
  Test-asserted: no subprocess invocation, no network, no
  DNS, no writes, and no environment reads.

## Out of scope (bannered, never silently modeled)

- **Peer/parent selection** — `cache_peer_access`,
  `always_direct` / `never_direct`, `cache_peer` choice:
  squidwho answers *allowed or denied*, never *via which
  peer* (SQ23).
- **Reply-side and adaptation rules** — `http_reply_access`,
  `adapted_http_access`, `miss_access`, `delay_access`,
  `cache`/`no_cache`: response/caching decisions happen
  after the `http_access` verdict this tool reports.
- **Authentication verdicts** — `proxy_auth`, `ident`,
  `external` helpers: presence inventoried (SQ12),
  grant/deny not decided.
- **SSL-Bump step rules** — `ssl_bump` peek/stare/bump
  actions and certificate state: inventoried, not verdicted.
- **Runtime state** — what the *running* daemon has in
  memory (helper replies, `maxconn` counters, DNS cache
  contents) can diverge from the files; every verdict is
  labeled on-disk policy. (The loaded-vs-disk honesty banner,
  AA14's sibling.)
- **Non-HTTP protocols through the proxy** — FTP/gopher
  fetch details beyond the `proto` value; the tool models
  the access decision, not the fetch.

## Not a validator (deliberate divergence, documented)

Real Squid refuses to start on any config error; squidwho
degrades: broken directives it was not asked about are warning
findings (SQ20/SQ21), dangling references are findings (SQ17),
and only defects that can change *this query's* winner poison
the verdict to UNKNOWN. One broken ACL must not blind the tool
to the other forty. The README must say this in one paragraph,
and must say `squid -k parse` remains the validation path.

## Hazards reviewed (why this design is safe to build)

1. **The reverse-of-last default is the catastrophic failure
   (SQ06).** A config ending in `http_access allow …` with no
   trailing `deny all` silently allows everything unmatched —
   the exact opposite of what a grep reader assumes, and the
   exact opposite of the HAProxy world's implicit-deny
   intuition. Any build that defaults unmatched to DENY has
   inverted the truth on real configs. The verdict line must
   name the reversed rule, and a missing explicit catch-all
   must be a finding on every run.
2. **First-match under three-valued conditions (SQ10/SQ13).**
   An UNKNOWN term in an early rule is not a skip: the real
   request might have taken that rule. Skipping it and
   reporting the next rule's verdict manufactures a confident
   answer from an undecidable prefix. Hence UNKNOWN blockers,
   never skips — and a missing ACL value file is never an
   empty value list (SQ20).
3. **The DNS trap (SQ03/SQ08/SQ10).** `dst` is `[slow]` because
   Squid resolves the URL host; `srcdomain` reverse-resolves
   the client; `dstdomain` reverse-resolves IP URLs. A static
   tool that resolves DNS itself answers a different question
   (what the resolver says *now*, from *this* machine) and
   would be wrong whenever the daemon's resolver disagrees.
   Hence: no DNS, ever; UNKNOWN with the lookup named.
4. **The dstdomain overlap quirk (SQ08).** The splay-tree
   behavior means the live daemon may honor only the most
   specific of overlapping entries while the documented
   intent is union. The tool evaluates the union and flags
   the overlap — the only honest middle, and the operator is
   warned rather than misled in either direction.
5. **Time is a moving target (SQ11).** A `time` ACL makes the
   verdict a function of *when*, and of *whose clock*. The
   tool never silently evaluates against its own invocation
   time without saying so; `--at` is the reproducible form,
   and the `[time-is-now-local]` banner is on every
   time-decided verdict without it.
6. **Regex dialect drift (SQ15).** POSIX-ERE vs PCRE builds make
   some patterns mean different things on different binaries;
   `[regex-approx]` on regex-decided verdicts, UNKNOWN on
   untranslatable patterns, is the ceiling of static honesty.
7. **CONNECT is a different URL shape (SQ07).** The authority
   form `host:port` has no path and no scheme; a tool that
   feeds it through the normal URL composer would test
   `urlpath_regex` against a path that does not exist and
   `url_regex` against a scheme that was never sent. The
   composed URL is printed so the shape is visible.
8. **Never executes (family rule).** Pure text parsing; a
   planted `$(touch marker)` in a comment, a regex, or an
   `external_acl_type` helper line — squid.conf carries helper
   command lines with real arguments — must be inert text.
   Dedicated never-executes test with payloads in comments,
   patterns, and helper definitions.

## Test plan (hermetic fixture configs; stdlib-only runner)

~50–60 tests, plain `python3` (no pytest — the aptpinswho lesson):

- **BG1 (rule core, SQ01/SQ04/SQ13):** first-match beats a
  *more permissive* later rule; bare unconditional rule;
  `!` negation (incl. `deny !Safe_ports` idiom); AND across
  terms; OR across rules; same-ACL value OR; repeated
  same-name same-type merge; `all` keyword.
- **BG2 (the default, SQ06):** no match + last rule allow →
  DENY (reversed, decider cited); no match + last rule deny
  → ALLOW (the footgun, finding raised); no rules at all →
  DENY; explicit trailing `deny all` → DENY by rule, not by
  default (decider differs).
- **BG3 (definition order & dangling, SQ02/SQ17):** forward
  reference → UNKNOWN + finding; undefined ACL → UNKNOWN +
  finding; same-name different-type → finding + UNKNOWN;
  ACL-name case mismatch → dangling, not a match.
- **BG4 (matching engine, SQ03/SQ08/SQ10):** src CIDR /
  netmask / range / IPv6 / `all`; src hostname value →
  UNKNOWN, never FALSE; dst with `--dst-ip` vs hostname →
  UNKNOWN; dstdomain exact vs dot-domain, case-insensitive,
  trailing-dot strip, overlap finding (union evaluated);
  dstdomain vs IP URL → UNKNOWN, `-n` → FALSE, `none`
  pattern → UNKNOWN; port ranges + port 0 branches;
  method exact; proto values incl. `cache_object` → FALSE;
  myport/localport with and without `--local`.
- **BG5 (files & dynamism, SQ12/SQ19/SQ20):** quoted-file
  expansion with provenance; missing value file → UNKNOWN,
  never empty; missing include → fatal exit 2; include depth
  cap; wildcard include lexical order; relative include
  resolved against including file's directory (finding);
  `proxy_auth` / `external` / `ident` / `maxconn` blockers;
  `srcdomain` blocker; multi-`--conf` concatenation order.
- **BG6 (time, SQ11):** day-abbrev matching incl. Sunday `S`
  vs Saturday `A`; time-window inside/outside; day-only and
  time-only specs; reversed range → unparseable finding;
  `--at` vs now (banner present without `--at`, absent with
  it); two-spec overnight window; time-decided verdict
  carries the banner.
- **BG7 (URL shape & regex, SQ07/SQ15):** `--url` parsing
  (scheme/host/port/path/query); explicit-flag override with
  finding; CONNECT authority-form composition (urlpath empty,
  url_regex over `host:port`); url_regex unanchored search;
  urlpath_regex excludes scheme/host; `-i`/`+i` flag
  tracking; regex-approx banner; untranslatable regex →
  UNKNOWN.
- **BG8 (honesty, SQ16/SQ20/SQ21/SQ23/SQ24):** unparseable
  line in the rule walk → UNKNOWN, in an unrelated directive
  → warning only; coverage completeness (every fixture
  asserts the coverage section names all files, ACLs, and
  rules); peer/reply/adaptation directives inventoried, never
  verdicted; `--list-acls` / `--list-rules` output incl. the
  SQ06 default stated explicitly; `--json` fidelity vs text
  verdicts; exit codes 0/1/2 across the matrix.
- **BG9 (safety):** never-executes payloads in comments,
  regexes, and `external_acl_type` lines; no-network/no-DNS/
  no-write assertion (family harness).

Dogfood: doccover + clicheck clean before the v1 commit, per
bench convention. README carries a Limitations section naming
SQ06/SQ08/SQ11/SQ12/SQ15 and the Out-of-scope list explicitly,
plus a pre-publish checklist.

## Build order

1. Tokenizer + loader (comments/continuations/quoting, SQ19
   includes, SQ20 value files, SQ21 recognizer).
2. ACL table (SQ02/SQ04) + evaluable-type engine (SQ03/SQ08/
   SQ10, Kleene logic, regex translation SQ15, time SQ11).
3. Rule walk (SQ01/SQ06/SQ13) + renderers (text/JSON) +
   coverage (SQ20) + inventory modes (SQ22).
4. Dogfood: doccover + clicheck --strict; bench-audit map
   extension; prepublish-check clean; README + CHANGELOG.

## Sources (read 2026-11-09)

- Squid cfgman, `acl` (5.10 / 6.9 / 7.0):
  http://www.squid-cache.org/Versions/v5/cfgman/acl.html
- Squid cfgman, `http_access` (4.17 / 5.10):
  http://www.squid-cache.org/Versions/v4/cfgman/
  (http_access: no-match default = opposite of last line;
  no-lines default = deny)
- Squid wiki, `SquidFaq/SquidAcl`:
  https://wiki.squid-cache.org/SquidFaq/SquidAcl
  (first-match, AND/OR, same-name rule, dstdomain dot
  semantics + splay-tree quirk, no-match reverses last rule)
- *Squid: The Definitive Guide* §6.2 (flylib):
  https://flylib.com/books/en/3.493.1.62/1/
  (single-pass define-before-use; value OR-logic)
- Amos Jeffries, squid-users 2012-06-20:
  http://www.squid-cache.org/mail-archive/squid-users/201206/0209.html
  (http_access tested at request receipt, request details
  only; per-directive rule lists independent)
- Squid source, `ACLTimeData.cc` (squid-3.0 mirror):
  https://mirror.math.princeton.edu/pub/squid/squid-3.0/src/ACLTimeData.cc
  (time-spec parse; reversed range is an error)
