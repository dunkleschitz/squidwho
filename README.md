# squidwho

Which `http_access` line allows or denies a request — and which
`acl` lines decided it?

`squid -k parse` validates a config; it never answers access
questions. The documented debug path is a live restart plus
`debug_options 28,3` plus `cache.log` spelunking — it answers only
after the fact, only for a request that actually happened, and only
by restarting the proxy. grep prints every candidate line and
adjudicates none of them — and it cannot see that the no-match
default is the *reverse* of the last rule's action (SQ06), the
single most counter-intuitive rule in the file. `squidwho` is a
static model of Squid's documented access rules that answers the
question with file:line provenance, and says UNKNOWN (naming the
blocker) whenever the answer is not statically knowable.

## Usage

```
squidwho --src IP --dst HOST [--port N] [--method M]
         [--url URL] [--proto PROTO] [--at DATETIME]
         [--dst-ip IP] [--local ADDR:PORT] [--conf FILE]...
squidwho --list-acls [--conf FILE]...
squidwho --list-rules [--conf FILE]...
```

- `--src` / `--dst` are required for an access query. `--method`
  defaults to `GET`; `--port` is optional (absent → the scheme
  default per SQ07, or UNKNOWN-valued port terms if no scheme
  default applies).
- `--url` supplies dst/port/path/proto; explicit `--dst` /
  `--port` / `--proto` flags override the parsed components, with
  a finding noting the override. A `--url` without a scheme is a
  usage error (exit 2).
- `--at` evaluates `time` ACLs against a stated instant (ISO
  datetime, or bare `HH:MM` meaning today); without it, time ACLs
  are evaluated against this machine's current local time and the
  verdict carries the `[time-is-now-local]` banner.
- `--dst-ip` supplies the destination IP for `dst` ACLs; without
  it (and a hostname `--dst`), `dst` terms are UNKNOWN — Squid
  DNS-resolves the URL host, and this tool never does DNS.
- `--local ADDR:PORT` supplies the local socket for `myport` /
  `localport` / `localip` / `myip` ACLs; without it those terms
  are UNKNOWN.
- `--conf` is repeatable; files are concatenated in the order
  given (a squidwho convenience — Squid itself takes one config
  file; the concatenation is bannered). Default:
  `/etc/squid/squid.conf` if it exists, else exit 2.
- `--list-acls` lists every ACL in load order, with type, value
  count, and evaluable/unmodeled status. `--list-rules` lists
  every `http_access` rule in order, with action, terms, and
  file:line — plus the SQ06 default the list implies, stated
  explicitly.
- `--json` renders the same structure machine-readably; `--quiet`
  prints the verdict line only; `--version` prints the version.

## Examples

```bash
# Would 10.0.0.5 reaching example.com:443 with CONNECT be allowed?
squidwho --src 10.0.0.5 --dst example.com --port 443 \
  --method CONNECT --conf /etc/squid/squid.conf

# Same query, machine-readable
squidwho --src 10.0.0.5 --dst example.com --port 443 \
  --method CONNECT --json --conf /etc/squid/squid.conf

# The SQ06 footgun: config ends in `http_access deny badhost`
# with no trailing `deny all` -- unmatched requests are ALLOWED
squidwho --src 192.168.1.1 --dst example.com --conf squid.conf
# ALLOW
# decider: implicit-default (reverse of last rule (deny at
#   squid.conf:4, SQ06)) -- last rule allow at squid.conf:4

# What does the config actually contain?
squidwho --list-rules --conf /etc/squid/squid.conf
squidwho --list-acls --conf /etc/squid/squid.conf
```

## Verdicts

| Verdict | Meaning | Exit |
|---|---|---|
| `ALLOW` | A rule allowed it, or the SQ06 default reversed a final `deny` (labeled) | 0 |
| `DENY` | A rule denied it, the SQ06 default reversed a final `allow`, or no rules exist | 1 |
| `UNKNOWN` | A blocker (named) prevents a static answer | 1 |

Every run also prints a rule trace (evaluated-false rules with
the deciding term, shadowed rules, UNKNOWN blockers), findings,
an unmodeled inventory, and a coverage section (files read with
byte/line counts, ACLs defined, rules evaluated/shadowed/blocked,
unparseable lines, and other access directives inventoried).

## Pinned semantics (SQ01–SQ24, see DESIGN-squidwho.md)

- **SQ01** First match wins; AND within a rule, OR across rules;
  `!` negates one ACL element; a bare rule matches
  unconditionally. Each directive type has its own rule list.
- **SQ02** ACLs must be defined before use (single pass); same
  name + same type merges (values OR); same name + different type
  is fatal for rules using it; `all` is pre-defined as `src all`
  iff the file never defines it.
- **SQ03** Evaluable ACL types: `src`, `dst`, `dstdomain`,
  `dstdom_regex`, `url_regex`, `urlpath_regex`, `port`,
  `myport`/`localport`, `localip`/`myip`, `method`, `proto`,
  `time`. Everything else is SQ12.
- **SQ04** Value OR-logic inside one ACL (inline, merged,
  file-expanded).
- **SQ06** The no-match default reverses the last rule; no rules
  at all means deny. A config ending in `http_access deny …`
  with no trailing `deny all` silently allows everything
  unmatched — the verdict line names the reversed rule, and a
  finding flags the missing explicit catch-all on every run.
- **SQ07** URL composition, including CONNECT authority-form
  (`host:port`, no path, no scheme); `urlpath_regex` tests the
  empty string for CONNECT. The composed URL is shown in the
  output.
- **SQ08** `dstdomain`: exact host vs `.domain` (whole domain,
  including the bare domain), case-insensitive, one trailing dot
  stripped; the splay-tree overlap quirk is flagged and the union
  is evaluated; IP URLs need a reverse lookup (UNKNOWN) unless
  `-n` (FALSE), and a `none` pattern against an IP URL is UNKNOWN.
- **SQ10** Three-valued (Kleene) rules: FALSE dominates, then
  UNKNOWN, then TRUE; `!` keeps UNKNOWN unknown. A rule matches
  iff its AND is TRUE; an UNKNOWN rule before any TRUE rule is a
  blocker.
- **SQ11** `time` ACLs: day abbreviations S M T W H F A, `h1:m1`
  must be less than `h2:m2` (reversed is a parse error), specs OR;
  `--at` is the reproducible form.
- **SQ12** Unmodeled dynamism (`proxy_auth`, `external`, `ident`,
  `maxconn`, `srcdomain`, `ssl::`/`tls::`, …) is bannered and
  UNKNOWN-poisoning, never approximated.
- **SQ15** Regex is an approximation: POSIX classes are
  translated to Python `re` where they coincide; untranslatable
  patterns are UNKNOWN; regex-decided verdicts carry
  `[regex-approx]`. `-i`/`+i` flags are per-pattern, tracked in
  order.
- **SQ16–SQ24** Structural findings, coverage on every run,
  inventory modes, the http_access-only banner, and the exact
  verdict vocabulary.

## Limitations

- **SQ06** — the reverse-of-last default is the tool's reason to
  exist and its sharpest edge: if the config's last rule is a
  `deny`, unmatched requests are ALLOWED. Read the decider line.
- **SQ08** — the dstdomain splay-tree overlap quirk: when one
  value in an ACL is a subdomain of another, the live daemon may
  honor only the most specific while this tool evaluates the
  union (the documented intent) and flags the overlap.
- **SQ11** — time is a moving target: a `time` verdict without
  `--at` is evaluated against this machine's clock, which may
  not be the proxy host's. `weekdays`/`weekends` day tokens are
  not confirmed to parse and are treated as unparseable (SQ21),
  never guessed.
- **SQ12** — anything the CLI cannot know statically (auth state,
  helper replies, connection counts, reverse DNS, certificate
  state) makes the verdict UNKNOWN, never a guess.
- **SQ15** — regex dialect drift: Squid regexes are POSIX-ERE and
  this tool translates them to Python `re`; a pattern the
  translator accepts but POSIX reads differently is the known
  residual risk, named here and bannered `[regex-approx]` on
  regex-decided verdicts.
- `method` values are compared case-sensitively (the cfgman never
  states the case rule; HTTP methods are uppercase by
  convention). A live contradiction flips the tag, not the rule.
- Runtime state can diverge from the files; every verdict is
  on-disk policy.
- `squidwho` is **not a validator**: `squid -k parse` remains the
  validation path. Real Squid refuses to start on any config
  error; squidwho degrades — broken directives it was not asked
  about are warning findings, dangling references are findings,
  and only defects that can change *this query's* winner poison
  the verdict to UNKNOWN. One broken ACL must not blind the tool
  to the other forty.

## Out of scope

- **Peer/parent selection** — `cache_peer_access`,
  `always_direct` / `never_direct`, `cache_peer` choice: squidwho
  answers *allowed or denied*, never *via which peer*.
- **Reply-side and adaptation rules** — `http_reply_access`,
  `adapted_http_access`, `miss_access`, `delay_access`,
  `cache`/`no_cache`: response/caching decisions happen after the
  `http_access` verdict this tool reports.
- **Authentication verdicts** — `proxy_auth`, `ident`,
  `external` helpers: presence inventoried (SQ12), grant/deny
  not decided.
- **SSL-Bump step rules** — `ssl_bump` peek/stare/bump actions
  and certificate state: inventoried, not verdicted.
- **Runtime state** — what the *running* daemon has in memory
  (helper replies, `maxconn` counters, DNS cache contents).
- **Non-HTTP protocols through the proxy** — FTP/gopher fetch
  details beyond the `proto` value; the tool models the access
  decision, not the fetch.

## Tests

83 tests (stdlib unittest, `python3 test_squidwho.py`): rule core,
the SQ06 default, definition order and dangling references, the
matching engine, files and dynamism, time ACLs, URL shape and
regex, honesty, safety. No squid binary exists on the build box,
so there is no live-agreement test — fixture trees are the only
oracle, exactly as the manual text is the only authority.

## Pre-publish checklist

- [x] Tests green (83/83)
- [x] Dogfood: doccover 15/15 + clicheck 15/15 clean (Nov 9, 2026 campaign)
- [x] Bench-audit map extended (A1–A7 clean, Nov 9, 2026 campaign)
- [x] README + CHANGELOG + LICENSE (MIT) in place
- [x] CI workflow (.github/workflows/tests.yml, Python 3.12)
- [x] Prepublish-check clean (Nov 9, 2026 campaign)

## License

MIT — see LICENSE.
