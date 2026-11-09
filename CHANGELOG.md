# CHANGELOG — squidwho

## 1.0.0 (2026-11-09)

Initial release. Static model of Squid's documented access rules
(5.10 / 6.9 / 7.0 cfgman): which `http_access` line allows or denies
a request, and which `acl` lines decided it.

SQ01 first-match wins, AND within a rule / OR across rules, `!`
negation, bare unconditional rules, per-directive rule lists;
SQ02 define-before-use (single pass), same-name same-type merge,
same-name different-type fatal for rules using it, `all`
pre-defined as `src all` iff the file never defines it; SQ03
evaluable ACL-type set (src, dst, dstdomain, dstdom_regex,
url_regex, urlpath_regex, port, myport/localport, localip/myip,
method, proto, time) with everything else SQ12; SQ04 value
OR-logic (inline, merged, file-expanded); SQ05 request-only
evaluation; SQ06 no-match default reverses the last rule, no
rules means deny, with the missing-catch-all finding on every
run; SQ07 URL composition incl. CONNECT authority-form, explicit
flag overrides with findings, composed URL shown; SQ08 dstdomain
exact vs whole-domain, case-insensitive, trailing-dot strip,
splay-tree overlap finding with union evaluation, IP-URL reverse
lookup UNKNOWN / `-n` FALSE / `none` UNKNOWN; SQ10 Kleene
three-valued rules with UNKNOWN blockers, hostname src/dst values
UNKNOWN (never FALSE), port 0 branches; SQ11 time ACLs (day
abbrevs, reversed-range parse error, OR specs, two-spec overnight
windows, `--at` reproducible form, `[time-is-now-local]` banner);
SQ12 unmodeled dynamism bannered and UNKNOWN-poisoning; SQ13 the
walk (first TRUE wins, else SQ06 default); SQ15 regex translation
with POSIX-class splicing, `-i`/`+i` per-pattern flags,
`[regex-approx]` banner, untranslatable patterns UNKNOWN; SQ16–
SQ24 structural findings, coverage on every run, `--list-acls` /
`--list-rules` inventory modes incl. the SQ06 default stated
explicitly, http_access-only banner, exact verdict vocabulary
ALLOW / DENY / UNKNOWN. Exit 0/1/2; --json/--quiet/--version;
read-only, no subprocess, no socket, no DNS, no environment reads
(test-asserted).

Claims are [documented]/[docs-inferred]/[hypothesized] only — no
squid binary on the build box, so there is no live-agreement test;
82 hermetic fixture-tree tests, all green.

Build corrections during v1: POSIX-class translation first
emitted doubled brackets (`[[0-9]]`); rewritten to splice class
contents into the enclosing bracket expression (`[[:digit:]]` ->
`[0-9]`, `[[:alpha:]x]` -> `[a-zA-Zx]`). Two test expectations
corrected against the design: `url_regex` anchors against the
full composed URL (not the path), and the SQ06 default of a list
ending in `deny all` is ALLOW by reversal.
