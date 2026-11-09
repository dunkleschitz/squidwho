"""Tests for squidwho. Hermetic fixture-tree tests (BG1-BG9);
stdlib-only runner, plain `python3 test_squidwho.py` (no pytest
-- the aptpinswho lesson). No squid binary exists on this box,
so there is no live-agreement test to skip-guard against; fixture
trees are the only oracle, exactly as the manual text is the only
authority."""
import importlib.machinery
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "squidwho")
_mod = importlib.machinery.SourceFileLoader("squidwho_mod", TOOL)
squidwho = _mod.load_module()


def run_cli(args, cwd=None):
    proc = subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


class TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="squidwho-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def conf(self, text, name="squid.conf"):
        return self.write(name, text)

    def query(self, conf_path, src="10.1.2.3", dst="example.com",
              extra=None, conf_args=None):
        args = ["--src", src, "--dst", dst]
        if conf_args is not None:
            args += conf_args
        else:
            args += ["--conf", conf_path]
        if extra:
            args += extra
        return run_cli(args)

    def query_json(self, conf_path, src="10.1.2.3",
                   dst="example.com", extra=None, conf_args=None):
        rc, out, err = self.query(conf_path, src, dst,
                                  (extra or []) + ["--json"],
                                  conf_args)
        try:
            data = json.loads(out)
        except ValueError:
            self.fail("not JSON (rc=%d, err=%r): %r" % (rc, err, out))
        return rc, data, err


# ------------------------------------------------------------------- BG1

class BG1RuleCore(TmpTree):
    def test_first_match_beats_more_permissive_later_rule(self):
        # SQ01/SQ13: declaration order, not specificity, decides.
        cfg = self.conf(
            "acl any src all\n"
            "acl local src 10.0.0.0/8\n"
            "http_access deny any\n"
            "http_access allow local\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "DENY")
        self.assertEqual(data["decider"]["where"], cfg + ":3")

    def test_bare_unconditional_rule(self):
        cfg = self.conf("http_access allow\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["decider"]["kind"], "http_access")

    def test_negation_deny_not_safe_ports(self):
        # The stock-config idiom: deny everything not on Safe_ports.
        cfg = self.conf(
            "acl Safe_ports port 80 443\n"
            "http_access deny !Safe_ports\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(cfg, extra=["--port", "22"])
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(cfg, extra=["--port", "443"])
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "ALLOW")

    def test_and_across_terms(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "acl bad dstdomain .evil.example\n"
            "http_access deny local bad\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(cfg, dst="x.evil.example")
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(cfg, dst="good.example")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_or_across_rules(self):
        cfg = self.conf(
            "acl a src 10.0.0.1\n"
            "acl b src 10.0.0.2\n"
            "http_access allow a\n"
            "http_access allow b\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="10.0.0.2")
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["decider"]["where"], cfg + ":4")
        rc, data, _ = self.query_json(cfg, src="10.0.0.3")
        self.assertEqual(data["verdict"], "DENY")

    def test_same_acl_value_or(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8 192.168.0.0/16\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="192.168.5.5")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_repeated_same_name_same_type_merges(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "acl local src 192.168.0.0/16\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="192.168.5.5")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_all_keyword(self):
        cfg = self.conf("http_access allow all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "ALLOW")

    def test_other_directive_type_does_not_disturb_order(self):
        # SQ01: per-directive rule lists are independent (Jeffries).
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_reply_access deny all\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["decider"]["where"], cfg + ":2")


# ------------------------------------------------------------------- BG2

class BG2Default(TmpTree):
    def test_no_match_last_allow_reverses_to_deny(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n")
        rc, data, _ = self.query_json(cfg, src="192.168.1.1")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "DENY")
        self.assertEqual(data["decider"]["kind"], "implicit-default")
        self.assertEqual(data["decider"]["where"], cfg + ":2")
        self.assertIn("reverse of last rule", data["decider"]["note"])

    def test_default_decider_line_names_last_rules_action(self):
        # Regression: the text decider line once printed the
        # *reversed* action as the last rule's action ("last rule
        # deny" for a trailing `allow` rule). It must name the
        # rule's own action.
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n")
        rc, out, _ = self.query(cfg, src="192.168.1.1")
        self.assertEqual(rc, 1)
        self.assertIn("decider: implicit-default (reverse of last "
                      "rule (allow at %s:2, SQ06)) -- last rule "
                      "allow at %s:2" % (cfg, cfg), out)

    def test_no_match_last_deny_reverses_to_allow_footgun(self):
        # SQ06: the footgun -- a config ending in deny with no
        # trailing `deny all` silently allows everything unmatched.
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "acl badhost dstdomain bad.example\n"
            "http_access allow local\n"
            "http_access deny badhost\n")
        rc, data, _ = self.query_json(cfg, src="192.168.1.1")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["decider"]["kind"], "implicit-default")
        self.assertEqual(data["decider"]["action"], "allow")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ06", fids)

    def test_no_rules_at_all_denies(self):
        cfg = self.conf("acl local src 10.0.0.0/8\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "DENY")
        self.assertEqual(data["decider"]["kind"], "implicit-default")
        self.assertIsNone(data["decider"]["where"])

    def test_explicit_trailing_deny_all_is_by_rule_not_default(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="192.168.1.1")
        self.assertEqual(data["verdict"], "DENY")
        self.assertEqual(data["decider"]["kind"], "http_access")
        self.assertEqual(data["decider"]["where"], cfg + ":3")
        fids = [f["id"] for f in data["findings"]]
        self.assertNotIn("SQ06", fids)


# ------------------------------------------------------------------- BG3

class BG3DefinitionOrder(TmpTree):
    def test_forward_reference_is_unknown(self):
        cfg = self.conf(
            "http_access allow local\n"
            "acl local src 10.0.0.0/8\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertIn("local", data["blocker"])
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ17", fids)

    def test_undefined_acl_is_unknown(self):
        cfg = self.conf(
            "http_access allow nope\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ17", fids)

    def test_dangling_ref_absorbed_when_rule_already_false(self):
        # Kleene absorption (SQ10/SQ17): a FALSE term decides the
        # rule, so the dangling reference is a warning only.
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local nope\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="192.168.1.1")
        self.assertEqual(data["verdict"], "DENY")
        self.assertEqual(data["decider"]["kind"], "http_access")

    def test_same_name_different_type_is_unknown(self):
        cfg = self.conf(
            "acl x src 10.0.0.0/8\n"
            "acl x dstdomain example.com\n"
            "http_access allow x\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ16", fids)

    def test_acl_name_case_mismatch_is_dangling(self):
        cfg = self.conf(
            "acl localhost src 127.0.0.1\n"
            "http_access allow Localhost\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="127.0.0.1")
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ17", fids)


# ------------------------------------------------------------------- BG4

class BG4MatchingEngine(TmpTree):
    def test_src_cidr_netmask_range_ipv6(self):
        cfg = self.conf(
            "acl a src 10.0.0.0/255.0.0.0\n"
            "acl b src 192.168.1.10-192.168.1.20\n"
            "acl c src 2001:db8::/32\n"
            "http_access allow a\n"
            "http_access allow b\n"
            "http_access allow c\n"
            "http_access deny all\n")
        for src in ("10.5.6.7", "192.168.1.15", "2001:db8::1"):
            rc, data, _ = self.query_json(cfg, src=src)
            self.assertEqual(data["verdict"], "ALLOW", src)
        rc, data, _ = self.query_json(cfg, src="11.0.0.1")
        self.assertEqual(data["verdict"], "DENY")

    def test_src_hostname_value_is_unknown_never_false(self):
        cfg = self.conf(
            "acl hosts src laptop.example\n"
            "http_access allow hosts\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="10.1.2.3")
        self.assertEqual(data["verdict"], "UNKNOWN")
        reasons = [u["reason"] for u in data["unmodeled"]]
        self.assertTrue(any("hostname" in r for r in reasons))

    def test_dst_with_dst_ip_vs_hostname_unknown(self):
        cfg = self.conf(
            "acl target dst 203.0.113.5\n"
            "http_access allow target\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, extra=["--dst-ip",
                                                  "203.0.113.5"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_dst_literal_ip_from_dst_host(self):
        cfg = self.conf(
            "acl target dst 203.0.113.5\n"
            "http_access allow target\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="203.0.113.5")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_dstdomain_exact_vs_dot_domain(self):
        cfg = self.conf(
            "acl exact dstdomain www.example.com\n"
            "acl whole dstdomain .example.com\n"
            "http_access allow exact\n"
            "http_access allow whole\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="www.example.com")
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(cfg, dst="example.com")
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(cfg, dst="other.com")
        self.assertEqual(data["verdict"], "DENY")

    def test_dstdomain_case_insensitive_and_trailing_dot(self):
        cfg = self.conf(
            "acl dom dstdomain .Example.COM\n"
            "http_access allow dom\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="WWW.EXAMPLE.COM")
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(cfg, dst="example.com.")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_dstdomain_overlap_finding_union_evaluated(self):
        cfg = self.conf(
            "acl dom dstdomain www.example.com .example.com\n"
            "http_access allow dom\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="www.example.com")
        self.assertEqual(data["verdict"], "ALLOW")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ08", fids)

    def test_dstdomain_vs_ip_url_unknown(self):
        cfg = self.conf(
            "acl dom dstdomain example.com\n"
            "http_access allow dom\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="203.0.113.5")
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_dstdomain_vs_ip_url_n_flag_is_false(self):
        cfg = self.conf(
            "acl dom dstdomain -n example.com\n"
            "http_access allow dom\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="203.0.113.5")
        self.assertEqual(data["verdict"], "DENY")

    def test_dstdomain_none_pattern_vs_ip_url_unknown(self):
        cfg = self.conf(
            "acl dom dstdomain none\n"
            "http_access allow dom\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, dst="203.0.113.5")
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_port_ranges_and_port_zero(self):
        cfg = self.conf(
            "acl web port 80 443\n"
            "acl rng port 8000-8010\n"
            "acl noport port 0\n"
            "http_access allow web\n"
            "http_access allow rng\n"
            "http_access allow noport\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, extra=["--port", "8005"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(cfg, extra=["--port", "22"])
        self.assertEqual(data["verdict"], "DENY")

    def test_port_zero_matches_only_with_no_port_anywhere(self):
        # Port 0 matches iff no --port, no --url port, and the
        # scheme has no default port (SQ10).
        cfg = self.conf(
            "acl noport port 0\n"
            "http_access allow noport\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--proto", "gopher"])
        self.assertEqual(data["verdict"], "ALLOW")
        # --port absent but scheme default http/80: the port is 80,
        # so port 0 does not match.
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "DENY")
        # An earlier port rule with an unknowable port is a blocker,
        # not a skip (SQ10/SQ13): the port-0 rule never gets a say.
        cfg2 = self.conf(
            "acl web port 80 443\n"
            "acl noport port 0\n"
            "http_access allow web\n"
            "http_access allow noport\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg2, extra=["--proto", "gopher"])
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_method_exact_case_sensitive(self):
        cfg = self.conf(
            "acl get method GET\n"
            "http_access allow get\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, extra=["--method", "GET"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(cfg, extra=["--method", "get"])
        self.assertEqual(data["verdict"], "DENY")

    def test_proto_values_and_cache_object(self):
        cfg = self.conf(
            "acl co proto cache_object\n"
            "acl https proto HTTPS\n"
            "http_access allow co\n"
            "http_access allow https\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "https://example.com/"])
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["decider"]["where"], cfg + ":4")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/"])
        self.assertEqual(data["verdict"], "DENY")

    def test_myport_localport_without_local_is_unknown(self):
        cfg = self.conf(
            "acl lp myport 3128\n"
            "http_access allow lp\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "UNKNOWN")
        rc, data, _ = self.query_json(
            cfg, extra=["--local", "127.0.0.1:3128"])
        self.assertEqual(data["verdict"], "ALLOW")

    def test_localip_with_and_without_local(self):
        cfg = self.conf(
            "acl li localip 127.0.0.1\n"
            "http_access allow li\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--local", "127.0.0.1:3128"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--local", "10.0.0.1:3128"])
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "UNKNOWN")

# ------------------------------------------------------------------- BG5

class BG5FilesAndDynamism(TmpTree):
    def test_quoted_value_file_expansion_with_provenance(self):
        vals = self.write("bad.txt",
                          "# comment\n"
                          ".evil.example\n"
                          "\n"
                          "bad.example\n")
        cfg = self.conf(
            "acl bad dstdomain \"%s\"\n"
            "http_access deny bad\n"
            "http_access allow all\n" % vals)
        rc, data, _ = self.query_json(cfg, dst="x.evil.example")
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(cfg, dst="bad.example")
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(cfg, dst="good.example")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_missing_value_file_is_unknown_never_empty(self):
        cfg = self.conf(
            "acl bad dstdomain \"/nonexistent/bad.txt\"\n"
            "http_access deny bad\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(cfg, dst="good.example")
        # Never treated as an empty list ("never matches") -- SQ20.
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ20", fids)

    def test_relative_value_file_resolves_against_config_dir(self):
        sub = self.write("conf.d/bad.txt", ".evil.example\n")
        cfg = self.write("conf.d/squid.conf",
                         "acl bad dstdomain \"bad.txt\"\n"
                         "http_access deny bad\n"
                         "http_access allow all\n")
        rc, data, _ = self.query_json(cfg, dst="x.evil.example")
        self.assertEqual(data["verdict"], "DENY")
        self.assertTrue(any("SQ20" == f["id"]
                            for f in data["findings"]))

    def test_missing_include_is_fatal_exit_2(self):
        cfg = self.conf("include /nonexistent/inc.conf\n"
                        "http_access allow all\n")
        rc, _, err = self.query(cfg)
        self.assertEqual(rc, 2)
        self.assertIn("include", err)

    def test_include_depth_cap(self):
        # 18 nested includes: depth 17 exceeds the 16-level cap.
        prev = self.write("i17.conf", "http_access allow all\n")
        for n in range(16, -1, -1):
            prev = self.write("i%d.conf" % n,
                              "include i%d.conf\n" % (n + 1))
        rc, _, err = self.query(prev)
        self.assertEqual(rc, 2)
        self.assertIn("depth", err)

    def test_wildcard_include_lexical_order(self):
        self.write("inc/b.conf",
                   "acl b src 10.0.0.2\n"
                   "http_access allow b\n")
        self.write("inc/a.conf",
                   "acl a src 10.0.0.1\n"
                   "http_access allow a\n")
        cfg = self.conf("include inc/*.conf\n"
                        "http_access deny all\n")
        rc, out, _ = run_cli(["--list-rules", "--conf", cfg])
        self.assertEqual(rc, 0)
        # Lexical: a.conf's rule (allow a) precedes b.conf's.
        self.assertLess(out.index("allow a"), out.index("allow b"))

    def test_relative_include_resolves_against_including_dir(self):
        self.write("conf.d/extra.conf",
                   "acl extra src 10.9.9.9\n"
                   "http_access allow extra\n")
        cfg = self.write("conf.d/squid.conf",
                         "include extra.conf\n"
                         "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="10.9.9.9")
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertTrue(any("SQ19" == f["id"]
                            for f in data["findings"]))

    def test_unmodeled_blockers(self):
        for type_line, acl in (
                ("acl auth proxy_auth REQUIRED\n", "auth"),
                ("acl ext external myhelper\n", "ext"),
                ("acl who ident joe\n", "who"),
                ("acl mc maxconn 5\n", "mc"),
                ("acl sd srcdomain .example\n", "sd")):
            cfg = self.conf(
                type_line +
                "http_access deny %s\n"
                "http_access allow all\n" % acl)
            rc, data, _ = self.query_json(cfg)
            self.assertEqual(data["verdict"], "UNKNOWN", acl)
            reasons = [u["reason"] for u in data["unmodeled"]]
            self.assertTrue(reasons, acl)

    def test_multi_conf_concatenation_order(self):
        c1 = self.conf("http_access allow all\n", name="a.conf")
        c2 = self.conf("acl local src 10.0.0.0/8\n"
                       "http_access deny local\n", name="b.conf")
        # a.conf first: its unconditional allow wins.
        rc, data, _ = self.query_json(
            c1, conf_args=["--conf", c1, "--conf", c2])
        self.assertEqual(data["verdict"], "ALLOW")
        # b.conf first: the deny-local rule wins for 10/8.
        rc, data, _ = self.query_json(
            c1, conf_args=["--conf", c2, "--conf", c1])
        self.assertEqual(data["verdict"], "DENY")
        self.assertTrue(any("SQ19" == f["id"]
                            for f in data["findings"]))

    def test_continuation_and_comments_and_quoting(self):
        cfg = self.conf(
            "# a comment line\n"
            "acl local src 10.0.0.0/8 \\\n"
            "    192.168.0.0/16  # trailing comment\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="192.168.1.1")
        self.assertEqual(data["verdict"], "ALLOW")


# ------------------------------------------------------------------- BG6

class BG6Time(TmpTree):
    def _time_cfg(self, spec):
        return self.conf(
            "acl work time %s\n"
            "http_access allow work\n"
            "http_access deny all\n" % spec)

    def test_day_abbrev_sunday_vs_saturday(self):
        # 2026-11-08 is a Sunday; 2026-11-07 is a Saturday.
        cfg = self._time_cfg("S 09:00-17:00")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-08T10:00"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-07T10:00"])
        self.assertEqual(data["verdict"], "DENY")
        cfg2 = self._time_cfg("A 09:00-17:00")
        rc, data, _ = self.query_json(
            cfg2, extra=["--at", "2026-11-07T10:00"])
        self.assertEqual(data["verdict"], "ALLOW")

    def test_time_window_inside_outside(self):
        cfg = self._time_cfg("MTWHF 09:00-17:00")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T12:00"])  # Monday
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T08:59"])
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T17:00"])
        self.assertEqual(data["verdict"], "DENY")

    def test_day_only_and_time_only_specs(self):
        cfg = self._time_cfg("M")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T03:00"])  # Monday
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-10T03:00"])  # Tuesday
        self.assertEqual(data["verdict"], "DENY")
        cfg2 = self._time_cfg("09:00-10:00")
        rc, data, _ = self.query_json(
            cfg2, extra=["--at", "2026-11-10T09:30"])
        self.assertEqual(data["verdict"], "ALLOW")

    def test_reversed_range_is_unparseable(self):
        cfg = self._time_cfg("MTWHF 17:00-09:00")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T12:00"])
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ21", fids)

    def test_unknown_day_token_is_unparseable(self):
        cfg = self._time_cfg("weekdays 09:00-17:00")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T12:00"])
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ21", fids)

    def test_now_banner_present_without_at_absent_with_at(self):
        cfg = self._time_cfg("SMTWHFA 00:00-24:00")
        rc, out, _ = self.query(cfg)
        self.assertIn("[time-is-now-local]", out)
        rc, out, _ = self.query(
            cfg, extra=["--at", "2026-11-09T12:00"])
        self.assertNotIn("[time-is-now-local]", out)

    def test_two_spec_overnight_window(self):
        cfg = self._time_cfg("22:00-24:00 00:00-06:00")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T23:30"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T02:00"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--at", "2026-11-09T12:00"])
        self.assertEqual(data["verdict"], "DENY")

    def test_bare_time_at_means_today(self):
        cfg = self._time_cfg("SMTWHFA 00:00-24:00")
        rc, data, _ = self.query_json(cfg, extra=["--at", "12:00"])
        self.assertEqual(data["verdict"], "ALLOW")


# ------------------------------------------------------------------- BG7

class BG7UrlAndRegex(TmpTree):
    def test_url_parsing(self):
        cfg = self.conf(
            "acl p urlpath_regex ^/api/\n"
            "http_access allow p\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/api/users?x=1"])
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["composed_url"],
                         "http://example.com/api/users?x=1")

    def test_explicit_flag_override_with_finding(self):
        cfg = self.conf(
            "acl p urlpath_regex ^/api/\n"
            "http_access allow p\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://other.com/api/x",
                        "--dst", "example.com"])
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertTrue(any("SQ07" == f["id"]
                            for f in data["findings"]))

    def test_url_without_scheme_is_exit_2(self):
        cfg = self.conf("http_access allow all\n")
        rc, _, err = self.query(
            cfg, extra=["--url", "example.com/path"])
        self.assertEqual(rc, 2)

    def test_connect_authority_form(self):
        cfg = self.conf(
            "acl u url_regex example\\.com:443$\n"
            "acl p urlpath_regex ^$\n"
            "acl d dstdomain example.com\n"
            "http_access allow u p d\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--method", "CONNECT", "--port", "443"])
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["composed_url"], "example.com:443")

    def test_connect_urlpath_empty_nonempty_pattern_fails(self):
        cfg = self.conf(
            "acl p urlpath_regex /api\n"
            "http_access allow p\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--method", "CONNECT", "--port", "443"])
        self.assertEqual(data["verdict"], "DENY")

    def test_url_regex_unanchored_search(self):
        cfg = self.conf(
            "acl u url_regex evil\n"
            "http_access deny u\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/very-evil-path"])
        self.assertEqual(data["verdict"], "DENY")

    def test_urlpath_regex_excludes_scheme_and_host(self):
        cfg = self.conf(
            "acl u urlpath_regex example\\.com\n"
            "http_access deny u\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/ok"])
        # The host is not part of the urlpath target.
        self.assertEqual(data["verdict"], "ALLOW")

    def test_regex_i_flag_tracking(self):
        cfg = self.conf(
            "acl u url_regex -i EVIL +i evil\n"
            "http_access deny u\n"
            "http_access allow all\n")
        # -i EVIL matches "evil" (case-insensitive).
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/evil"])
        self.assertEqual(data["verdict"], "DENY")
        # +i evil is case-sensitive: "EVIL" in the URL does not
        # match the second pattern, but the first (-i) pattern
        # still matches it.
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/EVIL"])
        self.assertEqual(data["verdict"], "DENY")

    def test_regex_i_plus_i_distinguishes(self):
        cfg = self.conf(
            "acl u url_regex +i EVIL -i evil\n"
            "http_access deny u\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/EVIL"])
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/evil"])
        self.assertEqual(data["verdict"], "DENY")
        # A URL with neither case form: no match.
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/eViL"])
        # -i evil matches eViL case-insensitively.
        self.assertEqual(data["verdict"], "DENY")

    def test_regex_approx_banner(self):
        cfg = self.conf(
            "acl u url_regex example\\.com/api/\n"
            "http_access allow u\n"
            "http_access deny all\n")
        rc, out, _ = self.query(
            cfg, extra=["--url", "http://example.com/api/x"])
        self.assertIn("[regex-approx]", out)

    def test_untranslatable_regex_is_unknown(self):
        cfg = self.conf(
            "acl u url_regex foo(?=bar)\n"
            "http_access allow u\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/foobar"])
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_posix_class_translated(self):
        cfg = self.conf(
            "acl u url_regex /[[:digit:]]+$\n"
            "http_access allow u\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/item/42"])
        self.assertEqual(data["verdict"], "ALLOW")
        rc, data, _ = self.query_json(
            cfg, extra=["--url", "http://example.com/item/abc"])
        self.assertEqual(data["verdict"], "DENY")

    def test_dstdom_regex(self):
        cfg = self.conf(
            "acl d dstdom_regex ^.*\\.evil\\.example$\n"
            "http_access deny d\n"
            "http_access allow all\n")
        rc, data, _ = self.query_json(cfg, dst="a.evil.example")
        self.assertEqual(data["verdict"], "DENY")
        rc, data, _ = self.query_json(cfg, dst="evil.example")
        self.assertEqual(data["verdict"], "ALLOW")


# ------------------------------------------------------------------- BG8

class BG8Honesty(TmpTree):
    def test_unparseable_line_in_walk_is_unknown(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "frobnicate the wobble\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="192.168.1.1")
        self.assertEqual(data["verdict"], "UNKNOWN")
        fids = [f["id"] for f in data["findings"]]
        self.assertIn("SQ21", fids)

    def test_unparseable_line_after_winner_is_shadowed(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "frobnicate the wobble\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="10.1.1.1")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_malformed_known_directive_is_warning_only(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "refresh_pattern\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg, src="10.1.1.1")
        self.assertEqual(data["verdict"], "ALLOW")

    def test_coverage_names_all_files_acls_rules(self):
        inc = self.write("inc.conf",
                         "acl inc src 10.2.0.0/16\n")
        cfg = self.conf(
            "include inc.conf\n"
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        cov = data["coverage"]
        self.assertEqual(len(cov["files"]), 2)
        names = [a["name"] for a in cov["acls"]]
        self.assertIn("local", names)
        self.assertIn("inc", names)
        self.assertIn("all", names)     # builtin default
        self.assertEqual(cov["rules"]["total"], 2)

    def test_other_access_directives_inventoried_never_verdicted(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_reply_access deny all\n"
            "cache_peer_access peer1 deny all\n"
            "miss_access allow all\n"
            "ssl_bump peek step1\n"
            "http_access deny all\n")
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(data["verdict"], "ALLOW")
        other = data["coverage"]["other_directives"]
        self.assertEqual(other.get("http_reply_access"), 1)
        self.assertEqual(other.get("cache_peer_access"), 1)
        self.assertEqual(other.get("miss_access"), 1)
        self.assertEqual(other.get("ssl_bump"), 1)

    def test_list_acls(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "acl auth proxy_auth REQUIRED\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, out, _ = run_cli(["--list-acls", "--conf", cfg])
        self.assertEqual(rc, 0)
        self.assertIn("local (src", out)
        self.assertIn("auth (proxy_auth", out)
        self.assertIn("unmodeled", out)
        rc, out, _ = run_cli(["--list-acls", "--conf", cfg, "--json"])
        data = json.loads(out)
        self.assertEqual(len(data["acls"]), 3)  # local, auth, builtin all
        by_name = {a["name"]: a for a in data["acls"]}
        self.assertTrue(by_name["local"]["evaluable"])
        self.assertFalse(by_name["auth"]["evaluable"])

    def test_list_acls_always_includes_builtin_all(self):
        cfg = self.conf("http_access allow all\n")
        # Only the builtin `all` exists, so this still lists one.
        rc, out, _ = run_cli(["--list-acls", "--conf", cfg])
        self.assertEqual(rc, 0)
        self.assertIn("all (src", out)

    def test_list_rules_states_sq06_default(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc, out, _ = run_cli(["--list-rules", "--conf", cfg])
        self.assertEqual(rc, 0)
        self.assertIn("allow local", out)
        self.assertIn("deny all", out)
        # Last rule is deny -> the SQ06 default is ALLOW (the
        # footgun, stated explicitly).
        self.assertIn("implicit default: ALLOW", out)
        rc, out, _ = run_cli(["--list-rules", "--conf", cfg, "--json"])
        data = json.loads(out)
        self.assertIn("implicit default", data["implicit_default"])

    def test_list_rules_no_rules_states_deny_default(self):
        cfg = self.conf("acl local src 10.0.0.0/8\n")
        rc, out, _ = run_cli(["--list-rules", "--conf", cfg])
        self.assertEqual(rc, 1)
        self.assertIn("implicit default: DENY", out)

    def test_json_fidelity_vs_text(self):
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_access deny all\n")
        rc_t, out_t, _ = self.query(cfg)
        rc_j, data, _ = self.query_json(cfg)
        self.assertEqual(rc_t, rc_j)
        self.assertIn("ALLOW", out_t.splitlines()[0])
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertEqual(data["decider"]["where"], cfg + ":2")

    def test_exit_codes_matrix(self):
        cfg = self.conf("http_access allow all\n")
        rc, _, _ = self.query(cfg)
        self.assertEqual(rc, 0)
        cfg2 = self.conf("http_access deny all\n")
        rc, _, _ = self.query(cfg2)
        self.assertEqual(rc, 1)
        rc, _, _ = run_cli(["--src", "10.0.0.1"])
        self.assertEqual(rc, 2)     # --dst missing
        rc, _, _ = run_cli(["--src", "10.0.0.1", "--dst", "example.com",
                            "--conf", "/nonexistent/squid.conf"])
        self.assertEqual(rc, 2)
        rc, _, _ = run_cli(["--src", "not-an-ip", "--dst",
                            "example.com", "--conf", cfg])
        self.assertEqual(rc, 2)
        rc, _, _ = run_cli(["--src", "10.0.0.1", "--dst",
                            "example.com", "--conf", cfg,
                            "--port", "99999"])
        self.assertEqual(rc, 2)

    def test_quiet_and_version(self):
        cfg = self.conf("http_access allow all\n")
        rc, out, _ = run_cli(["--src", "10.0.0.1", "--dst",
                              "example.com", "--conf", cfg, "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "ALLOW")
        rc, out, _ = run_cli(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("squidwho", out)

    def test_default_conf_missing_is_exit_2(self):
        if os.path.exists("/etc/squid/squid.conf"):
            self.skipTest("/etc/squid/squid.conf exists here")
        rc, _, err = run_cli(["--src", "10.0.0.1", "--dst",
                              "example.com"])
        self.assertEqual(rc, 2)
        self.assertIn("/etc/squid/squid.conf", err)


# ------------------------------------------------------------------- BG9

class BG9Safety(TmpTree):
    def test_never_executes_payloads(self):
        marker = os.path.join(self.tmp, "marker")
        marker2 = os.path.join(self.tmp, "marker2")
        cfg = self.conf(
            "# $(touch %s)\n"
            "acl u url_regex `touch %s`\n"
            "external_acl_type helper children-max=1 %%LOGIN "
            "/bin/touch %s\n"
            "http_access allow all\n" % (marker, marker, marker2))
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertFalse(os.path.exists(marker))
        self.assertFalse(os.path.exists(marker2))

    def test_no_subprocess_socket_dns_or_environ_in_source(self):
        with open(TOOL) as fh:
            src = fh.read()
        for banned in ("import subprocess", "import socket",
                       "os.system", "os.popen", "eval(",
                       "exec(", "__import__", "pty.",
                       "getaddrinfo", "gethostbyname", "os.environ",
                       "os.getenv", "socket."):
            self.assertNotIn(banned, src, "source contains %r" % banned)

    def test_no_writes_and_no_network(self):
        # The tool opens the config read-only and writes nothing:
        # the tree is byte-identical after a run.
        cfg = self.conf(
            "acl local src 10.0.0.0/8\n"
            "http_access allow local\n"
            "http_access deny all\n")
        before = sorted(os.listdir(self.tmp))
        mtime = os.path.getmtime(cfg)
        rc, data, _ = self.query_json(cfg)
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(os.listdir(self.tmp)), before)
        self.assertEqual(os.path.getmtime(cfg), mtime)

    def test_config_is_not_modified_by_query(self):
        cfg = self.conf("http_access allow all\n")
        with open(cfg) as fh:
            before = fh.read()
        self.query(cfg)
        with open(cfg) as fh:
            after = fh.read()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
