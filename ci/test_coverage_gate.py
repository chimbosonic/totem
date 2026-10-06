"""Tests for coverage_gate.py. Run with: python3 -m unittest discover ci"""

import unittest

import coverage_gate as gate


def summary(files, total=None):
    """Build a minimal `cargo llvm-cov --json --summary-only` document."""
    entries = [
        {"filename": name, "summary": {"lines": {"count": count, "covered": covered}}}
        for name, (covered, count) in files.items()
    ]
    if total is None:
        total = (
            sum(c for c, _ in files.values()),
            sum(n for _, n in files.values()),
        )
    covered, count = total
    return {"data": [{"files": entries, "totals": {"lines": {"count": count, "covered": covered}}}]}


ROOT = "/repo"


class GroupTests(unittest.TestCase):
    def test_files_are_grouped_by_rule(self):
        doc = summary(
            {
                "/repo/src/oath/tlv.rs": (99, 100),
                "/repo/src/oath/crypto.rs": (95, 100),
                "/repo/src/session.rs": (50, 50),
                "/repo/src/ratelimit.rs": (19, 20),
                "/repo/src/api/server.rs": (80, 100),
            }
        )
        groups = gate.group_lines(doc, ROOT)
        self.assertEqual(groups["oath::*"], (194, 200))
        self.assertEqual(groups["session"], (50, 50))
        self.assertEqual(groups["ratelimit"], (19, 20))
        self.assertEqual(groups["crate"], (343, 370))

    def test_missing_group_files_are_reported_as_zero_lines(self):
        groups = gate.group_lines(summary({"/repo/src/api/server.rs": (1, 1)}), ROOT)
        self.assertEqual(groups["session"], (0, 0))


class CheckTests(unittest.TestCase):
    def test_passes_when_every_threshold_is_met(self):
        doc = summary(
            {
                "/repo/src/oath/tlv.rs": (95, 100),
                "/repo/src/session.rs": (95, 100),
                "/repo/src/ratelimit.rs": (100, 100),
                "/repo/src/api/server.rs": (55, 100),
            }
        )
        failures, rows = gate.check(doc, ROOT)
        self.assertEqual(failures, [])
        self.assertEqual([r[0] for r in rows], ["oath::*", "session", "ratelimit", "crate"])

    def test_fails_a_module_below_95(self):
        doc = summary(
            {
                "/repo/src/oath/tlv.rs": (94, 100),
                "/repo/src/session.rs": (100, 100),
                "/repo/src/ratelimit.rs": (100, 100),
            }
        )
        failures, _ = gate.check(doc, ROOT)
        self.assertEqual(len(failures), 1)
        self.assertIn("oath::*", failures[0])
        self.assertIn("94.00%", failures[0])

    def test_fails_the_crate_below_85(self):
        doc = summary(
            {
                "/repo/src/oath/tlv.rs": (100, 100),
                "/repo/src/session.rs": (100, 100),
                "/repo/src/ratelimit.rs": (100, 100),
                "/repo/src/api/server.rs": (0, 100),
            }
        )
        failures, _ = gate.check(doc, ROOT)
        self.assertEqual(len(failures), 1)
        self.assertIn("crate", failures[0])

    def test_a_group_with_no_lines_fails(self):
        doc = summary({"/repo/src/api/server.rs": (100, 100)})
        failures, _ = gate.check(doc, ROOT)
        self.assertTrue(any("session" in f and "no lines" in f for f in failures))


class MarkdownTests(unittest.TestCase):
    def test_table_lists_each_group_with_status(self):
        rows = [("oath::*", 99.5, 95.0, True), ("crate", 80.0, 85.0, False)]
        table = gate.markdown(rows)
        self.assertIn("| oath::* | 99.50% | 95% | pass |", table)
        self.assertIn("| crate | 80.00% | 85% | FAIL |", table)


if __name__ == "__main__":
    unittest.main()
