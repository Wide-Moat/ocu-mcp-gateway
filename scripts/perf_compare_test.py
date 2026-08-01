# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Tests for perf_compare.py, the k6 perf-regression comparer. Stdlib unittest
# only (no pytest), matching the other script-adjacent tests in this repo.
#
# The comparer's contract (Fable ruling, wave-2 perf increment 1):
#   - each side (base, head) is one-or-more k6 --summary-export JSONs;
#     the per-side statistic is the MIN of each round's http_req_duration p95
#     (min-of-rounds squeezes out warm-up and scheduler jitter so the regression
#     signal is the floor, not a noisy tail).
#   - REGRESSION (exit 1) iff head_p95 > base_p95 * 1.10 AND
#     (head_p95 - base_p95) > 2ms. BOTH must hold: a large relative jump on a
#     sub-ms floor (noise) is not a regression, and a 2ms absolute jump that is
#     under 10% relative (a slow baseline) is not a regression either.
#   - a malformed or missing summary (no metrics, no http_req_duration, no p95
#     key, non-numeric p95, unreadable/absent file) is a BROKEN RIG: exit 2,
#     distinct from a clean pass (0) and a real regression (1), so CI can tell a
#     harness fault from a genuine red.

import json
import os
import tempfile
import unittest

import perf_compare


def _summary(p95):
    """A minimal k6 --summary-export object carrying one http_req_duration p95."""
    return {"metrics": {"http_req_duration": {"p(95)": p95}}}


class PerfCompareTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="perfcmp-")
        self._n = 0

    def _write(self, obj):
        """Write obj as JSON to a fresh temp file and return its path. A raw
        string is written verbatim (to exercise the malformed-JSON path)."""
        self._n += 1
        path = os.path.join(self._dir, f"s{self._n}.json")
        with open(path, "w", encoding="utf-8") as f:
            if isinstance(obj, str):
                f.write(obj)
            else:
                json.dump(obj, f)
        return path

    def _run(self, base_p95s, head_p95s):
        """Run the comparer over the given base and head p95 lists (each entry a
        round's http_req_duration p95, in ms) and return the exit code."""
        base = [self._write(_summary(p)) for p in base_p95s]
        head = [self._write(_summary(p)) for p in head_p95s]
        return perf_compare.compare(base, head)

    # --- the four TDD cases named in the ruling ---

    def test_regression_12pct_and_5ms_exit1(self):
        # head 56ms vs base 50ms: +12% (>10%) AND +6ms (>2ms) -> regression.
        self.assertEqual(self._run([50.0], [56.0]), 1)

    def test_within_8pct_exit0(self):
        # head 54ms vs base 50ms: +8% (<=10%) -> not a regression, even though
        # the absolute delta (4ms) clears the 2ms floor. Relative gate not met.
        self.assertEqual(self._run([50.0], [54.0]), 0)

    def test_12pct_but_sub_ms_exit0(self):
        # head 2.8ms vs base 2.5ms: +12% (>10%) BUT +0.3ms (<=2ms) -> not a
        # regression. Absolute floor not met: a big relative jump on a tiny floor
        # is noise, not a regression.
        self.assertEqual(self._run([2.5], [2.8]), 0)

    def test_missing_p95_key_exit2(self):
        # A summary object with no p(95) key is a broken rig -> exit 2.
        base = [self._write({"metrics": {"http_req_duration": {"avg": 10.0}}})]
        head = [self._write(_summary(50.0))]
        self.assertEqual(perf_compare.compare(base, head), 2)

    # --- min-of-rounds and boundary cases ---

    def test_min_of_rounds_picks_the_floor(self):
        # base min = 50 (of 50, 80); head min = 56 (of 56, 90). +12%/+6ms -> 1.
        self.assertEqual(self._run([80.0, 50.0], [90.0, 56.0]), 1)

    def test_min_of_rounds_head_floor_beats_noisy_tail(self):
        # head has a noisy 60ms round but its floor is 51ms; base floor 50ms:
        # +2% / +1ms -> not a regression. The noisy tail must not trip the gate.
        self.assertEqual(self._run([50.0], [51.0, 60.0]), 0)

    def test_equalish_exit0(self):
        # Identical floors -> 0% / 0ms -> pass.
        self.assertEqual(self._run([50.0], [50.0]), 0)

    def test_exactly_10pct_and_over_2ms_exit0(self):
        # head 55ms vs base 50ms: exactly +10% (NOT strictly > 10%) -> pass.
        # The relative gate is a strict '>', so the boundary is a pass.
        self.assertEqual(self._run([50.0], [55.0]), 0)

    def test_over_10pct_exactly_2ms_delta_exit0(self):
        # base 19ms, head 21ms: +10.5% (>10%) but delta exactly 2ms (NOT > 2ms)
        # -> pass. The absolute gate is a strict '>', so 2.0ms is a pass.
        self.assertEqual(self._run([19.0], [21.0]), 0)

    def test_over_10pct_and_over_2ms_exit1(self):
        # base 19ms, head 21.5ms: +13.2% (>10%) AND +2.5ms (>2ms) -> regression.
        self.assertEqual(self._run([19.0], [21.5]), 1)

    # --- broken-rig variants all exit 2, never a false pass/fail ---

    def test_absent_file_exit2(self):
        head = [self._write(_summary(50.0))]
        missing = os.path.join(self._dir, "does-not-exist.json")
        self.assertEqual(perf_compare.compare([missing], head), 2)

    def test_malformed_json_exit2(self):
        base = [self._write("{not valid json")]
        head = [self._write(_summary(50.0))]
        self.assertEqual(perf_compare.compare(base, head), 2)

    def test_no_metrics_key_exit2(self):
        base = [self._write({"root_group": {}})]
        head = [self._write(_summary(50.0))]
        self.assertEqual(perf_compare.compare(base, head), 2)

    def test_no_http_req_duration_exit2(self):
        base = [self._write({"metrics": {"iterations": {"count": 3}}})]
        head = [self._write(_summary(50.0))]
        self.assertEqual(perf_compare.compare(base, head), 2)

    def test_non_numeric_p95_exit2(self):
        base = [self._write({"metrics": {"http_req_duration": {"p(95)": "fast"}}})]
        head = [self._write(_summary(50.0))]
        self.assertEqual(perf_compare.compare(base, head), 2)

    def test_empty_side_exit2(self):
        # A side with zero summaries is a broken rig (nothing to compare).
        head = [self._write(_summary(50.0))]
        self.assertEqual(perf_compare.compare([], head), 2)

    def test_head_faster_exit0(self):
        # head 40ms vs base 50ms: an improvement -> pass.
        self.assertEqual(self._run([50.0], [40.0]), 0)


if __name__ == "__main__":
    unittest.main()
