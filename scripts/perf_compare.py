#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# perf_compare.py - the k6 perf-regression comparer for the gateway-LOCAL /mcp
# handshake (wave-2 perf increment 1). It reads k6 --summary-export JSONs for a
# BASE side (merge-base binary) and a HEAD side (PR binary), each side being one
# or more rounds, and decides whether HEAD regressed against BASE.
#
# stdlib only (no pip), matching mint_boot_set.py / vendored_check.py in this
# directory. It is the SINGLE source of the regression predicate: perf_gate.sh
# and the CI job both call compare(); neither re-implements the thresholds.
#
# The per-side statistic is the MIN of each round's http_req_duration p95.
# min-of-rounds is deliberate: an ABAB run interleaves base/head so both sides
# see the same scheduler weather, and taking the floor across rounds squeezes out
# warm-up and one-off jitter so the comparison is floor-vs-floor, not tail-vs-tail.
#
# Verdict (exit code):
#   0  no regression: head is within budget.
#   1  regression: head_p95 > base_p95 * 1.10 AND (head_p95 - base_p95) > 2ms.
#      BOTH gates must hold. A large relative jump on a sub-ms floor is noise; a
#      >2ms absolute jump that stays under 10% relative is a slow baseline, not a
#      new regression. Requiring both keeps the gate from firing on either alone.
#   2  broken rig: a summary is missing, unreadable, malformed, carries no
#      http_req_duration p95, or a non-numeric p95. This is an ERROR distinct from
#      a clean pass and a real regression, so CI can tell a harness fault (fix the
#      rig) from a genuine red (fix the code).
#
# Usage:
#   perf_compare.py --base b1.json [b2.json ...] --head h1.json [h2.json ...]

import argparse
import json
import sys

# The regression thresholds. Both must be exceeded (strict >) for a regression.
REL_THRESHOLD = 1.10  # head p95 must exceed base p95 by more than 10%
ABS_THRESHOLD_MS = 2.0  # AND the absolute delta must exceed 2ms

# Exit codes (also the compare() return value).
EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_BROKEN_RIG = 2


class BrokenRig(Exception):
    """A summary could not be read as a valid k6 export with a numeric
    http_req_duration p95. Raised so compare() maps it to EXIT_BROKEN_RIG rather
    than a spurious pass/fail."""


def _p95_from_summary(path):
    """Read one k6 --summary-export JSON and return its http_req_duration p(95)
    as a float (milliseconds, k6's native unit). Any structural miss - absent
    file, unparseable JSON, missing metrics/http_req_duration/p(95), or a
    non-numeric p95 - is a BrokenRig, never a silent default."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError as exc:
        raise BrokenRig(f"summary not found: {path}") from exc
    except (OSError, ValueError) as exc:
        # ValueError covers json.JSONDecodeError (malformed body).
        raise BrokenRig(f"summary unreadable/malformed: {path}: {exc}") from exc

    if not isinstance(doc, dict):
        raise BrokenRig(f"summary is not a JSON object: {path}")
    metrics = doc.get("metrics")
    if not isinstance(metrics, dict):
        raise BrokenRig(f"summary has no metrics object: {path}")
    hrd = metrics.get("http_req_duration")
    if not isinstance(hrd, dict):
        raise BrokenRig(f"summary has no http_req_duration metric: {path}")
    if "p(95)" not in hrd:
        raise BrokenRig(f"summary http_req_duration has no p(95): {path}")
    p95 = hrd["p(95)"]
    # bool is a subclass of int - reject it so a True/False never reads as 1.0/0.
    if isinstance(p95, bool) or not isinstance(p95, (int, float)):
        raise BrokenRig(f"summary p(95) is not numeric: {path}: {p95!r}")
    return float(p95)


def _side_p95(paths):
    """The per-side statistic: the MIN of each round's http_req_duration p95. An
    empty side (no summaries) is a broken rig - there is nothing to compare."""
    if not paths:
        raise BrokenRig("side has no summaries")
    return min(_p95_from_summary(p) for p in paths)


def compare(base_paths, head_paths):
    """Compare the head side against the base side and return the exit code
    (EXIT_OK / EXIT_REGRESSION / EXIT_BROKEN_RIG). Pure function over file paths
    so the unit tests drive it directly; the CLI wrapper only marshals argv and
    prints a human line."""
    try:
        base_p95 = _side_p95(base_paths)
        head_p95 = _side_p95(head_paths)
    except BrokenRig as exc:
        print(f"perf_compare: BROKEN RIG (exit 2): {exc}", file=sys.stderr)
        return EXIT_BROKEN_RIG

    delta = head_p95 - base_p95
    rel = head_p95 / base_p95 if base_p95 > 0 else float("inf")
    over_rel = head_p95 > base_p95 * REL_THRESHOLD
    over_abs = delta > ABS_THRESHOLD_MS
    regressed = over_rel and over_abs

    verdict = "REGRESSION" if regressed else "OK"
    print(
        f"perf_compare: base p95={base_p95:.3f}ms head p95={head_p95:.3f}ms "
        f"delta={delta:+.3f}ms ratio={rel:.4f} "
        f"(rel>1.10: {over_rel}, abs>2ms: {over_abs}) -> {verdict}"
    )
    return EXIT_REGRESSION if regressed else EXIT_OK


def main(argv):
    ap = argparse.ArgumentParser(
        description="Compare k6 head vs base http_req_duration p95 summaries."
    )
    ap.add_argument(
        "--base",
        nargs="+",
        required=True,
        help="one or more base-side k6 --summary-export JSONs (min-of-rounds p95)",
    )
    ap.add_argument(
        "--head",
        nargs="+",
        required=True,
        help="one or more head-side k6 --summary-export JSONs (min-of-rounds p95)",
    )
    args = ap.parse_args(argv)
    return compare(args.base, args.head)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
