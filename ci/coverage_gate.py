"""Enforce PLAN.md section 14.3 line coverage thresholds.

cargo-llvm-cov can only fail on the total, so this reads its JSON summary
and checks each group:

    cargo llvm-cov report --json --summary-only --output-path cov.json \\
        --ignore-filename-regex '...'
    python3 ci/coverage_gate.py cov.json

Exits non-zero if any threshold is missed. Writes a Markdown table to
$GITHUB_STEP_SUMMARY when set. Standard library only.
"""

import json
import os
import sys

# (group, path prefix relative to the repo root, minimum line coverage %)
# The "crate" group is every file in the report (already filtered by the
# --ignore-filename-regex that excludes card/pcsc.rs, main.rs, and tests/).
RULES = [
    ("oath::*", "src/oath/", 95.0),
    ("session", "src/session.rs", 95.0),
    ("ratelimit", "src/ratelimit.rs", 95.0),
    ("crate", "", 85.0),
]


def _relative(filename, root):
    root = root.rstrip("/") + "/"
    return filename[len(root):] if filename.startswith(root) else filename


def group_lines(doc, root):
    """Return {group: (covered, count)} for every rule."""
    files = doc["data"][0]["files"]
    groups = {}
    for name, prefix, _ in RULES:
        covered = count = 0
        for entry in files:
            if _relative(entry["filename"], root).startswith(prefix):
                lines = entry["summary"]["lines"]
                covered += lines["covered"]
                count += lines["count"]
        groups[name] = (covered, count)
    return groups


def check(doc, root):
    """Return (failure messages, rows of (group, percent, minimum, passed))."""
    groups = group_lines(doc, root)
    failures, rows = [], []
    for name, _, minimum in RULES:
        covered, count = groups[name]
        if count == 0:
            failures.append(f"{name}: no lines found; is the path rule still right?")
            rows.append((name, 0.0, minimum, False))
            continue
        percent = 100.0 * covered / count
        passed = percent >= minimum
        if not passed:
            failures.append(f"{name}: {percent:.2f}% of lines covered, needs {minimum:g}%")
        rows.append((name, percent, minimum, passed))
    return failures, rows


def markdown(rows):
    lines = ["| Group | Lines | Minimum | Result |", "|---|---|---|---|"]
    for name, percent, minimum, passed in rows:
        lines.append(f"| {name} | {percent:.2f}% | {minimum:g}% | {'pass' if passed else 'FAIL'} |")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <llvm-cov summary json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        doc = json.load(f)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    failures, rows = check(doc, root)
    table = markdown(rows)
    print(table)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("## Coverage\n\n" + table)
    for failure in failures:
        print(f"coverage gate: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
