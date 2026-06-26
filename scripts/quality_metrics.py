#!/usr/bin/env python3
"""Measure local code-quality metrics for the check_msdefender package.

Computes a snapshot of the trackable quality criteria: size/structure
stats (via AST), cyclomatic complexity (ruff C901), lint debt (default
ruff rule set), pyright / vulture / refurb findings, docstring coverage
(interrogate) and test coverage (read from the last ``coverage`` run, if
any).

Usage:
    .venv/bin/python scripts/quality_metrics.py [--json] [--record] [--gate]

--record appends a CSV row to doc/quality-history.csv so the evolution
of each criterion stays visible over time.

--gate evaluates the blocking quality gate: absolute ceilings/floors plus
a best-ever ratchet against quality-history.csv (no tracked criterion may
regress past its best recorded value). Exits non-zero on any violation;
wired into ``pdm run check`` and publish.sh.

Aligned on the lduchosal quality standard established in the kenboard
project (gate bloquant + cliquet best-ever).
"""

import argparse
import ast
import csv
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "check_msdefender"
HISTORY = REPO / "doc" / "quality-history.csv"
VENV_BIN = Path(sys.executable).parent

# Lint debt: count of findings under the default ruff rule set that are not
# yet clean. Ratcheted down over time — never allowed to climb back.
DEBT_SELECT = "ALL"

LONG_FUNC_LINES = 50
BIG_FILE_LINES = 500

# --- Blocking gate ------------------------------------------------------
# Seuils initiaux calés sur l'état mesuré au moment de l'introduction du
# gate (palier 1) : le gate doit être VERT dès le premier run. Procédure
# lduchosal : dès que le gate est vert, enregistrer un snapshot puis
# resserrer au palier suivant — un gate vert n'est jamais un état stable.
# On ne détend JAMAIS un seuil sans décision humaine explicite.
# Palier 1 calé sur l'état mesuré 2026-06-25 (v1.3.0) : max_func_lines=212,
# c901_over_10=2, test_cov=62.25, min_file_cov=0 (integration.py = stub
# d'entrée non couvert). Le gate est VERT à ce palier ; on resserre ensuite.
GATE_PALIER = 1
GATE_MAX = {
    "max_file_lines": 500,
    "max_func_lines": 212,
    "c901_over_10": 2,
    "vulture": 0,
    "refurb": 0,
    "pyright_errors": 0,
}
GATE_MIN = {
    "docstring_cov": 95.0,
    "test_cov": 60.0,
    "min_file_cov": 0.0,
}
# Best-ever ratchet: counts may never exceed their lowest recorded value,
# coverage may not drop more than RATCHET_COV_SLACK below its highest.
RATCHET_DOWN = ("files_over_500", "funcs_over_50", "c901_over_10", "ruff_debt")
RATCHET_UP = ("test_cov",)
RATCHET_COV_SLACK = 0.5


def _run(tool: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run a venv tool from the repo root and capture its output."""
    return subprocess.run(
        [str(VENV_BIN / tool), *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )


def _ast_stats() -> dict[str, int]:
    """Walk check_msdefender and compute size/structure metrics via AST."""
    files = sorted(SRC.rglob("*.py"))
    loc = 0
    max_file = 0
    big_files = 0
    func_lengths: list[int] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        lines = text.count("\n") + (0 if text.endswith("\n") else 1)
        loc += lines
        max_file = max(max_file, lines)
        if lines > BIG_FILE_LINES:
            big_files += 1
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_lengths.append((node.end_lineno or node.lineno) - node.lineno + 1)
    return {
        "py_files": len(files),
        "loc_src": loc,
        "max_file_lines": max_file,
        "files_over_500": big_files,
        "functions": len(func_lengths),
        "max_func_lines": max(func_lengths) if func_lengths else 0,
        "funcs_over_50": sum(1 for length in func_lengths if length > LONG_FUNC_LINES),
    }


def _ruff_count(select: str) -> int:
    """Count ruff findings in the package for the given rule selection."""
    proc = _run(
        "ruff",
        "check",
        "check_msdefender",
        "--select",
        select,
        "--output-format",
        "json",
    )
    return len(json.loads(proc.stdout or "[]"))


def _ruff_debt() -> int:
    """Count findings under the default ruff configuration (lint debt)."""
    proc = _run("ruff", "check", "check_msdefender", "--output-format", "json")
    return len(json.loads(proc.stdout or "[]"))


def _pyright_errors() -> int:
    """Count pyright type errors in the package."""
    proc = _run("pyright", "check_msdefender", "--outputjson")
    try:
        data = json.loads(proc.stdout)
        return int(data["summary"]["errorCount"])
    except (ValueError, KeyError):
        match = re.search(r"(\d+) error", proc.stdout + proc.stderr)
        return int(match.group(1)) if match else 0


def _vulture_findings() -> int:
    """Count vulture dead-code findings at the configured confidence level."""
    proc = _run("vulture", "check_msdefender", "tests")
    return len([line for line in proc.stdout.splitlines() if ": " in line])


def _refurb_findings() -> int:
    """Count refurb findings in the package."""
    proc = _run("refurb", "check_msdefender")
    return len([line for line in proc.stdout.splitlines() if "[FURB" in line])


def _docstring_coverage() -> float:
    """Read the interrogate docstring-coverage percentage for the package."""
    proc = _run("interrogate", "check_msdefender", "-c", "pyproject.toml", "--no-color")
    match = re.search(r"actual: ([\d.]+)%", proc.stdout + proc.stderr)
    return float(match.group(1)) if match else 0.0


def _test_coverage() -> float | None:
    """Read total test coverage from the last coverage run, if available."""
    if not (REPO / ".coverage").exists():
        return None
    proc = _run("coverage", "report", "--format=total", "--precision=2")
    try:
        return float(proc.stdout.strip())
    except ValueError:
        return None


def _offending_files(limit: int) -> list[str]:
    """List package files longer than limit lines, biggest first."""
    rows: list[tuple[int, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        lines = text.count("\n") + (0 if text.endswith("\n") else 1)
        if lines > limit:
            rows.append((lines, str(path.relative_to(REPO))))
    return [f"{lines} lignes  {path}" for lines, path in sorted(rows, reverse=True)]


def _offending_functions(limit: int) -> list[str]:
    """List package functions longer than limit lines, longest first."""
    rows: list[tuple[int, str, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = (node.end_lineno or node.lineno) - node.lineno + 1
                if length > limit:
                    location = f"{path.relative_to(REPO)}:{node.lineno}"
                    rows.append((length, node.name, location))
    return [
        f"{length} lignes  {name}  {location}"
        for length, name, location in sorted(rows, reverse=True)
    ]


def _ruff_findings(select: str) -> list[str]:
    """Per-finding concise ruff output for the given selection."""
    proc = _run(
        "ruff",
        "check",
        "check_msdefender",
        "--select",
        select,
        "--output-format",
        "concise",
    )
    return [line for line in proc.stdout.splitlines() if ".py:" in line]


def _undercovered_files(floor: float) -> list[str]:
    """List files whose coverage sits below the given floor."""
    proc = _run("coverage", "json", "-o", "-")
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return []
    return [
        f"{summary['summary']['percent_covered']:.1f} %  {name}"
        for name, summary in sorted(data["files"].items())
        if summary["summary"]["percent_covered"] < floor
    ]


def gate_details(key: str) -> list[str]:
    """Actionable offender list for a violated gate rule.

    This is what tells an agent *what* to fix, not just that the gate is
    red; computed lazily, only for the rules that actually failed.
    """
    if key == "max_file_lines":
        return _offending_files(GATE_MAX["max_file_lines"])
    if key == "files_over_500":
        return _offending_files(BIG_FILE_LINES)
    if key == "max_func_lines":
        return _offending_functions(GATE_MAX["max_func_lines"])
    if key == "funcs_over_50":
        return _offending_functions(LONG_FUNC_LINES)
    if key == "c901_over_10":
        return _ruff_findings("C901")
    if key == "ruff_debt":
        return ["détail : pdm run lint"]
    if key == "min_file_cov":
        return _undercovered_files(GATE_MIN["min_file_cov"])
    if key == "test_cov":
        return ["détail : .venv/bin/coverage report --sort=cover"]
    if key == "pyright_errors":
        return ["détail : pdm run typecheck"]
    if key == "vulture":
        return ["détail : pdm run vulture"]
    if key == "refurb":
        return ["détail : pdm run refurb"]
    if key == "docstring_cov":
        return ["détail : pdm run interrogate -- -vv"]
    return []


def _min_file_coverage() -> float | None:
    """Read the lowest per-file coverage from the last run.

    Catches the classic drift of a new module landing without tests: the
    total barely moves but the per-file minimum collapses.
    """
    if not (REPO / ".coverage").exists():
        return None
    proc = _run("coverage", "json", "-o", "-")
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return None
    percents = [f["summary"]["percent_covered"] for f in data["files"].values()]
    return round(min(percents), 2) if percents else None


def _history_best(path: Path = HISTORY) -> dict[str, float]:
    """Best-ever value per ratcheted metric across the recorded history."""
    best: dict[str, float] = {}
    if not path.exists():
        return best
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            for key in RATCHET_DOWN + RATCHET_UP:
                raw = (row.get(key) or "").strip()
                if not raw:
                    continue
                value = float(raw)
                if key in RATCHET_DOWN:
                    best[key] = min(best.get(key, value), value)
                else:
                    best[key] = max(best.get(key, value), value)
    return best


def evaluate_gate(
    metrics: dict[str, object], best: dict[str, float]
) -> tuple[list[str], list[str]]:
    """Evaluate the blocking gate; return (failures, skipped-rule names).

    Rules whose metric is unavailable (no coverage data) are skipped, not
    failed — publish.sh runs the gate right after the coverage test run so
    coverage is fresh in CI.
    """
    failures: list[str] = []
    skipped: list[str] = []
    for key, ceiling in GATE_MAX.items():
        value = metrics.get(key)
        if value is None:
            skipped.append(key)
        elif float(str(value)) > ceiling:
            failures.append(f"{key} = {value} > plafond absolu {ceiling}")
    for key, floor in GATE_MIN.items():
        value = metrics.get(key)
        if value is None:
            skipped.append(key)
        elif float(str(value)) < floor:
            failures.append(f"{key} = {value} < plancher absolu {floor}")
    for key in RATCHET_DOWN:
        value, limit = metrics.get(key), best.get(key)
        if value is None or limit is None:
            continue
        if float(str(value)) > limit:
            failures.append(
                f"{key} = {value} > meilleur historique {limit:g} (ratchet)"
            )
    for key in RATCHET_UP:
        value, limit = metrics.get(key), best.get(key)
        if value is None or limit is None:
            continue
        if float(str(value)) < limit - RATCHET_COV_SLACK:
            failures.append(
                f"{key} = {value} < meilleur historique {limit:g} "
                f"- tolérance {RATCHET_COV_SLACK} (ratchet)"
            )
    return failures, skipped


def _version() -> str:
    """Read the package version from check_msdefender/__init__.py."""
    text = (SRC / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    return match.group(1) if match else "?"


def collect() -> dict[str, object]:
    """Collect the full metrics snapshot."""
    metrics: dict[str, object] = {
        "date": datetime.date.today().isoformat(),
        "version": _version(),
    }
    metrics.update(_ast_stats())
    metrics["c901_over_10"] = _ruff_count("C901")
    metrics["ruff_debt"] = _ruff_debt()
    metrics["pyright_errors"] = _pyright_errors()
    metrics["vulture"] = _vulture_findings()
    metrics["refurb"] = _refurb_findings()
    metrics["docstring_cov"] = _docstring_coverage()
    metrics["test_cov"] = _test_coverage()
    metrics["min_file_cov"] = _min_file_coverage()
    return metrics


def record(metrics: dict[str, object]) -> None:
    """Append the snapshot to doc/quality-history.csv.

    Rewrites the file when the snapshot carries new columns so the header
    stays the union of all known criteria; historical rows keep blanks for
    the new ones.
    """
    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(metrics)
    rows: list[dict[str, str]] = []
    if HISTORY.exists():
        with HISTORY.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            existing = list(reader.fieldnames or [])
            rows = list(reader)
        fieldnames = existing + [key for key in fieldnames if key not in existing]
    with HISTORY.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, restval="")
        writer.writeheader()
        writer.writerows(rows)
        writer.writerow(metrics)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument(
        "--record", action="store_true", help="append to doc/quality-history.csv"
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="enforce the blocking quality gate, exit 1 on violation",
    )
    args = parser.parse_args()

    metrics = collect()
    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        width = max(len(key) for key in metrics)
        for key, value in metrics.items():
            shown = "n/a (run pdm run test-cov first)" if value is None else value
            print(f"{key:<{width}}  {shown}")
    if args.record:
        record(metrics)
        print(f"\nrecorded -> {HISTORY.relative_to(REPO)}")
    if args.gate:
        failures, skipped = evaluate_gate(metrics, _history_best())
        print()
        if skipped:
            print(f"gate: règles sautées faute de données : {', '.join(skipped)}")
        if failures:
            print(f"gate (palier {GATE_PALIER}): FAIL")
            for failure in failures:
                print(f"  ✗ {failure}")
                for line in gate_details(failure.split(" = ")[0]):
                    print(f"        {line}")
            return 1
        print(
            f"gate (palier {GATE_PALIER}): PASS — enregistrer un snapshot et "
            "resserrer au palier suivant (doc/code-quality.md § Gate bloquant)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
