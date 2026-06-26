#!/usr/bin/env python3
# pyright: basic
# Tooling script (hors périmètre du gate `pyright check_msdefender/`) :
# le typage strict des réponses JSON dynamiques de l'API Sonarcloud serait
# disproportionné. Mode basic = vrais bugs signalés, bruit "unknown" tu.
"""Check the Sonarcloud quality gate for the latest analysis.

Polls the Sonarcloud API until the analysis for the current commit is
available, then checks the quality gate status. Exits 0 if the gate
passes, 1 if it fails (with issue details printed to stderr).

Usage:
    python scripts/sonar_gate.py [--timeout 300] [--interval 15]

Requires SONAR_TOKEN in the environment (or .env file).
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request

PROJECT_KEY = "lduchosal_check_msdefender"
MAIN_BRANCH = "master"
SONAR_BASE = "https://sonarcloud.io/api"


def _ssl_context() -> ssl.SSLContext | None:
    """Build an SSL context using certifi's CA bundle if available."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return None


_SSL_CTX = _ssl_context()


def _get_token() -> str:
    """Resolve the Sonar token from env or .env file."""
    token = os.environ.get("SONAR_TOKEN", "")
    if token:
        return token
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.isfile(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("SONAR_TOKEN="):
                    return line.split("=", 1)[1].strip()
    return ""


def _api(path: str, token: str, params: dict | None = None) -> dict:
    """Call the Sonarcloud API and return parsed JSON."""
    url = f"{SONAR_BASE}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, context=_SSL_CTX) as resp:
        return json.loads(resp.read())


def _current_commit() -> str:
    """Return the current git HEAD commit SHA."""
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def _wait_for_analysis(
    token: str, commit: str, timeout: int, interval: int
) -> str | None:
    """Poll until the analysis for the given commit is available.

    Returns the analysis key or None on timeout.
    """
    deadline = time.time() + timeout
    print(f"Waiting for Sonarcloud analysis of commit {commit[:8]}...")
    while time.time() < deadline:
        try:
            data = _api(
                "/project_analyses/search",
                token,
                {"project": PROJECT_KEY, "ps": "5"},
            )
            for analysis in data.get("analyses", []):
                revision = analysis.get("revision", "")
                if revision == commit:
                    print(f"  Analysis found: {analysis['key']}")
                    return analysis["key"]
        except Exception as e:
            print(f"  API error: {e}", file=sys.stderr)
        remaining = int(deadline - time.time())
        print(f"  Not ready yet, retrying in {interval}s ({remaining}s remaining)...")
        time.sleep(interval)
    return None


def _check_gate(token: str, analysis_key: str) -> tuple[bool, list[dict]]:
    """Check the LIVE quality gate status of the main branch.

    ``analysis_key`` n'est plus passé à l'API : le statut figé par analysisId
    ignore le triage d'issues postérieur à l'analyse (faux positif marqué dans
    l'UI → la branche repasse OK mais l'analyse resterait FAILED à jamais).
    L'appelant a déjà attendu l'analyse du commit courant, ce qui garantit que
    le statut live couvre bien ce code. Returns (passed, conditions).
    """
    del analysis_key  # fraîcheur déjà garantie par _wait_for_analysis
    data = _api(
        "/qualitygates/project_status",
        token,
        {"projectKey": PROJECT_KEY, "branch": MAIN_BRANCH},
    )
    status = data.get("projectStatus", {})
    passed = status.get("status") == "OK"
    conditions = status.get("conditions", [])
    return passed, conditions


def _fetch_issues(token: str) -> list[dict]:
    """Fetch open issues for the project."""
    data = _api(
        "/issues/search",
        token,
        {"componentKeys": PROJECT_KEY, "resolved": "false", "ps": "50"},
    )
    return data.get("issues", [])


def main() -> None:
    """Run the Sonarcloud quality gate check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Max seconds to wait for analysis (default 300)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=15,
        help="Poll interval in seconds (default 15)",
    )
    args = parser.parse_args()

    token = _get_token()
    if not token:
        print("Error: SONAR_TOKEN not found in env or .env", file=sys.stderr)
        sys.exit(1)

    commit = _current_commit()

    analysis_key = _wait_for_analysis(token, commit, args.timeout, args.interval)
    if not analysis_key:
        print(
            f"Timeout: no analysis found for {commit[:8]} after {args.timeout}s",
            file=sys.stderr,
        )
        sys.exit(1)

    passed, conditions = _check_gate(token, analysis_key)

    if passed:
        print("\n✓ Sonarcloud quality gate: PASSED")
        sys.exit(0)

    print("\n✗ Sonarcloud quality gate: FAILED", file=sys.stderr)
    for c in conditions:
        if c.get("status") != "OK":
            print(
                f"  - {c.get('metricKey')}: {c.get('actualValue')} "
                f"(threshold: {c.get('errorThreshold', 'n/a')})",
                file=sys.stderr,
            )

    print("\nOpen issues:", file=sys.stderr)
    issues = _fetch_issues(token)
    for issue in issues:
        component = issue.get("component", "").replace(f"{PROJECT_KEY}:", "")
        line = issue.get("line", "?")
        severity = issue.get("severity", "?")
        msg = issue.get("message", "")
        print(f"  [{severity}] {component}:{line} — {msg}", file=sys.stderr)

    sys.exit(1)


if __name__ == "__main__":
    main()
