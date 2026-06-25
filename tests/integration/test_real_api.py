"""
End-to-end tests that hit the real Microsoft Defender API.

These are opt-in: they run only when ``CHECK_MSDEFENDER_E2E=1`` is set AND a
configuration file with an ``[integration]`` machine is available. Otherwise they
are skipped, so the normal ``pdm test`` run stays offline and credential-free.

They catch API-contract regressions (wrong endpoint, unsupported query options,
auth/scope issues) that mocked tests cannot — e.g. a device-scoped alerts request
rejected with HTTP 400.

Run with::

    CHECK_MSDEFENDER_E2E=1 pdm run test-integration
"""

import configparser
import os
import subprocess
from pathlib import Path

import pytest

# Nagios exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN.
# Only 3 (UNKNOWN) means the plugin itself failed (bad request, auth, etc.).
NAGIOS_UNKNOWN = 3

pytestmark = pytest.mark.e2e


def _find_machine() -> str:
    """Return the configured integration machine, or skip if unavailable."""
    if os.environ.get("CHECK_MSDEFENDER_E2E") != "1":
        pytest.skip("Set CHECK_MSDEFENDER_E2E=1 to run real-API end-to-end tests")

    locations = [
        Path("check_msdefender.ini"),
        Path.home() / ".check_msdefender.ini",
        Path("/etc/check_msdefender.ini"),
    ]
    config_path = next((loc for loc in locations if loc.exists()), None)
    if config_path is None:
        pytest.skip("No check_msdefender.ini found for end-to-end tests")

    config = configparser.ConfigParser()
    config.read(config_path)
    machine = config.get("integration", "machine", fallback=None)
    if not machine:
        pytest.skip("No machine configured in the [integration] section")
    return machine


@pytest.mark.parametrize("command", ["alerts", "incidents"])
def test_command_does_not_return_unknown(command: str) -> None:
    """The command runs against the real API without a plugin (UNKNOWN) failure."""
    machine = _find_machine()

    result = subprocess.run(
        ["check_msdefender", command, "-d", machine],
        capture_output=True,
        text=True,
    )

    assert result.returncode < NAGIOS_UNKNOWN, (
        f"`check_msdefender {command} -d {machine}` returned UNKNOWN\n"
        f"exit_code={result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
