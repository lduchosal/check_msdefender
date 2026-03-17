"""Integration test runner for check_msdefender commands."""

import configparser
import subprocess
import sys
from pathlib import Path


def find_config() -> Path:
    """Find the configuration file."""
    locations = [
        Path("check_msdefender.ini"),
        Path.home() / ".check_msdefender.ini",
        Path("/etc/check_msdefender.ini"),
    ]
    for loc in locations:
        if loc.exists():
            return loc
    raise FileNotFoundError("Configuration file not found")


def main() -> int:
    """Run all check_msdefender commands."""
    quiet = "-q" in sys.argv or "--quiet" in sys.argv

    try:
        config_path = find_config()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1

    config = configparser.ConfigParser()
    config.read(config_path)

    machine = config.get("integration", "machine", fallback=None)
    if not machine:
        print("Error: No machine configured in [integration] section")
        return 1

    if not quiet:
        print(f"Running integration tests with machine: {machine}")
        print(f"Config: {config_path}")
        print("=" * 60)

    all_commands = [
        ["check_msdefender", "machines"],
        ["check_msdefender", "alerts", "-d", machine],
        ["check_msdefender", "detail", "-d", machine],
        ["check_msdefender", "lastseen", "-d", machine],
        ["check_msdefender", "onboarding", "-d", machine],
        ["check_msdefender", "products", "-d", machine],
        ["check_msdefender", "vulnerabilities", "-d", machine],
    ]

    failures = 0
    for cmd in all_commands:
        cmd_str = " ".join(cmd)

        if quiet:
            result = subprocess.run(cmd, capture_output=True, text=True)
            status = "OK" if result.returncode == 0 else "FAIL"
            if result.returncode != 0:
                failures += 1
            print(f"  [{status:4}] {cmd_str}")
        else:
            print(f"\n>>> {cmd_str}")
            print("-" * 60)
            result = subprocess.run(cmd, capture_output=False)
            if result.returncode != 0:
                failures += 1

    return 1 if failures > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
