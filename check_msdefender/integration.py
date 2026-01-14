"""Integration test runner for check_msdefender commands."""

import configparser
import subprocess
import sys
from pathlib import Path


def find_config() -> Path:
    """Find the configuration file."""
    # Check common locations
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

    print(f"Running integration tests with machine: {machine}")
    print(f"Config: {config_path}")
    print("=" * 60)

    # Commands that don't need -d flag
    commands_no_machine = [
        ["check_msdefender", "machines"],
    ]

    # Commands that need -d flag
    commands_with_machine = [
        ["check_msdefender", "alerts", "-d", machine],
        ["check_msdefender", "detail", "-d", machine],
        ["check_msdefender", "lastseen", "-d", machine],
        ["check_msdefender", "onboarding", "-d", machine],
        ["check_msdefender", "products", "-d", machine],
        ["check_msdefender", "vulnerabilities", "-d", machine],
    ]

    all_commands = commands_no_machine + commands_with_machine
    results = []

    for cmd in all_commands:
        cmd_str = " ".join(cmd)
        print(f"\n>>> {cmd_str}")
        print("-" * 60)

        result = subprocess.run(cmd, capture_output=False)
        results.append((cmd_str, result.returncode))

    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)

    for cmd_str, returncode in results:
        status = "OK" if returncode == 0 else f"EXIT {returncode}"
        print(f"  [{status:8}] {cmd_str}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
