"""Integration test runner for check_msdefender commands."""

import argparse
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
    parser = argparse.ArgumentParser(description="Run check_msdefender integration tests")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet mode: show only summary with OK/FAIL"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose mode: show full command output"
    )
    args = parser.parse_args()

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

    if not args.quiet:
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
    results: list[tuple[str, int, str]] = []

    for cmd in all_commands:
        cmd_str = " ".join(cmd)

        if args.verbose:
            print(f"\n>>> {cmd_str}")
            print("-" * 60)
            result = subprocess.run(cmd, capture_output=False)
            results.append((cmd_str, result.returncode, ""))
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
            first_line = result.stdout.strip().split("\n")[0] if result.stdout.strip() else ""
            results.append((cmd_str, result.returncode, first_line))

    if not args.quiet:
        print("\n" + "=" * 60)
        print("Summary:")
        print("=" * 60)

    failures = 0
    for cmd_str, returncode, output in results:
        if returncode == 0:
            status = "OK"
        else:
            status = "FAIL"
            failures += 1

        if args.quiet:
            print(f"  [{status:4}] {cmd_str}")
        else:
            if output:
                print(f"  [{status:4}] {cmd_str} → {output}")
            else:
                print(f"  [{status:4}] {cmd_str}")

    return 1 if failures > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
