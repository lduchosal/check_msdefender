"""Configuration management."""

import configparser
from pathlib import Path

from check_msdefender.core.path_probe import DEFAULT_VERIFY_COMMAND


def load_config(config_path: str = "check_msdefender.ini") -> configparser.ConfigParser:
    """
    Load configuration from file.

    Raises:
        FileNotFoundError: If no configuration file can be located.
    """
    config = configparser.ConfigParser()

    # Try to find config file
    config_file = _find_config_file(config_path)

    if not config_file or not Path(config_file).exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    config.read(config_file)
    return config


def get_timeout(config: configparser.ConfigParser) -> int:
    """
    Read the request timeout in seconds from [settings], defaulting to 30.

    Heavy TVM endpoints (machine vulnerabilities) can exceed short timeouts on machines with a large
    vulnerable surface; keep the worst case of the two sequential API calls under the Nagios
    service_check_timeout (60s).
    """
    return config.getint("settings", "timeout", fallback=30)


def get_verify_command(config: configparser.ConfigParser) -> str:
    """
    Read the path verification command template from [verify], with the SSH default.

    The template is split shell-style and run without a shell; ``{host}`` is replaced by
    the machine's DNS name. Keeping it in configuration is what lets the check work on an
    estate whose monitoring server reaches its hosts some other way.
    """
    return config.get("verify", "command", fallback=DEFAULT_VERIFY_COMMAND)


def get_verify_timeout(config: configparser.ConfigParser) -> int:
    """
    Read the path verification timeout in seconds from [verify], defaulting to 20.

    It is spent on top of the API calls, so keep the sum under the Nagios
    service_check_timeout (60s). A probe that times out leaves the score unfiltered.
    """
    return config.getint("verify", "timeout", fallback=20)


def _find_config_file(config_path: str) -> str | None:
    """Find configuration file in current directory or Nagios base directory."""
    # If absolute path provided, use it
    if Path(config_path).is_absolute():
        return config_path

    # Try current directory
    current_dir = Path.cwd() / config_path
    if current_dir.exists():
        return str(current_dir)

    # Try Nagios base directory
    nagios_base = Path("/usr/local/etc/nagios") / config_path
    if nagios_base.exists():
        return str(nagios_base)

    # Return original path (will fail later if not found)
    return config_path
