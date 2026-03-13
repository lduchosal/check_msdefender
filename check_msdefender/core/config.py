"""Configuration management."""

import configparser
from pathlib import Path
from typing import Optional


def load_config(config_path: str = "check_msdefender.ini") -> configparser.ConfigParser:
    """Load configuration from file."""
    config = configparser.ConfigParser()

    # Try to find config file
    config_file = _find_config_file(config_path)

    if not config_file or not Path(config_file).exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    config.read(config_file)
    return config


def _find_config_file(config_path: str) -> Optional[str]:
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
