"""Commands package for CLI."""

from typing import Any

from check_msdefender.cli.commands.alerts import register_alerts_commands
from check_msdefender.cli.commands.detail import register_detail_commands
from check_msdefender.cli.commands.incidents import register_incidents_commands
from check_msdefender.cli.commands.lastseen import register_lastseen_commands
from check_msdefender.cli.commands.machines import register_machines_commands
from check_msdefender.cli.commands.onboarding import register_onboarding_commands
from check_msdefender.cli.commands.products import register_products_commands
from check_msdefender.cli.commands.vulnerabilities import (
    register_vulnerability_commands,
)


def register_all_commands(main_group: Any) -> None:
    """Register all commands with the main CLI group."""
    register_lastseen_commands(main_group)
    register_vulnerability_commands(main_group)
    register_onboarding_commands(main_group)
    register_machines_commands(main_group)
    register_detail_commands(main_group)
    register_alerts_commands(main_group)
    register_incidents_commands(main_group)
    register_products_commands(main_group)
