"""Commands package for CLI."""

from typing import Any

from .alerts import register_alerts_commands
from .detail import register_detail_commands
from .lastseen import register_lastseen_commands
from .machines import register_machines_commands
from .onboarding import register_onboarding_commands
from .products import register_products_commands
from .vulnerabilities import register_vulnerability_commands


def register_all_commands(main_group: Any) -> None:
    """Register all commands with the main CLI group."""
    register_lastseen_commands(main_group)
    register_vulnerability_commands(main_group)
    register_onboarding_commands(main_group)
    register_machines_commands(main_group)
    register_detail_commands(main_group)
    register_alerts_commands(main_group)
    register_products_commands(main_group)
