"""List machines commands for CLI."""

# pyright: reportUnusedFunction=false

import sys
from typing import Any, Optional

from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.nagios import NagiosPlugin
from check_msdefender.services.machines_service import MachinesService

from ..decorators import common_options


def register_machines_commands(main_group: Any) -> None:
    """Register list machines commands with the main CLI group."""

    @main_group.command("machines")
    @common_options
    def machines_cmd(
        config: str,
        verbose: int,
        machine_id: Optional[str],
        dns_name: Optional[str],
        warning: Optional[float],
        critical: Optional[float],
    ) -> None:
        """List all machines in Microsoft Defender for Endpoint."""
        warning = warning if warning is not None else 10
        critical = critical if critical is not None else 25

        try:
            # Load configuration
            cfg = load_config(config)

            # Get authenticator
            authenticator = get_authenticator(cfg)

            # Create Defender client
            client = DefenderClient(authenticator, verbose_level=verbose)

            # Create the service
            service = MachinesService(client, verbose_level=verbose)

            # Create Nagios plugin
            plugin = NagiosPlugin(service, "machines")

            # Execute check
            result = plugin.check(warning=warning, critical=critical, verbose=verbose)

            sys.exit(result)

        except Exception as e:
            print(f"UNKNOWN: {e}")
            sys.exit(3)
