"""Last seen commands for CLI."""

# pyright: reportUnusedFunction=false

import sys
from typing import Any, Optional

from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.nagios import NagiosPlugin
from check_msdefender.services.lastseen_service import LastSeenService

from ..decorators import common_options


def register_lastseen_commands(main_group: Any) -> None:
    """Register last seen commands with the main CLI group."""

    @main_group.command("lastseen")
    @common_options
    def lastseen_cmd(
        config: str,
        verbose: int,
        machine_id: Optional[str],
        dns_name: Optional[str],
        warning: Optional[float],
        critical: Optional[float],
    ) -> None:
        """Check days since last seen for Microsoft Defender."""
        warning = warning if warning is not None else 7
        critical = critical if critical is not None else 30

        try:
            # Load configuration
            cfg = load_config(config)

            # Get authenticator
            authenticator = get_authenticator(cfg)

            # Create Defender client
            client = DefenderClient(authenticator, verbose_level=verbose)

            # Create the appropriate service based on service
            service = LastSeenService(client, verbose_level=verbose)

            # Create Nagios plugin
            plugin = NagiosPlugin(service, "lastseen")

            # Execute check
            result = plugin.check(
                machine_id=machine_id,
                dns_name=dns_name,
                warning=warning,
                critical=critical,
                verbose=verbose,
            )

            sys.exit(result)

        except Exception as e:
            print(f"UNKNOWN: {e}")
            sys.exit(3)
