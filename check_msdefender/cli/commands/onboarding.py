"""Onboarding status commands for CLI."""

import sys
from typing import Any, Optional

from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.nagios import NagiosPlugin
from check_msdefender.services.onboarding_service import OnboardingService

from ..decorators import common_options


def register_onboarding_commands(main_group: Any) -> None:
    """Register onboarding status commands with the main CLI group."""

    @main_group.command("onboarding")
    @common_options
    def onboarding_cmd(
        config: str,
        verbose: int,
        machine_id: Optional[str],
        dns_name: Optional[str],
        warning: Optional[float],
        critical: Optional[float],
    ) -> None:
        """Check onboarding status for Microsoft Defender (alias)."""
        warning = warning if warning is not None else 1
        critical = critical if critical is not None else 2

        try:
            # Load configuration
            cfg = load_config(config)

            # Get authenticator
            authenticator = get_authenticator(cfg)

            # Create Defender client
            client = DefenderClient(authenticator, verbose_level=verbose)

            # Create the appropriate service based on service
            service = OnboardingService(client, verbose_level=verbose)

            # Create Nagios plugin
            plugin = NagiosPlugin(service, "onboarding")

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
