"""Products commands for CLI."""

import sys
from typing import Any, Optional

from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.nagios import NagiosPlugin
from check_msdefender.services.products_service import ProductsService

from ..decorators import common_options


def register_products_commands(main_group: Any) -> None:
    """Register products commands with the main CLI group."""

    @main_group.command("products")
    @common_options
    def products_cmd(
        config: str,
        verbose: int,
        machine_id: Optional[str],
        dns_name: Optional[str],
        warning: Optional[float],
        critical: Optional[float],
    ) -> None:
        """Check installed products for Microsoft Defender."""
        warning = (
            warning if warning is not None else 1
        )  # Trigger warning on any high/medium severity
        critical = (
            critical if critical is not None else 1
        )  # Trigger critical on any critical severity

        try:
            # Load configuration
            cfg = load_config(config)

            # Get authenticator
            authenticator = get_authenticator(cfg)

            # Create Defender client
            client = DefenderClient(authenticator, verbose_level=verbose)

            # Create the products service
            service = ProductsService(client, verbose_level=verbose)

            # Create Nagios plugin
            plugin = NagiosPlugin(service, "products")

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
