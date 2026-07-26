"""Products commands for CLI."""

# pyright: reportUnusedFunction=false

import sys
from typing import Any

from check_msdefender.cli.decorators import common_options
from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import get_timeout, load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.nagios import NagiosPlugin
from check_msdefender.services.products_service import ProductsService


def register_products_commands(main_group: Any) -> None:
    """Register products commands with the main CLI group."""

    @main_group.command("products")
    @common_options
    def products_cmd(
        config: str,
        verbose: int,
        machine_id: str | None,
        dns_name: str | None,
        warning: float | None,
        critical: float | None,
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
            client = DefenderClient(
                authenticator, timeout=get_timeout(cfg), verbose_level=verbose
            )

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

        except Exception as e:  # noqa: BLE001
            print(f"UNKNOWN: {e}")
            sys.exit(3)
