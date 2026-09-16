"""Products commands for CLI."""

# pyright: reportUnusedFunction=false

import configparser
import sys
from typing import Any

import click

from check_msdefender.cli.decorators import common_options
from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import (
    get_timeout,
    get_verify_command,
    get_verify_timeout,
    load_config,
)
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.nagios import NagiosPlugin
from check_msdefender.core.path_probe import CommandPathProbe
from check_msdefender.services.products_service import ProductsService
from check_msdefender.services.products_verifier import ProductsVerifier

_VERIFY_HELP = (
    "Ask the host whether the paths Defender reports still exist, and drop the "
    "products it no longer confirms (removed, or already upgraded). Anything the "
    "host cannot answer for stays counted."
)


def _build_verifier(
    cfg: configparser.ConfigParser, verify_paths: bool, verbose: int
) -> ProductsVerifier | None:
    """Build the path verifier when the check was asked to confirm what it reports."""
    if not verify_paths:
        return None
    probe = CommandPathProbe(
        get_verify_command(cfg), get_verify_timeout(cfg), verbose_level=verbose
    )
    return ProductsVerifier(probe, verbose_level=verbose)


def _check_products(
    config: str,
    verbose: int,
    machine_id: str | None,
    dns_name: str | None,
    warning: float,
    critical: float,
    verify_paths: bool,
) -> int:
    """Run the products check and return its Nagios exit code."""
    cfg = load_config(config)
    client = DefenderClient(
        get_authenticator(cfg), timeout=get_timeout(cfg), verbose_level=verbose
    )
    service = ProductsService(
        client,
        verbose_level=verbose,
        verifier=_build_verifier(cfg, verify_paths, verbose),
    )
    return NagiosPlugin(service, "products").check(
        machine_id=machine_id,
        dns_name=dns_name,
        warning=warning,
        critical=critical,
        verbose=verbose,
    )


def register_products_commands(main_group: Any) -> None:
    """Register products commands with the main CLI group."""

    @main_group.command("products")
    @common_options
    @click.option("--verify-paths", is_flag=True, help=_VERIFY_HELP)
    def products_cmd(
        config: str,
        verbose: int,
        machine_id: str | None,
        dns_name: str | None,
        warning: float | None,
        critical: float | None,
        verify_paths: bool,
    ) -> None:
        """Check installed products for Microsoft Defender."""
        # Trigger warning on any high/medium severity, critical on any critical one.
        warning = warning if warning is not None else 1
        critical = critical if critical is not None else 1

        try:
            result = _check_products(
                config,
                verbose,
                machine_id,
                dns_name,
                warning,
                critical,
                verify_paths,
            )
            sys.exit(result)
        except Exception as e:  # noqa: BLE001
            print(f"UNKNOWN: {e}")
            sys.exit(3)
