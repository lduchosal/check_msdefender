"""Incident detail command for CLI."""

# pyright: reportUnusedFunction=false

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import get_timeout, load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.graph import GraphClient
from check_msdefender.services.incident_detail_service import IncidentDetailService


def _incident_detail_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Attach the incident-detail arguments and options to ``func``."""
    decorators = (
        click.argument("reference"),
        click.option(
            "-c",
            "--config",
            default="check_msdefender.ini",
            help="Configuration file path",
        ),
        click.option("-v", "--verbose", count=True, help="Increase verbosity"),
        click.option(
            "-o",
            "--output",
            type=click.Path(dir_okay=False),
            help="Write the report here",
        ),
        click.option(
            "--json", "as_json", is_flag=True, help="Dump the raw collected JSON"
        ),
        click.option(
            "--window",
            "window_minutes",
            type=click.IntRange(min=0),
            default=10,
            show_default=True,
            help="Minutes of device activity kept before and after the incident",
        ),
        click.option(
            "--timeline-limit",
            type=click.IntRange(min=0),
            default=500,
            show_default=True,
            help="Events kept per Advanced Hunting table (0: no timeline)",
        ),
        click.option(
            "--no-graph",
            is_flag=True,
            help="Use the MDE alerts API only (no Graph incident, no timeline)",
        ),
    )
    for decorator in reversed(decorators):
        func = decorator(func)
    return func


def _build_service(
    config: str, verbose: int, window_minutes: int, timeline_limit: int, no_graph: bool
) -> IncidentDetailService:
    """Wire the Defender (and, unless ``no_graph``, Graph) clients into the service."""
    cfg = load_config(config)
    authenticator = get_authenticator(cfg)
    timeout = get_timeout(cfg)
    client = DefenderClient(authenticator, timeout=timeout, verbose_level=verbose)
    graph = None
    if not no_graph:
        graph = GraphClient(authenticator, timeout=timeout, verbose_level=verbose)
    return IncidentDetailService(
        client,
        verbose_level=verbose,
        graph_client=graph,
        window_minutes=window_minutes,
        timeline_limit=timeline_limit,
    )


def register_incident_detail_commands(main_group: Any) -> None:
    """Register incident detail commands with the main CLI group."""

    @main_group.command("incident-detail")
    @_incident_detail_options
    def incident_detail_cmd(
        reference: str,
        config: str,
        verbose: int,
        output: str | None,
        as_json: bool,
        window_minutes: int,
        timeline_limit: int,
        no_graph: bool,
    ) -> None:
        """
        Dump every detail of an incident (alerts, evidence, processes, users, files, IPs...) as text
        for analysis.

        REFERENCE is an incident id (integer) or the id of any alert of the incident. Resolved
        incidents are reported too. The Graph security API (SecurityIncident.Read.All,
        ThreatHunting.Read.All) gives the incident header, evidence verdicts and the device
        timeline; without it the MDE alerts API is used alone.
        """
        try:
            service = _build_service(
                config, verbose, window_minutes, timeline_limit, no_graph
            )
            incident_id = service.resolve_incident_id(reference)
            data = service.collect(incident_id)
            if as_json:
                report = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
            else:
                report = service.render(data)

            if output:
                Path(output).write_text(report, encoding="utf-8")
                print(f"Incident {incident_id} written to {output}", file=sys.stderr)
            else:
                sys.stdout.write(report)

        except Exception as e:  # noqa: BLE001
            print(f"UNKNOWN: {e}", file=sys.stderr)
            sys.exit(3)
