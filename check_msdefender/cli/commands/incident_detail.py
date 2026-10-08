"""Incident detail command for CLI."""

# pyright: reportUnusedFunction=false

import json
import sys
from pathlib import Path
from typing import Any

import click

from check_msdefender.core.auth import get_authenticator
from check_msdefender.core.config import get_timeout, load_config
from check_msdefender.core.defender import DefenderClient
from check_msdefender.services.incident_detail_service import IncidentDetailService


def register_incident_detail_commands(main_group: Any) -> None:
    """Register incident detail commands with the main CLI group."""

    @main_group.command("incident-detail")
    @click.argument("reference")
    @click.option(
        "-c", "--config", default="check_msdefender.ini", help="Configuration file path"
    )
    @click.option("-v", "--verbose", count=True, help="Increase verbosity")
    @click.option(
        "-o", "--output", type=click.Path(dir_okay=False), help="Write the report here"
    )
    @click.option("--json", "as_json", is_flag=True, help="Dump the raw collected JSON")
    def incident_detail_cmd(
        reference: str,
        config: str,
        verbose: int,
        output: str | None,
        as_json: bool,
    ) -> None:
        """
        Dump every detail of an incident (alerts, evidence, processes, users, files, IPs...) as text
        for analysis.

        REFERENCE is an incident id (integer) or the id of any alert of the incident. Resolved
        incidents are reported too.
        """
        try:
            cfg = load_config(config)
            authenticator = get_authenticator(cfg)
            client = DefenderClient(
                authenticator, timeout=get_timeout(cfg), verbose_level=verbose
            )
            service = IncidentDetailService(client, verbose_level=verbose)

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
