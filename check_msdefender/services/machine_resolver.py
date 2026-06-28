"""
Shared machine-identity resolution used across services.

Translates the ``(machine_id, dns_name)`` pair a CLI command receives into the identifiers the
Defender API needs, raising a uniform ValidationError. Keeping this in one place removes the
resolution boilerplate that was duplicated across every service.
"""

from __future__ import annotations

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.models import DefenderClientProtocol


def resolve_machine(
    defender: DefenderClientProtocol,
    machine_id: str | None,
    dns_name: str | None,
) -> tuple[str, str]:
    """
    Resolve a machine to its ``(id, dns_name)`` from either identifier.

    When ``machine_id`` is given the DNS name is looked up; when only
    ``dns_name`` is given the id is looked up.

    Raises:
        ValidationError: If neither identifier is provided, the named machine
            is not found, or no id could be resolved.
    """
    if not machine_id and not dns_name:
        raise ValidationError("Either machine_id or dns_name must be provided")

    if machine_id:
        machine_details = defender.get_machine_by_id(machine_id)
        return machine_id, machine_details.get("computerDnsName", "Unknown")

    assert dns_name is not None
    machines = defender.get_machine_by_dns_name(dns_name).get("value", [])
    if not machines:
        raise ValidationError(f"Machine not found with DNS name: {dns_name}")
    resolved_id = machines[0].get("id")
    if not resolved_id:
        raise ValidationError("Could not resolve a machine id for the request")
    return resolved_id, dns_name


def resolve_machine_id(
    defender: DefenderClientProtocol,
    machine_id: str | None,
    dns_name: str | None,
) -> str:
    """
    Resolve a machine id, looking it up by DNS name when needed.

    Raises:
        ValidationError: If neither identifier is provided, the named machine
            is not found, or no id could be resolved.
    """
    if not machine_id and not dns_name:
        raise ValidationError("Either machine_id or dns_name must be provided")

    if dns_name:
        machines = defender.get_machine_by_dns_name(dns_name).get("value", [])
        if not machines:
            raise ValidationError(f"Machine not found with DNS name: {dns_name}")
        machine_id = machines[0].get("id")

    if not machine_id:
        raise ValidationError("Could not resolve a machine id for the request")
    return machine_id
