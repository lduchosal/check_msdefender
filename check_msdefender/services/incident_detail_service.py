"""Incident detail service: gather everything known about one incident into a text report."""

from __future__ import annotations

import json
import re
from typing import Any, cast

from check_msdefender.core.exceptions import DefenderAPIError, ValidationError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import DefenderClientProtocol

# Entities exposed under /api/alerts/{id}/<entity>, in report order. The machine is not
# among them: it is fetched once per incident, not once per alert.
RELATED_ENTITIES = ("user", "files", "ips", "domains")

# Evidence fields that identify an entity. The same file, process or account is attached to
# every alert that saw it; these fields tell two copies apart, so the incident lists each
# entity once, as the portal does. Left out on purpose: evidenceCreationTime (differs per
# alert) and attributes one copy may lack while the other has them (hashes, SID, AAD id) --
# the merge fills those in instead.
_EVIDENCE_IDENTITY_FIELDS = (
    "entityType",
    "fileName",
    "filePath",
    "processId",
    "processCreationTime",
    "ipAddress",
    "url",
    "registryKey",
    "registryValueName",
    "accountName",
    "domainName",
)

# Alert fields rendered first, in this order; every other field follows them.
_ALERT_KEY_FIELDS = (
    "id",
    "title",
    "severity",
    "status",
    "classification",
    "determination",
    "category",
    "detectionSource",
    "threatFamilyName",
    "threatName",
    "mitreTechniques",
    "computerDnsName",
    "machineId",
    "relatedUser",
    "alertCreationTime",
    "firstEventTime",
    "lastEventTime",
    "lastUpdateTime",
    "resolvedTime",
    "investigationId",
    "investigationState",
    "assignedTo",
    "description",
    "recommendedAction",
)

# Fields kept out of the generic alert dump: rendered in their own section or noise.
_ALERT_SKIPPED_FIELDS = {"evidence", "comments", "incidentId", "aadTenantId"}

# A GUID is what people paste from the portal URL bar; it is never an incidentId.
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

_RULE = "=" * 78

# What the alerts API cannot see; said in the report so a reader does not assume absence.
_NOT_COVERED = (
    "Not covered (needs the incidents API, Incident.Read.All / SecurityIncident.Read.All): "
    "incident activity log, attack story, incident-level classification and tags."
)


def _is_empty(value: Any) -> bool:
    """Tell whether an API value carries no information (None, "", [], {})."""
    return value is None or value in ("", [], {})


def _as_dict(value: Any) -> dict[str, Any] | None:
    """Return ``value`` as a JSON object, or None when it is something else."""
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _as_list(value: Any) -> list[Any]:
    """Return ``value`` as a JSON array, or an empty list when it is something else."""
    return cast("list[Any]", value) if isinstance(value, list) else []


def _format_value(value: Any) -> str:
    """Render one API value on a single line (lists/dicts as compact JSON)."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _format_fields(
    record: dict[str, Any],
    indent: str,
    first: tuple[str, ...] = (),
    skip: set[str] | frozenset[str] = frozenset(),
) -> list[str]:
    """Render every non-empty field of ``record`` as ``key: value`` lines."""
    keys = [key for key in first if key in record]
    keys += sorted(key for key in record if key not in first and key not in skip)
    lines: list[str] = []
    for key in keys:
        value = record[key]
        if _is_empty(value):
            continue
        text = _format_value(value)
        if "\n" in text:
            lines.append(f"{indent}{key}:")
            lines.extend(f"{indent}  | {line}" for line in text.splitlines())
        else:
            lines.append(f"{indent}{key}: {text}")
    return lines


class IncidentDetailService:
    """Collect an incident's alerts, evidence and related entities, and render them as text."""

    def __init__(
        self, defender_client: DefenderClientProtocol, verbose_level: int = 0
    ) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def resolve_incident_id(self, reference: str) -> int:
        """
        Turn the user's reference into an incidentId.

        An integer is taken as the incidentId itself; anything else is looked up as an alert id
        and replaced by the incident that alert belongs to.

        Raises:
            ValidationError: If the reference is a GUID or the alert has no incident.
        """
        reference = reference.strip()
        if reference.isdigit():
            return int(reference)
        if _GUID_RE.match(reference):
            raise ValidationError(
                f"{reference} looks like a GUID (tenant, machine or investigation id), "
                "not an incident: Defender incident ids are integers, alert ids look "
                "like 'da0123...-..._1'"
            )
        incident_id = self.defender.get_alert(reference).get("incidentId")
        if not isinstance(incident_id, int):
            raise ValidationError(f"Alert {reference} is not attached to any incident")
        self.logger.info(f"Alert {reference} belongs to incident {incident_id}")
        return incident_id

    def collect(self, incident_id: int) -> dict[str, Any]:
        """
        Gather the incident's alerts (with evidence), its machines and each alert's related
        entities.

        A failure on a machine or related entity is recorded in the report instead of aborting
        it: the point of the report is debugging, and a partial picture beats none.

        Raises:
            ValidationError: If no alert belongs to the incident.
        """
        self.logger.method_entry("collect", incident_id=incident_id)

        alerts = self.defender.get_incident_alerts(incident_id).get("value", [])
        if not alerts:
            raise ValidationError(f"No alert found for incident {incident_id}")
        alerts.sort(key=lambda alert: alert.get("alertCreationTime", ""))

        machine_ids = sorted({mid for a in alerts if (mid := a.get("machineId"))})
        machines = {mid: self._fetch_machine(mid) for mid in machine_ids}

        related: dict[str, dict[str, Any]] = {}
        for alert in alerts:
            alert_id = alert.get("id")
            if not alert_id:
                continue
            related[alert_id] = {
                entity: self._fetch_related(alert_id, entity)
                for entity in RELATED_ENTITIES
            }

        data: dict[str, Any] = {
            "incidentId": incident_id,
            "alerts": alerts,
            "machines": machines,
            "related": related,
        }
        self.logger.method_exit("collect", f"{len(alerts)} alert(s)")
        return data

    def _fetch_machine(self, machine_id: str) -> Any:
        """Fetch one machine, turning an API failure into an ``error`` record."""
        try:
            return self.defender.get_machine_by_id(machine_id)
        except DefenderAPIError as e:
            self.logger.info(f"Machine {machine_id} unavailable: {e}")
            return {"error": str(e)}

    def _fetch_related(self, alert_id: str, entity: str) -> Any:
        """Fetch one related entity, turning an API failure into an ``error`` record."""
        try:
            result = self.defender.get_alert_related(alert_id, entity)
        except DefenderAPIError as e:
            self.logger.info(f"Related {entity} of {alert_id} unavailable: {e}")
            return {"error": str(e)}
        record = _as_dict(result)
        if record is not None and "value" in record:
            return record["value"]
        return result

    def render(self, data: dict[str, Any]) -> str:
        """Render collected incident data as a structured plain-text report."""
        records: list[dict[str, Any]] = [dict(alert) for alert in data["alerts"]]
        evidence, references = self._merge_evidence(records)

        lines: list[str] = [
            _RULE,
            f"INCIDENT {data['incidentId']}",
            _RULE,
            _NOT_COVERED,
        ]
        lines += self._render_summary(records, evidence)
        lines += self._render_machines(data.get("machines", {}))
        lines += self._render_evidence(evidence)

        for index, record in enumerate(records, start=1):
            lines += ["", _RULE, f"ALERT {index}/{len(records)}", _RULE]
            lines += _format_fields(
                record, "", first=_ALERT_KEY_FIELDS, skip=_ALERT_SKIPPED_FIELDS
            )
            numbers = references[index - 1]
            listed = ", ".join(f"#{n}" for n in numbers) if numbers else "none"
            lines.append(f"evidence: {listed}")
            lines += self._render_comments(record.get("comments"))
            lines += self._render_related(data["related"].get(record.get("id"), {}))

        return "\n".join(lines) + "\n"

    def _merge_evidence(
        self, records: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[list[int]]]:
        """
        Deduplicate the evidence of every alert into one incident-wide list.

        Returns the merged entities (each with the ``alerts`` that cite it) and, per alert, the
        1-based numbers of the entities it cites.
        """
        merged: dict[tuple[str, ...], dict[str, Any]] = {}
        cited: list[list[tuple[str, ...]]] = []
        for index, record in enumerate(records, start=1):
            keys: list[tuple[str, ...]] = []
            for item in _as_list(record.get("evidence")):
                entity = _as_dict(item)
                if entity is None:
                    continue
                key = tuple(
                    _format_value(entity.get(field))
                    for field in _EVIDENCE_IDENTITY_FIELDS
                )
                target = merged.setdefault(key, {"alerts": []})
                for field, value in entity.items():
                    if _is_empty(target.get(field)):
                        target[field] = value
                if index not in target["alerts"]:
                    target["alerts"].append(index)
                if key not in keys:
                    keys.append(key)
            cited.append(keys)

        ordered = sorted(
            merged.items(), key=lambda kv: str(kv[1].get("entityType", "Unknown"))
        )
        numbers = {key: number for number, (key, _) in enumerate(ordered, start=1)}
        references = [sorted(numbers[key] for key in keys) for keys in cited]
        return [entity for _, entity in ordered], references

    def _render_summary(
        self, records: list[dict[str, Any]], evidence: list[dict[str, Any]]
    ) -> list[str]:
        """Summarise the incident across its alerts (time span, machines, users, statuses)."""

        def distinct(key: str) -> list[str]:
            """Return the sorted distinct non-empty values of ``key`` across the alerts."""
            values = {
                _format_value(r[key]) for r in records if not _is_empty(r.get(key))
            }
            return sorted(values)

        first_times = distinct("firstEventTime") or distinct("alertCreationTime")
        last_times = distinct("lastEventTime") or distinct("alertCreationTime")
        accounts: set[str] = set()
        for entity in evidence:
            if entity.get("accountName"):
                parts = (entity.get("domainName"), entity["accountName"])
                accounts.add("\\".join(str(part) for part in parts if part))
        types: dict[str, int] = {}
        for entity in evidence:
            entity_type = str(entity.get("entityType", "Unknown"))
            types[entity_type] = types.get(entity_type, 0) + 1

        summary = {
            "alerts": len(records),
            "firstActivity": first_times[0] if first_times else None,
            "lastActivity": last_times[-1] if last_times else None,
            "severities": distinct("severity"),
            "statuses": distinct("status"),
            "classifications": distinct("classification"),
            "determinations": distinct("determination"),
            "categories": distinct("category"),
            "detectionSources": distinct("detectionSource"),
            "mitreTechniques": sorted(
                {str(t) for r in records for t in _as_list(r.get("mitreTechniques"))}
            ),
            "machines": distinct("computerDnsName"),
            "accounts": sorted(accounts),
            "evidence": types,
            "titles": [r.get("title", "Unknown alert") for r in records],
        }
        lines = _format_fields(summary, "", first=tuple(summary))
        return ["", "SUMMARY", "-------", *lines]

    def _render_machines(self, machines: dict[str, Any]) -> list[str]:
        """Render the incident's machines (the devices of the portal's assets tab)."""
        lines = ["", f"MACHINES ({len(machines)})", "--------"]
        for machine_id, value in machines.items():
            record = _as_dict(value) or {}
            if set(record) == {"error"}:
                lines.append(f"#{machine_id}: unavailable ({record['error']})")
                continue
            lines.append(f"#{machine_id}")
            lines += _format_fields(
                record, "  ", first=("computerDnsName",), skip={"id", "@odata.context"}
            )
        return lines

    def _render_evidence(self, evidence: list[dict[str, Any]]) -> list[str]:
        """Render the incident-wide evidence, numbered and grouped by entity type."""
        lines = ["", f"EVIDENCE ({len(evidence)} distinct)", "--------"]
        if not evidence:
            return [*lines, "none"]
        current = None
        for number, entity in enumerate(evidence, start=1):
            entity_type = str(entity.get("entityType", "Unknown"))
            if entity_type != current:
                current = entity_type
                lines.append(f"[{entity_type}]")
            lines.append(f"  #{number}")
            lines += _format_fields(
                entity, "    ", first=("alerts",), skip={"entityType"}
            )
        return lines

    def _render_comments(self, comments: Any) -> list[str]:
        """Render the analyst comments of an alert."""
        entries = [_as_dict(item) for item in _as_list(comments)]
        if not entries:
            return []
        lines = ["comments:"]
        for comment in entries:
            if comment is not None:
                author = comment.get("createdBy", "?")
                when = comment.get("createdTime", "?")
                lines.append(f"  - [{when}] {author}: {comment.get('comment', '')}")
        return lines

    def _render_related(self, related: dict[str, Any]) -> list[str]:
        """Render the entities fetched from /api/alerts/{id}/<entity>."""
        lines: list[str] = []
        for entity in RELATED_ENTITIES:
            if entity not in related:
                continue
            value = related[entity]
            record = _as_dict(value)
            title = f"related {entity}"
            if record is not None and set(record) == {"error"}:
                lines.append(f"{title}: unavailable ({record['error']})")
            elif _is_empty(value):
                lines.append(f"{title}: none")
            elif isinstance(value, list):
                items = _as_list(value)
                lines.append(f"{title} ({len(items)}):")
                for number, item in enumerate(items, start=1):
                    lines.append(f"  #{number}")
                    item_record = _as_dict(item)
                    if item_record is not None:
                        lines += _format_fields(item_record, "    ")
                    else:
                        lines.append(f"    {_format_value(item)}")
            elif record is not None:
                lines.append(f"{title}:")
                lines += _format_fields(record, "  ")
            else:
                lines.append(f"{title}: {_format_value(value)}")
        return lines
