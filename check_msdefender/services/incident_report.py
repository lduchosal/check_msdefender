"""Incident report rendering: the collected incident data as structured plain text."""

from __future__ import annotations

import json
from typing import Any, cast

from check_msdefender.services.incident_timeline import printable, render_timeline

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
    "processCreationDateTime",
    "mdeDeviceId",
    "deviceDnsName",
    "ipAddress",
    "url",
    "registryKey",
    "registryValueName",
    "accountName",
    "domainName",
)

# Alert fields rendered first, in this order; every other field follows them. Both
# vocabularies are listed: the MDE alerts API and the Graph alerts (v2) name things apart.
_ALERT_KEY_FIELDS = (
    "id",
    "title",
    "severity",
    "status",
    "classification",
    "determination",
    "category",
    "detectionSource",
    "productName",
    "serviceSource",
    "threatFamilyName",
    "threatName",
    "threatDisplayName",
    "mitreTechniques",
    "computerDnsName",
    "machineId",
    "relatedUser",
    "alertCreationTime",
    "createdDateTime",
    "firstEventTime",
    "firstActivityDateTime",
    "lastEventTime",
    "lastActivityDateTime",
    "lastUpdateTime",
    "lastUpdateDateTime",
    "resolvedTime",
    "resolvedDateTime",
    "investigationId",
    "investigationState",
    "assignedTo",
    "alertWebUrl",
    "description",
    "recommendedAction",
    "recommendedActions",
)

# Fields kept out of the generic alert dump: rendered in their own section or noise.
_ALERT_SKIPPED_FIELDS = {
    "evidence",
    "comments",
    "incidentId",
    "aadTenantId",
    "tenantId",
    "incidentWebUrl",
    "@odata.type",
}

# Incident (Graph) fields rendered first; alerts have their own sections.
_INCIDENT_KEY_FIELDS = (
    "displayName",
    "severity",
    "status",
    "classification",
    "determination",
    "assignedTo",
    "priorityScore",
    "createdDateTime",
    "lastUpdateDateTime",
    "lastModifiedBy",
    "resolvingComment",
    "summary",
    "customTags",
    "systemTags",
    "incidentWebUrl",
    "redirectIncidentId",
    "description",
)
_INCIDENT_SKIPPED_FIELDS = {"alerts", "comments", "id", "tenantId", "@odata.context"}

_RULE = "=" * 78

# What the report cannot see; said so a reader does not take it for absence.
_NOT_COVERED_GRAPH = (
    "Not covered (no API exposes it): the incident activity log (status/classification "
    "history). The attack story is approximated by the Advanced Hunting timeline."
)
_NOT_COVERED_MDE = (
    "Not covered (Graph incidents API unavailable, needs SecurityIncident.Read.All): "
    "incident header, evidence verdicts and remediation status."
)


def is_empty(value: Any) -> bool:
    """Tell whether an API value carries no information (None, "", [], {})."""
    return value is None or value in ("", [], {})


def as_dict(value: Any) -> dict[str, Any] | None:
    """Return ``value`` as a JSON object, or None when it is something else."""
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def as_list(value: Any) -> list[Any]:
    """Return ``value`` as a JSON array, or an empty list when it is something else."""
    return cast("list[Any]", value) if isinstance(value, list) else []


def _format_value(value: Any) -> str:
    """Render one API value on a single line (lists/dicts as compact JSON)."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return printable(str(value))


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
        if is_empty(value):
            continue
        text = _format_value(value)
        if "\n" in text:
            lines.append(f"{indent}{key}:")
            lines.extend(f"{indent}  | {line}" for line in text.splitlines())
        else:
            lines.append(f"{indent}{key}: {text}")
    return lines


def pick(record: dict[str, Any], *keys: str) -> Any:
    """Return the first non-empty value among ``keys`` (field names differ per API)."""
    for key in keys:
        if not is_empty(record.get(key)):
            return record[key]
    return None


def render_report(data: dict[str, Any]) -> str:
    """Render collected incident data as a structured plain-text report."""
    records: list[dict[str, Any]] = [dict(alert) for alert in data["alerts"]]
    evidence, references = _merge_evidence(records)

    lines: list[str] = [_RULE, f"INCIDENT {data['incidentId']}", _RULE]
    if data.get("source") == "graph":
        lines.append(_NOT_COVERED_GRAPH)
        incident = as_dict(data.get("incident")) or {}
        lines += _format_fields(
            incident, "", first=_INCIDENT_KEY_FIELDS, skip=_INCIDENT_SKIPPED_FIELDS
        )
        lines += _render_comments(incident.get("comments"))
    else:
        lines.append(_NOT_COVERED_MDE)
        if data.get("graphError"):
            lines.append(f"graph: unavailable ({data['graphError']})")
    lines += _render_summary(records, evidence)
    lines += _render_machines(data.get("machines", {}))
    lines += _render_evidence(evidence)

    for index, record in enumerate(records, start=1):
        lines += ["", _RULE, f"ALERT {index}/{len(records)}", _RULE]
        lines += _format_fields(
            record, "", first=_ALERT_KEY_FIELDS, skip=_ALERT_SKIPPED_FIELDS
        )
        numbers = references[index - 1]
        listed = ", ".join(f"#{n}" for n in numbers) if numbers else "none"
        lines.append(f"evidence: {listed}")
        lines += _render_comments(record.get("comments"))
        lines += _render_related(data["related"].get(record.get("id"), {}))

    timeline = data.get("timeline")
    if isinstance(timeline, dict) and "error" in timeline:
        lines += ["", f"TIMELINE: unavailable ({timeline['error']})"]
    elif isinstance(timeline, dict):
        lines += render_timeline(cast("dict[str, Any]", timeline))

    return "\n".join(lines) + "\n"


def _merge_evidence(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[list[int]]]:
    """
    Deduplicate the evidence of every alert into one incident-wide list.

    Returns the merged entities (each with the ``alerts`` that cite it) and, per alert, the 1-based
    numbers of the entities it cites.
    """
    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    cited: list[list[tuple[str, ...]]] = []
    for index, record in enumerate(records, start=1):
        keys: list[tuple[str, ...]] = []
        for item in as_list(record.get("evidence")):
            entity = as_dict(item)
            if entity is None:
                continue
            key = tuple(
                _format_value(entity.get(field)) for field in _EVIDENCE_IDENTITY_FIELDS
            )
            target = merged.setdefault(key, {"alerts": []})
            for field, value in entity.items():
                if is_empty(target.get(field)):
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


# Where each API puts an alert's activity bounds, best first.
_FIRST_TIME_FIELDS = (
    "firstEventTime",
    "firstActivityDateTime",
    "alertCreationTime",
    "createdDateTime",
)
_LAST_TIME_FIELDS = (
    "lastEventTime",
    "lastActivityDateTime",
    "alertCreationTime",
    "createdDateTime",
)


def _distinct(records: list[dict[str, Any]], key: str) -> list[str]:
    """Return the sorted distinct non-empty values of ``key`` across ``records``."""
    return sorted({_format_value(r[key]) for r in records if not is_empty(r.get(key))})


def _times(records: list[dict[str, Any]], fields: tuple[str, ...]) -> list[str]:
    """Return each alert's first available timestamp among ``fields``, sorted."""
    return sorted(str(t) for r in records if (t := pick(r, *fields)))


def _tally(labels: list[str]) -> dict[str, int]:
    """Count each label, in first-seen order."""
    counts: dict[str, int] = {}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    return counts


def _accounts(evidence: list[dict[str, Any]]) -> list[str]:
    """Return the distinct domain-qualified account names found in the evidence."""
    accounts = {
        "\\".join(str(part) for part in (e.get("domainName"), e["accountName"]) if part)
        for e in evidence
        if e.get("accountName")
    }
    return sorted(accounts)


def _render_summary(
    records: list[dict[str, Any]], evidence: list[dict[str, Any]]
) -> list[str]:
    """Summarise the incident across its alerts (time span, machines, users, statuses)."""
    first_times = _times(records, _FIRST_TIME_FIELDS)
    last_times = _times(records, _LAST_TIME_FIELDS)
    summary: dict[str, Any] = {
        "alerts": len(records),
        "firstActivity": first_times[0] if first_times else None,
        "lastActivity": last_times[-1] if last_times else None,
    }
    for label, key in (
        ("severities", "severity"),
        ("statuses", "status"),
        ("classifications", "classification"),
        ("determinations", "determination"),
        ("categories", "category"),
        ("detectionSources", "detectionSource"),
    ):
        summary[label] = _distinct(records, key)
    summary["mitreTechniques"] = sorted(
        {str(t) for r in records for t in as_list(r.get("mitreTechniques"))}
    )
    summary["machines"] = sorted(
        set(_distinct(records, "computerDnsName"))
        | {str(e["deviceDnsName"]) for e in evidence if e.get("deviceDnsName")}
    )
    summary["accounts"] = _accounts(evidence)
    summary["evidence"] = _tally(
        [str(e.get("entityType", "Unknown")) for e in evidence]
    )
    summary["verdicts"] = _tally(
        [
            f"{e['verdict']}/{e.get('remediationStatus', '?')}"
            for e in evidence
            if e.get("verdict")
        ]
    )
    summary["titles"] = [r.get("title", "Unknown alert") for r in records]
    lines = _format_fields(summary, "", first=tuple(summary))
    return ["", "SUMMARY", "-------", *lines]


def _render_machines(machines: dict[str, Any]) -> list[str]:
    """Render the incident's machines (the devices of the portal's assets tab)."""
    lines = ["", f"MACHINES ({len(machines)})", "--------"]
    for machine_id, value in machines.items():
        record = as_dict(value) or {}
        if set(record) == {"error"}:
            lines.append(f"#{machine_id}: unavailable ({record['error']})")
            continue
        lines.append(f"#{machine_id}")
        lines += _format_fields(
            record, "  ", first=("computerDnsName",), skip={"id", "@odata.context"}
        )
    return lines


def _render_evidence(evidence: list[dict[str, Any]]) -> list[str]:
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
        lines += _format_fields(entity, "    ", first=("alerts",), skip={"entityType"})
    return lines


def _render_comments(comments: Any) -> list[str]:
    """Render the analyst comments of an alert."""
    entries = [as_dict(item) for item in as_list(comments)]
    if not entries:
        return []
    lines = ["comments:"]
    for comment in entries:
        if comment is not None:
            author = pick(comment, "createdBy", "createdByDisplayName") or "?"
            when = pick(comment, "createdTime", "createdDateTime") or "?"
            lines.append(f"  - [{when}] {author}: {comment.get('comment', '')}")
    return lines


def _render_related(related: dict[str, Any]) -> list[str]:
    """Render the entities fetched from /api/alerts/{id}/<entity>."""
    lines: list[str] = []
    for entity in RELATED_ENTITIES:
        if entity not in related:
            continue
        value = related[entity]
        record = as_dict(value)
        title = f"related {entity}"
        if record is not None and set(record) == {"error"}:
            lines.append(f"{title}: unavailable ({record['error']})")
        elif is_empty(value):
            lines.append(f"{title}: none")
        elif isinstance(value, list):
            items = as_list(value)
            lines.append(f"{title} ({len(items)}):")
            for number, item in enumerate(items, start=1):
                lines.append(f"  #{number}")
                item_record = as_dict(item)
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
