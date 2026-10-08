"""
Incident timeline: the device activity around an incident, from Advanced Hunting.

The portal's attack story is not exposed by any API; this rebuilds its substance from the
Device*Events tables. Raw activity is far too large to hand over whole (a package install alone
writes thousands of file events), so the timeline follows the processes the incident points at: the
evidence processes and their parents are the seeds, their descendants are added from
DeviceProcessEvents, and every table is then read for what those processes did. Files whose hash is
in evidence are kept whatever process touched them; logons and Defender's own events (antivirus,
ASR, exploit guard...) are kept whole, since they are rare and telling.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from operator import itemgetter
from typing import Any, Protocol

from check_msdefender.core.exceptions import DefenderAPIError

# How many rounds of children are followed from the seed processes.
_DESCENDANT_DEPTH = 3

# Per table: the columns kept for the report, besides the common ones.
_TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "DeviceProcessEvents": (
        "FileName",
        "ProcessId",
        "ProcessCommandLine",
        "FolderPath",
        "SHA1",
        "AccountName",
        "InitiatingProcessParentFileName",
        "InitiatingProcessParentId",
    ),
    "DeviceFileEvents": ("FolderPath", "PreviousFolderPath", "SHA1", "FileSize"),
    "DeviceNetworkEvents": (
        "RemoteIP",
        "RemotePort",
        "RemoteUrl",
        "Protocol",
        "LocalPort",
    ),
    "DeviceRegistryEvents": (
        "RegistryKey",
        "RegistryValueName",
        "RegistryValueData",
        "PreviousRegistryValueData",
    ),
    "DeviceImageLoadEvents": ("FolderPath", "SHA1"),
    "DeviceLogonEvents": ("AccountDomain", "AccountName", "LogonType", "RemoteIP"),
    "DeviceEvents": (
        "FileName",
        "FolderPath",
        "SHA1",
        "RemoteIP",
        "RemoteUrl",
        "AdditionalFields",
    ),
}

_COMMON_COLUMNS = (
    "Timestamp",
    "DeviceId",
    "DeviceName",
    "ActionType",
    "InitiatingProcessFileName",
    "InitiatingProcessId",
)

# DeviceEvents action types kept even when no followed process raised them.
_DEFENDER_ACTIONS = (
    "Antivirus",
    "Asr",
    "ExploitGuard",
    "SmartScreen",
    "Tamper",
    "Firewall",
)


# Control characters break text tools (a NUL makes grep call the report binary); REG_MULTI_SZ
# registry data carries them. Newlines are kept by ``printable`` unless asked otherwise.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CONTROL_AND_NEWLINE_RE = re.compile(r"[\x00-\x1f\x7f]")


def printable(text: str, keep_newlines: bool = True) -> str:
    """Escape the control characters of ``text`` as hex escapes (newlines optionally kept)."""
    pattern = _CONTROL_RE if keep_newlines else _CONTROL_AND_NEWLINE_RE
    return pattern.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


class HuntingClientProtocol(Protocol):
    """The Advanced Hunting call the timeline needs."""

    def run_hunting_query(self, query: str) -> list[dict[str, Any]]:
        """Run a KQL query and return its rows."""
        ...


@dataclass
class TimelineRequest:
    """What the timeline is built from."""

    start: datetime
    end: datetime
    # (DeviceId, ProcessId) of the evidence processes and of their parents.
    seeds: set[tuple[str, int]] = field(default_factory=lambda: set[tuple[str, int]]())
    devices: set[str] = field(default_factory=lambda: set[str]())
    sha1s: set[str] = field(default_factory=lambda: set[str]())
    limit: int = 500


def _kql_datetime(moment: datetime) -> str:
    """Render ``moment`` as a KQL datetime literal."""
    return (
        f"datetime({moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
    )


def _kql_list(values: Iterable[str]) -> str:
    """Render strings as a KQL dynamic list, quoted and escaped."""
    quoted = ", ".join(
        '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"' for v in values
    )
    return f"({quoted})"


def _process_keys(pairs: Iterable[tuple[str, int]]) -> list[str]:
    """Turn (DeviceId, ProcessId) pairs into the ``device:pid`` keys the queries match."""
    return sorted(f"{device}:{pid}" for device, pid in pairs)


def parse_time(value: Any) -> datetime | None:
    """Parse an API timestamp (ISO 8601, any sub-second precision), or None."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # Python < 3.11 accepts at most 6 fractional digits; the APIs send up to 7.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        text = f"{head}.{digits[:6]}{tail[len(digits) :]}"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def window(first: datetime, last: datetime, minutes: int) -> tuple[datetime, datetime]:
    """Widen the incident's activity span by ``minutes`` on both sides."""
    margin = timedelta(minutes=minutes)
    return first - margin, last + margin


class TimelineBuilder:
    """Query Advanced Hunting for the activity of the processes an incident points at."""

    def __init__(self, hunting: HuntingClientProtocol) -> None:
        """Initialize with the client that runs the KQL queries."""
        self.hunting = hunting

    def build(self, request: TimelineRequest) -> dict[str, Any]:
        """
        Collect the timeline rows, per table, in chronological order.

        A table whose query fails is recorded as an error; the others are still reported.
        """
        scope = (
            f"Timestamp between ({_kql_datetime(request.start)} .. "
            f"{_kql_datetime(request.end)}) and DeviceId in {_kql_list(request.devices)}"
        )
        processes = self._follow_processes(scope, request)
        keys = _process_keys(processes)

        tables: dict[str, Any] = {}
        for table, columns in _TABLE_COLUMNS.items():
            condition = self._condition(table, keys, request)
            if condition is None:
                continue
            query = (
                f"{table} | where {scope} | where {condition} "
                f"| project {', '.join(_COMMON_COLUMNS + columns)} "
                f"| order by Timestamp asc | take {request.limit + 1}"
            )
            try:
                rows = self.hunting.run_hunting_query(query)
            except DefenderAPIError as e:
                tables[table] = {"error": str(e)}
                continue
            entry: dict[str, Any] = {
                "rows": [_clean(row) for row in rows[: request.limit]],
                "truncated": len(rows) > request.limit,
            }
            if entry["truncated"]:
                entry["total"] = self._count(
                    f"{table} | where {scope} | where {condition}"
                )
            tables[table] = entry

        return {
            "start": request.start.isoformat(),
            "end": request.end.isoformat(),
            "limit": request.limit,
            "processes": keys,
            "tables": tables,
        }

    def _count(self, query: str) -> int | None:
        """Count the rows ``query`` selects, or None if the count cannot be had."""
        try:
            rows = self.hunting.run_hunting_query(f"{query} | count")
        except DefenderAPIError:
            return None
        count = rows[0].get("Count") if rows else None
        return count if isinstance(count, int) else None

    def _follow_processes(
        self, scope: str, request: TimelineRequest
    ) -> set[tuple[str, int]]:
        """Add to the seeds the processes they started, a few generations down."""
        followed = request.seeds.copy()
        frontier = request.seeds.copy()
        for _ in range(_DESCENDANT_DEPTH):
            if not frontier:
                break
            query = (
                f"DeviceProcessEvents | where {scope} "
                f"| where strcat(DeviceId, ':', tostring(InitiatingProcessId)) in "
                f"{_kql_list(_process_keys(frontier))} "
                "| distinct DeviceId, ProcessId"
            )
            try:
                rows = self.hunting.run_hunting_query(query)
            except DefenderAPIError:
                break
            children = {
                (str(row["DeviceId"]), int(row["ProcessId"]))
                for row in rows
                if row.get("DeviceId") and isinstance(row.get("ProcessId"), int)
            }
            frontier = children - followed
            followed |= children
        return followed

    def _condition(
        self, table: str, keys: list[str], request: TimelineRequest
    ) -> str | None:
        """Return the KQL filter selecting what a table contributes, or None for nothing."""
        conditions: list[str] = []
        if keys:
            key_list = _kql_list(keys)
            conditions.append(
                f"strcat(DeviceId, ':', tostring(InitiatingProcessId)) in {key_list}"
            )
            if table == "DeviceProcessEvents":
                conditions.append(
                    f"strcat(DeviceId, ':', tostring(ProcessId)) in {key_list}"
                )
        if request.sha1s and table in ("DeviceFileEvents", "DeviceProcessEvents"):
            conditions.append(f"SHA1 in {_kql_list(sorted(request.sha1s))}")
        if table == "DeviceLogonEvents":
            conditions = ["true"]
        if table == "DeviceEvents":
            actions = " or ".join(
                f"ActionType startswith '{a}'" for a in _DEFENDER_ACTIONS
            )
            conditions.append(f"({actions})")
        return " or ".join(f"({c})" for c in conditions) if conditions else None


def _clean(row: dict[str, Any]) -> dict[str, Any]:
    """Drop the OData type annotations and empty cells of a hunting row."""
    return {
        key: value
        for key, value in row.items()
        if "@odata" not in key and value not in (None, "", [], {})
    }


def render_timeline(timeline: dict[str, Any]) -> list[str]:
    """Render the timeline as one line per event, all tables merged chronologically."""
    lines = [
        "",
        "TIMELINE (Advanced Hunting)",
        "--------",
        f"window: {timeline['start']} .. {timeline['end']}",
        f"followed processes (device:pid): {len(timeline['processes'])}",
    ]
    events: list[tuple[str, str, dict[str, Any]]] = []
    for table, result in timeline["tables"].items():
        short = table.removeprefix("Device").removesuffix("Events") or "Device"
        if "error" in result:
            lines.append(f"{short}: unavailable ({result['error']})")
            continue
        rows: list[dict[str, Any]] = result["rows"]
        note = ""
        if result["truncated"]:
            total = result.get("total")
            note = f" (first {len(rows)} of {total if total is not None else 'more'})"
        lines.append(f"{short}: {len(rows)} event(s){note}")
        events.extend((str(row.get("Timestamp", "")), short, row) for row in rows)

    lines.append("")
    if not events:
        return [*lines, "no event"]
    for timestamp, short, row in sorted(events, key=itemgetter(0)):
        actor = f"{row.get('InitiatingProcessFileName', '?')}({row.get('InitiatingProcessId', '?')})"
        details = "; ".join(
            f"{key}={printable(str(value), keep_newlines=False)}"
            for key, value in row.items()
            if key not in _COMMON_COLUMNS
        )
        device = row.get("DeviceName", row.get("DeviceId", "?"))
        lines.append(
            f"{timestamp} {device} [{short}] {row.get('ActionType', '?')} by {actor}"
            + (f" :: {details}" if details else "")
        )
    return lines
