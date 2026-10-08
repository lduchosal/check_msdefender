"""Incident detail service: gather everything known about one incident."""

from __future__ import annotations

import re
from typing import Any, Protocol

from check_msdefender.core.exceptions import DefenderAPIError, ValidationError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import DefenderClientProtocol
from check_msdefender.services.incident_report import (
    RELATED_ENTITIES,
    as_dict,
    as_list,
    pick,
    render_report,
)
from check_msdefender.services.incident_timeline import (
    HuntingClientProtocol,
    TimelineBuilder,
    TimelineRequest,
    parse_time,
    window,
)

# Graph evidence nests the file, image and account of an entity; their fields are lifted to
# the top level (under these prefixes) so both APIs render and deduplicate the same way.
_GRAPH_NESTED_PREFIXES = {
    "fileDetails": "",
    "imageFile": "",
    "userAccount": "",
    "parentProcessImageFile": "parentProcess",
}

# A GUID is what people paste from the portal URL bar; it is never an incidentId.
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _flatten_graph_evidence(item: dict[str, Any]) -> dict[str, Any]:
    """Reshape one Graph evidence like an MDE one: ``entityType`` from ``@odata.type``
    (``#microsoft.graph.security.fileEvidence`` -> ``File``) and nested details lifted up.
    """
    kind = str(item.get("@odata.type", "")).rsplit(".", 1)[-1].removesuffix("Evidence")
    flat: dict[str, Any] = {"entityType": kind[:1].upper() + kind[1:] or "Unknown"}
    lifted: dict[str, Any] = {}
    for key, value in item.items():
        prefix = _GRAPH_NESTED_PREFIXES.get(key)
        nested = as_dict(value)
        if key == "@odata.type":
            continue
        if prefix is None or nested is None:
            flat[key] = value
            continue
        for sub_key, sub_value in nested.items():
            name = prefix + sub_key[:1].upper() + sub_key[1:] if prefix else sub_key
            lifted.setdefault(name, sub_value)
    # Top-level fields win over lifted ones of the same name.
    return lifted | flat


def _machine_ids(alerts: list[dict[str, Any]]) -> list[str]:
    """Return the MDE device ids of an incident, from its alerts (MDE) or evidence (Graph)."""
    machine_ids: set[str] = set()
    for alert in alerts:
        if alert.get("machineId"):
            machine_ids.add(str(alert["machineId"]))
        for item in as_list(alert.get("evidence")):
            device = (as_dict(item) or {}).get("mdeDeviceId")
            if device:
                machine_ids.add(str(device))
    return sorted(machine_ids)


class GraphClientProtocol(HuntingClientProtocol, Protocol):
    """The Graph security calls the incident report needs."""

    def get_security_incident(self, incident_id: int) -> dict[str, Any]:
        """Get an incident with its alerts."""
        ...


class IncidentDetailService:
    """Collect an incident's alerts, evidence and related entities, and render them as text."""

    def __init__(
        self,
        defender_client: DefenderClientProtocol,
        verbose_level: int = 0,
        graph_client: GraphClientProtocol | None = None,
        window_minutes: int = 10,
        timeline_limit: int = 500,
    ) -> None:
        """
        Initialize with the Defender client and, optionally, the Graph client.

        Without a Graph client the report comes from the MDE alerts API alone and has no timeline.
        ``window_minutes`` widens the incident's activity span for the timeline; ``timeline_limit``
        caps the events kept per hunting table (0 disables the timeline).
        """
        self.defender = defender_client
        self.graph = graph_client
        self.window_minutes = window_minutes
        self.timeline_limit = timeline_limit
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
        Gather the incident, its alerts (with evidence), its machines and its timeline.

        The Graph incidents API is the main source; when it cannot be read the MDE alerts API
        stands in, with each alert's related entities. A failure on any secondary call is
        recorded in the report instead of aborting it: the point of the report is debugging,
        and a partial picture beats none.

        Raises:
            ValidationError: If no alert belongs to the incident.
        """
        self.logger.method_entry("collect", incident_id=incident_id)

        data: dict[str, Any] = {"incidentId": incident_id}
        alerts = self._collect_alerts(incident_id, data)
        if not alerts:
            raise ValidationError(f"No alert found for incident {incident_id}")
        alerts.sort(
            key=lambda alert: str(pick(alert, "alertCreationTime", "createdDateTime"))
        )
        data["alerts"] = alerts
        data["machines"] = {
            mid: self._fetch_machine(mid) for mid in _machine_ids(alerts)
        }
        data["timeline"] = self._build_timeline(alerts)

        self.logger.method_exit(
            "collect", f"{len(alerts)} alert(s) from {data['source']}"
        )
        return data

    def _collect_alerts(
        self, incident_id: int, data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Read the alerts from Graph, or from MDE when Graph is unavailable; fill ``data``."""
        incident = self._fetch_graph_incident(incident_id, data)
        if incident is not None:
            alerts = [dict(alert) for alert in as_list(incident.pop("alerts", []))]
            for alert in alerts:
                alert["evidence"] = [
                    _flatten_graph_evidence(entity)
                    for item in as_list(alert.get("evidence"))
                    if (entity := as_dict(item)) is not None
                ]
            data.update(source="graph", incident=incident, related={})
        else:
            alerts = [
                dict(alert)
                for alert in self.defender.get_incident_alerts(incident_id).get(
                    "value", []
                )
            ]
            data.update(source="mde", related=self._fetch_all_related(alerts))
        return alerts

    def _fetch_graph_incident(
        self, incident_id: int, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Fetch the Graph incident, or None (with the reason in ``data``) to fall back."""
        if self.graph is None:
            return None
        try:
            return dict(self.graph.get_security_incident(incident_id))
        except DefenderAPIError as e:
            self.logger.info(f"Graph incident unavailable, falling back to MDE: {e}")
            data["graphError"] = str(e)
            return None

    def _fetch_all_related(
        self, alerts: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Fetch the related entities of every alert (MDE only: Graph evidence has them)."""
        related: dict[str, dict[str, Any]] = {}
        for alert in alerts:
            alert_id = alert.get("id")
            if alert_id:
                related[alert_id] = {
                    entity: self._fetch_related(alert_id, entity)
                    for entity in RELATED_ENTITIES
                }
        return related

    def _build_timeline(self, alerts: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Build the Advanced Hunting timeline around the incident, or None when disabled."""
        if self.graph is None or self.timeline_limit <= 0:
            return None
        times = [
            moment
            for alert in alerts
            for key in (
                "firstEventTime",
                "firstActivityDateTime",
                "lastEventTime",
                "lastActivityDateTime",
                "alertCreationTime",
                "createdDateTime",
            )
            if (moment := parse_time(alert.get(key))) is not None
        ]
        if not times:
            return {"error": "no activity time on the alerts"}
        start, end = window(min(times), max(times), self.window_minutes)
        request = TimelineRequest(start=start, end=end, limit=self.timeline_limit)
        for alert in alerts:
            alert_device = alert.get("machineId")
            for item in as_list(alert.get("evidence")):
                entity = as_dict(item) or {}
                device = entity.get("mdeDeviceId") or alert_device
                if device:
                    request.devices.add(str(device))
                if entity.get("entityType") == "Process" and device:
                    for key in ("processId", "parentProcessId"):
                        if isinstance(entity.get(key), int):
                            request.seeds.add((str(device), entity[key]))
                if entity.get("entityType") == "File" and entity.get("sha1"):
                    request.sha1s.add(str(entity["sha1"]))
            if alert_device:
                request.devices.add(str(alert_device))
        if not request.devices:
            return {"error": "no device in the incident"}
        assert self.graph is not None
        return TimelineBuilder(self.graph).build(request)

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
        record = as_dict(result)
        if record is not None and "value" in record:
            return record["value"]
        return result

    def render(self, data: dict[str, Any]) -> str:
        """Render collected incident data as a structured plain-text report."""
        return render_report(data)
