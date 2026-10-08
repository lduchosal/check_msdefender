"""Unit tests for IncidentDetailService."""

from unittest.mock import Mock

import pytest

from check_msdefender.core.exceptions import DefenderAPIError, ValidationError
from check_msdefender.services.incident_detail_service import (
    RELATED_ENTITIES,
    IncidentDetailService,
)

ALERTS = {
    "value": [
        {
            "id": "da2_1",
            "incidentId": 199,
            "title": "Second alert",
            "severity": "High",
            "status": "Resolved",
            "computerDnsName": "q.domain.tld",
            "machineId": "mid-1",
            "alertCreationTime": "2026-10-07T16:40:00Z",
            "aadTenantId": "4b0cae28-9de3-4e28-afee-48bb769263ce",
            "evidence": [
                {
                    "entityType": "File",
                    "fileName": "sync.exe",
                    "filePath": "C:\\Users\\jdoe\\AppData",
                    "sha1": "4cadd107",
                    "sha256": "26a564b6",
                    "evidenceCreationTime": "2026-10-07T16:40:01Z",
                }
            ],
        },
        {
            "id": "da1_1",
            "incidentId": 199,
            "title": "A suspicious file was observed",
            "severity": "Medium",
            "status": "New",
            "classification": "FalsePositive",
            "mitreTechniques": ["T1027", "T1105"],
            "computerDnsName": "q.domain.tld",
            "machineId": "mid-1",
            "alertCreationTime": "2026-10-07T16:36:07Z",
            "firstEventTime": "2026-10-07T16:30:50Z",
            "lastEventTime": "2026-10-07T16:34:53Z",
            "description": "line one\nline two",
            "threatName": None,
            "comments": [
                {
                    "comment": "checked, benign installer",
                    "createdBy": "admin@domain.tld",
                    "createdTime": "2026-10-08T07:18:00Z",
                }
            ],
            "evidence": [
                {
                    "entityType": "Process",
                    "fileName": "powershell.exe",
                    "processId": 26596,
                    "processCommandLine": "powershell.exe -File cleanup.ps1",
                    "parentProcessFileName": "cmd.exe",
                    "accountName": "jdoe",
                    "domainName": "domain.tld",
                    "sha256": None,
                },
                {
                    "entityType": "File",
                    "fileName": "sync.exe",
                    "filePath": "C:\\Users\\jdoe\\AppData",
                    "sha1": "4cadd107",
                    "detectionStatus": "Detected",
                    "evidenceCreationTime": "2026-10-07T16:36:07Z",
                },
                {"entityType": "Ip", "ipAddress": "2.56.0.2"},
            ],
        },
    ]
}


MACHINE = {
    "@odata.context": "https://api.security.microsoft.com/api/$metadata#Machines/$entity",
    "id": "mid-1",
    "computerDnsName": "q.domain.tld",
    "osPlatform": "Windows11",
    "riskScore": "Low",
}


def _related(alert_id, entity):
    """Answer the related-entity calls: a 403 on files, lists elsewhere."""
    if entity == "files":
        raise DefenderAPIError("MS Defender API 403 Forbidden after 1 attempt")
    if entity == "ips":
        return {"value": [{"id": "2.56.0.2"}]}
    return {"value": []}


class TestResolveIncidentId:
    """Tests for turning the user reference into an incidentId."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = Mock()
        self.service = IncidentDetailService(self.client)

    def test_integer_is_the_incident_id(self):
        """A number is taken verbatim, without any API call."""
        assert self.service.resolve_incident_id(" 199 ") == 199
        self.client.get_alert.assert_not_called()

    def test_guid_is_rejected(self):
        """A tenant/machine GUID is refused with an explanation, not sent to the API."""
        with pytest.raises(ValidationError, match="looks like a GUID"):
            self.service.resolve_incident_id("4b0cae28-9de3-4e28-afee-48bb769263ce")
        self.client.get_alert.assert_not_called()

    def test_alert_id_resolves_to_its_incident(self):
        """An alert id is replaced by the incident it belongs to."""
        self.client.get_alert.return_value = {"id": "da1_1", "incidentId": 199}

        assert self.service.resolve_incident_id("da1_1") == 199
        self.client.get_alert.assert_called_once_with("da1_1")

    def test_alert_without_incident(self):
        """An alert not correlated into any incident is an error."""
        self.client.get_alert.return_value = {"id": "da1_1"}

        with pytest.raises(ValidationError, match="not attached to any incident"):
            self.service.resolve_incident_id("da1_1")


class TestCollect:
    """Tests for gathering the incident data."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = Mock()
        self.client.get_incident_alerts.return_value = ALERTS
        self.client.get_alert_related.side_effect = _related
        self.client.get_machine_by_id.return_value = MACHINE
        self.service = IncidentDetailService(self.client)

    def test_no_alert_is_an_error(self):
        """An unknown incident has no alert: say so instead of writing an empty report."""
        self.client.get_incident_alerts.return_value = {"value": []}

        with pytest.raises(ValidationError, match="No alert found for incident 42"):
            self.service.collect(42)

    def test_alerts_sorted_chronologically(self):
        """Alerts are reported in creation order, whatever the API order."""
        data = self.service.collect(199)

        assert [a["id"] for a in data["alerts"]] == ["da1_1", "da2_1"]
        self.client.get_incident_alerts.assert_called_once_with(199)

    def test_every_related_entity_is_fetched(self):
        """Each alert gets one call per related entity."""
        data = self.service.collect(199)

        assert set(data["related"]) == {"da1_1", "da2_1"}
        assert set(data["related"]["da1_1"]) == set(RELATED_ENTITIES)
        assert self.client.get_alert_related.call_count == 2 * len(RELATED_ENTITIES)

    def test_related_values_unwrapped_and_errors_recorded(self):
        """Lists lose their OData wrapper; a failed call is kept as an error, not raised."""
        related = self.service.collect(199)["related"]["da1_1"]

        assert related["ips"] == [{"id": "2.56.0.2"}]
        assert "403 Forbidden" in related["files"]["error"]

    def test_machines_fetched_once_per_incident(self):
        """Both alerts share one machine: it is fetched a single time."""
        data = self.service.collect(199)

        assert data["machines"] == {"mid-1": MACHINE}
        self.client.get_machine_by_id.assert_called_once_with("mid-1")

    def test_machine_failure_recorded(self):
        """A machine the API refuses is kept as an error, not raised."""
        self.client.get_machine_by_id.side_effect = DefenderAPIError("404 Not Found")

        data = self.service.collect(199)

        assert data["machines"] == {"mid-1": {"error": "404 Not Found"}}


class TestRender:
    """Tests for the text report."""

    def setup_method(self):
        """Render the fixture incident once."""
        client = Mock()
        client.get_incident_alerts.return_value = ALERTS
        client.get_alert_related.side_effect = _related
        client.get_machine_by_id.return_value = MACHINE
        service = IncidentDetailService(client)
        self.report = service.render(service.collect(199))

    def test_header_and_summary(self):
        """The summary spans every alert of the incident."""
        assert "INCIDENT 199" in self.report
        assert "alerts: 2" in self.report
        assert "firstActivity: 2026-10-07T16:30:50Z" in self.report
        assert 'severities: ["High", "Medium"]' in self.report
        assert 'machines: ["q.domain.tld"]' in self.report
        assert 'accounts: ["domain.tld\\\\jdoe"]' in self.report

    def test_alert_fields(self):
        """Key fields come first and multi-line text is kept whole."""
        assert "ALERT 1/2\n" in self.report
        assert "title: A suspicious file was observed" in self.report
        assert 'mitreTechniques: ["T1027", "T1105"]' in self.report
        assert "  | line one\n  | line two" in self.report
        alert_one = self.report.split("ALERT 1/2")[1].split("ALERT 2/2")[0]
        assert alert_one.index("id: da1_1") < alert_one.index("title:")

    def test_noise_and_empty_fields_left_out(self):
        """Null fields and the tenant id do not clutter the report."""
        assert "threatName" not in self.report
        assert "sha256: None" not in self.report
        assert "aadTenantId" not in self.report

    def test_comments(self):
        """Analyst comments are rendered with author and time."""
        assert (
            "  - [2026-10-08T07:18:00Z] admin@domain.tld: checked, benign installer"
            in self.report
        )

    def test_not_covered_note(self):
        """The report says what the alerts API cannot provide."""
        assert "Not covered (needs the incidents API" in self.report

    def test_machines_section(self):
        """The machine is rendered once, without OData noise."""
        assert "MACHINES (1)" in self.report
        assert "#mid-1\n  computerDnsName: q.domain.tld" in self.report
        assert "osPlatform: Windows11" in self.report
        assert "@odata.context" not in self.report

    def test_evidence_deduplicated_across_alerts(self):
        """The file seen by both alerts is listed once, cited by both, gaps filled."""
        assert "EVIDENCE (3 distinct)" in self.report
        assert 'evidence: {"File": 1, "Ip": 1, "Process": 1}' in self.report
        assert self.report.count("fileName: sync.exe") == 1
        sync = self.report.split("[File]")[1].split("[Ip]")[0]
        assert "alerts: [1, 2]" in sync
        # first copy wins, the later one fills what it lacked
        assert "evidenceCreationTime: 2026-10-07T16:36:07Z" in sync
        assert "sha256: 26a564b6" in sync
        assert "detectionStatus: Detected" in sync

    def test_evidence_grouped_by_type(self):
        """Processes, files and IPs are grouped and numbered, with every populated field."""
        assert "[File]\n  #1" in self.report
        assert "[Ip]\n  #2" in self.report
        assert "[Process]\n  #3" in self.report
        assert "processCommandLine: powershell.exe -File cleanup.ps1" in self.report
        assert "parentProcessFileName: cmd.exe" in self.report
        assert "ipAddress: 2.56.0.2" in self.report

    def test_alerts_cite_evidence_numbers(self):
        """Each alert points to the incident evidence it carries."""
        alert_one = self.report.split("ALERT 1/2")[1].split("ALERT 2/2")[0]
        alert_two = self.report.split("ALERT 2/2")[1]
        assert "evidence: #1, #2, #3" in alert_one
        assert "evidence: #1\n" in alert_two

    def test_related_entities(self):
        """Related entities are rendered, failures say why."""
        assert "related files: unavailable (MS Defender API 403" in self.report
        assert "related ips (1):" in self.report
        assert "related user: none" in self.report
