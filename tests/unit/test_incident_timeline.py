"""Unit tests for the Advanced Hunting incident timeline."""

from datetime import datetime, timezone

from check_msdefender.core.exceptions import DefenderAPIError
from check_msdefender.services.incident_timeline import (
    TimelineBuilder,
    TimelineRequest,
    parse_time,
    printable,
    render_timeline,
    window,
)

DEV = "dev-1"
START = datetime(2026, 10, 7, 16, 20, tzinfo=timezone.utc)
END = datetime(2026, 10, 7, 16, 45, tzinfo=timezone.utc)


class FakeHunting:
    """Answer hunting queries by table, recording every query."""

    def __init__(self, children=None, rows=None, failing=(), count=None):
        """Script the descendants per parent pid, the rows per table and the failing tables."""
        self.children = children or {}
        self.rows = rows or {}
        self.failing = set(failing)
        self.count = count
        self.queries = []

    def run_hunting_query(self, query):
        """Return scripted rows for ``query``."""
        self.queries.append(query)
        table = query.split(" ", 1)[0]
        if table in self.failing:
            raise DefenderAPIError("Graph API 400 Bad Request")
        if query.endswith("| count"):
            return [{"Count@odata.type": "#Int64", "Count": self.count}]
        if "| distinct DeviceId, ProcessId" in query:
            found = []
            for parent, kids in self.children.items():
                if f'"{DEV}:{parent}"' in query:
                    found += [{"DeviceId": DEV, "ProcessId": kid} for kid in kids]
            return found
        return self.rows.get(table, [])


def _request(**kwargs):
    """Build a timeline request on DEV with one seed process."""
    defaults = {"start": START, "end": END, "seeds": {(DEV, 100)}, "devices": {DEV}}
    defaults.update(kwargs)
    return TimelineRequest(**defaults)


class TestHelpers:
    """Tests for the time and text helpers."""

    def test_parse_time_seven_digit_fraction(self):
        """The APIs send 7 fractional digits; they are cut to what Python parses."""
        moment = parse_time("2026-10-07T16:34:16.5632412Z")
        assert moment == datetime(2026, 10, 7, 16, 34, 16, 563241, tzinfo=timezone.utc)

    def test_parse_time_rejects_garbage(self):
        """Anything that is not a timestamp gives None."""
        assert parse_time(None) is None
        assert parse_time("") is None
        assert parse_time("yesterday") is None

    def test_parse_time_naive_is_utc(self):
        """A timestamp without zone is taken as UTC."""
        assert parse_time("2026-10-07T16:00:00").tzinfo == timezone.utc

    def test_window_widens_both_sides(self):
        """The activity span is widened by the margin on both sides."""
        start, end = window(START, END, 10)
        assert start == datetime(2026, 10, 7, 16, 10, tzinfo=timezone.utc)
        assert end == datetime(2026, 10, 7, 16, 55, tzinfo=timezone.utc)

    def test_printable_escapes_control_characters(self):
        """A NUL (REG_MULTI_SZ data) is escaped; newlines only when asked."""
        assert printable("a\x00b\nc") == "a\\x00b\nc"
        assert printable("a\nb", keep_newlines=False) == "a\\x0ab"


class TestTimelineBuilder:
    """Tests for the hunting queries and the collected rows."""

    def test_descendants_followed_generation_by_generation(self):
        """Children and grandchildren of the seeds are followed, up to three levels."""
        hunting = FakeHunting(children={100: [200], 200: [300], 300: [400], 400: [500]})

        timeline = TimelineBuilder(hunting).build(_request())

        assert timeline["processes"] == [f"{DEV}:{pid}" for pid in (100, 200, 300, 400)]

    def test_queries_scoped_to_window_and_devices(self):
        """Every query is bound to the time window and the incident's devices."""
        hunting = FakeHunting()

        TimelineBuilder(hunting).build(_request())

        assert hunting.queries
        for query in hunting.queries:
            assert (
                "datetime(2026-10-07T16:20:00.000000Z) .. datetime(2026-10-07T16:45:00"
                in query
            )
            assert f'DeviceId in ("{DEV}")' in query

    def test_table_filters(self):
        """Tables follow the processes; hashes, logons and Defender events are kept too."""
        hunting = FakeHunting()

        TimelineBuilder(hunting).build(_request(sha1s={"abc"}))

        by_table = {q.split(" ", 1)[0]: q for q in hunting.queries if "| project" in q}
        assert set(by_table) == {
            "DeviceProcessEvents",
            "DeviceFileEvents",
            "DeviceNetworkEvents",
            "DeviceRegistryEvents",
            "DeviceImageLoadEvents",
            "DeviceLogonEvents",
            "DeviceEvents",
        }
        assert (
            f'tostring(InitiatingProcessId)) in ("{DEV}:100")'
            in by_table["DeviceNetworkEvents"]
        )
        assert 'SHA1 in ("abc")' in by_table["DeviceFileEvents"]
        assert "SHA1 in" not in by_table["DeviceNetworkEvents"]
        assert "where (true)" in by_table["DeviceLogonEvents"]
        assert "ActionType startswith 'Antivirus'" in by_table["DeviceEvents"]

    def test_rows_cleaned_and_truncation_counted(self):
        """OData annotations and empty cells go; a cut table reports its real total."""
        rows = [
            {
                "Timestamp": f"2026-10-07T16:30:0{i}Z",
                "ProcessId@odata.type": "#Int64",
                "X": "",
            }
            for i in range(3)
        ]
        hunting = FakeHunting(rows={"DeviceFileEvents": rows}, count=1965)

        timeline = TimelineBuilder(hunting).build(_request(limit=2))

        files = timeline["tables"]["DeviceFileEvents"]
        assert files["rows"] == [
            {"Timestamp": "2026-10-07T16:30:00Z"},
            {"Timestamp": "2026-10-07T16:30:01Z"},
        ]
        assert files["truncated"] is True
        assert files["total"] == 1965
        assert "total" not in timeline["tables"]["DeviceNetworkEvents"]

    def test_failing_table_recorded(self):
        """A table whose query fails is an error entry; the others are still collected."""
        hunting = FakeHunting(failing={"DeviceRegistryEvents"})

        timeline = TimelineBuilder(hunting).build(_request())

        assert "400 Bad Request" in timeline["tables"]["DeviceRegistryEvents"]["error"]
        assert timeline["tables"]["DeviceFileEvents"] == {
            "rows": [],
            "truncated": False,
        }

    def test_no_process_no_hash_skips_process_tables(self):
        """Without seed or hash, only logons and Defender events can be selected."""
        hunting = FakeHunting()

        timeline = TimelineBuilder(hunting).build(_request(seeds=set()))

        assert set(timeline["tables"]) == {"DeviceLogonEvents", "DeviceEvents"}


class TestRenderTimeline:
    """Tests for the timeline text."""

    def test_events_merged_chronologically(self):
        """All tables are merged in time order, one line per event."""
        timeline = {
            "start": "S",
            "end": "E",
            "limit": 500,
            "processes": ["dev-1:100"],
            "tables": {
                "DeviceFileEvents": {
                    "rows": [
                        {
                            "Timestamp": "2026-10-07T16:30:02Z",
                            "DeviceName": "q.tld",
                            "ActionType": "FileCreated",
                            "InitiatingProcessFileName": "choco.exe",
                            "InitiatingProcessId": 100,
                            "FolderPath": "C:\\x\ny",
                        }
                    ],
                    "truncated": True,
                    "total": 1965,
                },
                "DeviceProcessEvents": {
                    "rows": [
                        {
                            "Timestamp": "2026-10-07T16:30:01Z",
                            "DeviceName": "q.tld",
                            "ActionType": "ProcessCreated",
                            "InitiatingProcessFileName": "powershell.exe",
                            "InitiatingProcessId": 99,
                            "FileName": "choco.exe",
                            "ProcessId": 100,
                        }
                    ],
                    "truncated": False,
                },
                "DeviceRegistryEvents": {"error": "Graph API 400"},
            },
        }

        lines = render_timeline(timeline)

        assert "File: 1 event(s) (first 1 of 1965)" in lines
        assert "Process: 1 event(s)" in lines
        assert "Registry: unavailable (Graph API 400)" in lines
        events = [line for line in lines if line.startswith("2026-")]
        assert events == [
            (
                "2026-10-07T16:30:01Z q.tld [Process] ProcessCreated by powershell.exe(99)"
                " :: FileName=choco.exe; ProcessId=100"
            ),
            (
                "2026-10-07T16:30:02Z q.tld [File] FileCreated by choco.exe(100)"
                " :: FolderPath=C:\\x\\x0ay"
            ),
        ]

    def test_empty_timeline(self):
        """No event is said plainly."""
        lines = render_timeline(
            {"start": "S", "end": "E", "limit": 5, "processes": [], "tables": {}}
        )
        assert lines[-1] == "no event"
