"""Unit tests for the path-based staleness verifier."""

from unittest.mock import Mock

from check_msdefender.core.models import SoftwareEntry
from check_msdefender.core.path_probe import PathProbeError, PathState, PathVerdict
from check_msdefender.services.products_verifier import (
    REASON_REMOVED,
    REASON_UPGRADED,
    ProductsVerifier,
)


def _entry(version="3.0.15", paths=(), registry=()):
    """Build one aggregated software entry as ProductsService groups them."""
    return SoftwareEntry(
        name="openssl",
        version=version,
        vendor="openssl",
        cves=[],
        paths=set(paths),
        registryPaths=set(registry),
        max_cvss=0.0,
        severities=[],
    )


def _probe(verdicts):
    """Build a probe returning the given verdicts."""
    probe = Mock()
    probe.probe.return_value = verdicts
    return probe


class TestProductsVerifier:
    """What the host says decides; anything it cannot say keeps the product counted."""

    def test_all_paths_absent_is_stale_removed(self):
        """Every path gone ⇒ the entry is a leftover of Defender's snapshot."""
        software = {"k": _entry(paths=["c:\\a.dll", "c:\\b.dll"])}
        verdicts = {
            "c:\\a.dll": PathVerdict(PathState.ABSENT),
            "c:\\b.dll": PathVerdict(PathState.ABSENT),
        }

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale["k"].reason == REASON_REMOVED
        assert outcome.stale["k"].evidence == "c:\\a.dll"
        assert outcome.unverified == 0
        assert outcome.error is None

    def test_matching_version_on_disk_keeps_the_entry(self):
        """The file is there, in the reported version: this is a real finding."""
        software = {"k": _entry(paths=["c:\\a.dll"])}
        verdicts = {"c:\\a.dll": PathVerdict(PathState.PRESENT, "3.0.15")}

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale == {}
        assert outcome.unverified == 0

    def test_newer_version_on_disk_is_stale_upgraded(self):
        """Patched since the export: the vulnerable binary is not there any more."""
        software = {"k": _entry(version="3.6.1.0", paths=["c:\\a.dll"])}
        verdicts = {"c:\\a.dll": PathVerdict(PathState.PRESENT, "3.6.3")}

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale["k"].reason == REASON_UPGRADED
        assert "3.6.3" in outcome.stale["k"].evidence

    def test_older_version_on_disk_keeps_the_entry(self):
        """A version below the reported one still confirms a vulnerable binary."""
        software = {"k": _entry(version="3.6.1.0", paths=["c:\\a.dll"])}
        verdicts = {"c:\\a.dll": PathVerdict(PathState.PRESENT, "3.5.0")}

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale == {}

    def test_one_copy_still_matching_keeps_the_entry(self):
        """Two copies, one deleted and one still vulnerable ⇒ the product is counted."""
        software = {"k": _entry(paths=["c:\\a.dll", "c:\\b.dll"])}
        verdicts = {
            "c:\\a.dll": PathVerdict(PathState.ABSENT),
            "c:\\b.dll": PathVerdict(PathState.PRESENT, "3.0.15"),
        }

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale == {}

    def test_unreadable_version_counts_as_confirming(self):
        """A present file whose version cannot be parsed is never treated as upgraded."""
        software = {"k": _entry(paths=["c:\\a.dll"])}
        verdicts = {"c:\\a.dll": PathVerdict(PathState.PRESENT, "unknown")}

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale == {}

    def test_denied_path_leaves_the_entry_undecided(self):
        """Access denied is not absence: the product stays counted, marked unverified."""
        software = {"k": _entry(paths=["c:\\a.dll", "c:\\b.dll"])}
        verdicts = {
            "c:\\a.dll": PathVerdict(PathState.ABSENT),
            "c:\\b.dll": PathVerdict(PathState.DENIED),
        }

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale == {}
        assert outcome.unverified == 1

    def test_unanswered_path_leaves_the_entry_undecided(self):
        """A path the probe said nothing about is missing evidence, not absence."""
        software = {"k": _entry(paths=["c:\\a.dll"])}

        outcome = ProductsVerifier(_probe({})).verify("h", software)

        assert outcome.stale == {}
        assert outcome.unverified == 1

    def test_registry_only_entry_is_verified_too(self):
        """MSI products expose registry keys instead of files, and those are testable."""
        software = {"k": _entry(registry=["HKEY_LOCAL_MACHINE\\SOFTWARE\\X"])}
        verdicts = {"HKEY_LOCAL_MACHINE\\SOFTWARE\\X": PathVerdict(PathState.ABSENT)}

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale["k"].reason == REASON_REMOVED

    def test_surviving_registry_key_keeps_the_entry(self):
        """The key is still there: the product is still declared installed."""
        software = {"k": _entry(paths=["c:\\a.dll"], registry=["HKLM\\SOFTWARE\\X"])}
        verdicts = {
            "c:\\a.dll": PathVerdict(PathState.ABSENT),
            "HKLM\\SOFTWARE\\X": PathVerdict(PathState.PRESENT),
        }

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert outcome.stale == {}

    def test_entry_without_evidence_is_never_stale(self):
        """No path in the export ⇒ nothing to verify ⇒ the product keeps its score."""
        software = {"k": _entry(paths=["c:\\a.dll"]), "no_evidence": _entry()}
        verdicts = {"c:\\a.dll": PathVerdict(PathState.ABSENT)}

        outcome = ProductsVerifier(_probe(verdicts)).verify("h", software)

        assert set(outcome.stale) == {"k"}
        assert outcome.unverified == 1

    def test_probe_failure_leaves_everything_counted(self):
        """The host could not be questioned: no entry is dropped, and the error is kept."""
        probe = Mock()
        probe.probe.side_effect = PathProbeError("timeout after 20s")
        software = {"k": _entry(paths=["c:\\a.dll"]), "j": _entry(paths=["c:\\b.dll"])}

        outcome = ProductsVerifier(probe).verify("h", software)

        assert outcome.stale == {}
        assert outcome.unverified == 2
        assert outcome.error == "timeout after 20s"

    def test_no_evidence_at_all_skips_the_probe(self):
        """Nothing to ask about ⇒ no remote command is run."""
        probe = Mock()

        outcome = ProductsVerifier(probe).verify("h", {"k": _entry()})

        probe.probe.assert_not_called()
        assert outcome.unverified == 1

    def test_paths_are_submitted_once_and_sorted(self):
        """Two products sharing a path must not make the probe test it twice."""
        probe = _probe({})
        software = {
            "k": _entry(paths=["c:\\b.dll", "c:\\a.dll"]),
            "j": _entry(paths=["c:\\a.dll"]),
        }

        ProductsVerifier(probe).verify("h", software)

        assert probe.probe.call_args[0][1] == ["c:\\a.dll", "c:\\b.dll"]
