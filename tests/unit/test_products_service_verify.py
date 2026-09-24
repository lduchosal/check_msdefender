"""Unit tests for ProductsService once a path verifier is wired in."""

from unittest.mock import Mock

from check_msdefender.core.path_probe import PathState, PathVerdict
from check_msdefender.services.products_service import ProductsService
from check_msdefender.services.products_verifier import StaleEntry, VerificationOutcome

_CRITICAL = {
    "deviceId": "m1",
    "softwareName": "python",
    "softwareVersion": "3.7.9.0",
    "softwareVendor": "python",
    "cveId": "CVE-2024-0001",
    "cvssScore": 9.8,
    "vulnerabilitySeverityLevel": "Critical",
    "diskPaths": ["d:\\gone\\python.exe"],
    "registryPaths": [],
}
_MEDIUM = {
    "deviceId": "m1",
    "softwareName": "openssl",
    "softwareVersion": "3.0.15.0",
    "softwareVendor": "openssl",
    "cveId": "CVE-2024-0002",
    "cvssScore": 5.0,
    "vulnerabilitySeverityLevel": "Medium",
    "diskPaths": ["c:\\rider\\libcrypto-3.dll"],
    "registryPaths": [],
}
_STALE_KEY = "python-3.7.9.0-python"


def _verifier(outcome):
    """Build a verifier returning a fixed outcome."""
    verifier = Mock()
    verifier.verify.return_value = outcome
    return verifier


def _service(outcome):
    """Build a ProductsService over the two-product fixture and the given outcome."""
    client = Mock()
    client.get_machine_by_id.return_value = {"computerDnsName": "q.arcantel.ch"}
    client.get_products.return_value = {"value": [_CRITICAL, _MEDIUM]}
    return ProductsService(client, verifier=_verifier(outcome))


def _line(details, needle):
    """Return the first detail line containing the needle."""
    return next(line for line in details if needle in line)


class TestProductsServiceVerification:
    """A verified check reports the net score, and says what it took out."""

    def test_stale_product_leaves_the_score(self):
        """The 100 points of the removed python are not compared to the thresholds."""
        outcome = VerificationOutcome(
            stale={_STALE_KEY: StaleEntry("removed", "d:\\gone\\python.exe")}
        )

        result = _service(outcome).get_result(machine_id="m1")

        assert result["value"] == 5
        assert result["raw_value"] == 105
        assert result["stale_value"] == 100
        assert result["stale_count"] == 1
        assert result["vulnerable_count"] == 1

    def test_summary_line_carries_raw_and_excluded(self):
        """The first line -- the only one Nagios lists -- must not hide the filtering."""
        outcome = VerificationOutcome(
            stale={_STALE_KEY: StaleEntry("removed", "d:\\gone\\python.exe")},
            unverified=2,
        )

        details = _service(outcome).get_result(machine_id="m1")["details"]

        assert details[0] == (
            "1 vulnerable products, score: 5 (raw 105, 1 stale excluded: 100), "
            "2 unverified, path verification: 0 paths, 0 absent, 0 unreadable"
        )

    def test_summary_line_says_the_probe_ran_even_when_nothing_is_excluded(self):
        """A verified check that retires nothing must not read like an unverified one."""
        outcome = VerificationOutcome(
            verdicts={
                "d:\\gone\\python.exe": PathVerdict(PathState.PRESENT, "3.7.9"),
                "c:\\rider\\libcrypto-3.dll": PathVerdict(PathState.DENIED),
                "c:\\old\\libcrypto-3.dll": PathVerdict(PathState.ABSENT),
            }
        )

        details = _service(outcome).get_result(machine_id="m1")["details"]

        assert details[0] == (
            "2 vulnerable products, score: 105, "
            "path verification: 3 paths, 1 absent, 1 unreadable"
        )

    def test_paths_carry_the_verdict_with_the_present_ones_first(self):
        """The path that keeps a product in the score is the one listed first."""
        paths = [
            "c:\\rider\\x64\\python.exe",
            "c:\\rider\\x86\\pythonw.exe",
            "c:\\rider\\aarch64\\python.exe",
            "c:\\denied\\python.exe",
        ]
        record = _CRITICAL | {"diskPaths": paths}
        outcome = VerificationOutcome(
            verdicts={
                paths[0]: PathVerdict(PathState.ABSENT),
                paths[1]: PathVerdict(PathState.ABSENT),
                paths[2]: PathVerdict(PathState.PRESENT, "3.12.9"),
                paths[3]: PathVerdict(PathState.DENIED),
            }
        )
        client = Mock()
        client.get_machine_by_id.return_value = {"computerDnsName": "q.arcantel.ch"}
        client.get_products.return_value = {"value": [record]}

        details = ProductsService(client, verifier=_verifier(outcome)).get_result(
            machine_id="m1"
        )["details"]

        assert details[3:7] == [
            " - [PRESENT 3.12.9] c:\\rider\\aarch64\\python.exe",
            " - [DENIED] c:\\denied\\python.exe",
            " - [ABSENT] c:\\rider\\x64\\python.exe",
            " - [ABSENT] c:\\rider\\x86\\pythonw.exe",
        ]

    def test_path_list_is_truncated_after_the_ordering(self):
        """Beyond four paths the absent ones are the ones folded away."""
        paths = [f"c:\\gone{index}\\python.exe" for index in range(5)]
        record = _CRITICAL | {"diskPaths": [*paths, "c:\\z\\python.exe"]}
        verdicts = {path: PathVerdict(PathState.ABSENT) for path in paths}
        verdicts["c:\\z\\python.exe"] = PathVerdict(PathState.PRESENT)
        client = Mock()
        client.get_machine_by_id.return_value = {"computerDnsName": "q.arcantel.ch"}
        client.get_products.return_value = {"value": [record]}

        details = ProductsService(
            client, verifier=_verifier(VerificationOutcome(verdicts=verdicts))
        ).get_result(machine_id="m1")["details"]

        assert details[3] == " - [PRESENT] c:\\z\\python.exe"
        assert details[7] == " - .. (+2 more)"

    def test_excluded_products_stay_visible_with_their_reason(self):
        """Masked, not deleted: the operator must be able to audit what was dropped."""
        outcome = VerificationOutcome(
            stale={_STALE_KEY: StaleEntry("removed", "d:\\gone\\python.exe")}
        )

        details = _service(outcome).get_result(machine_id="m1")["details"]

        assert _line(details, "Stale entries excluded") == (
            "Stale entries excluded (1 products, score: 100):"
        )
        assert _line(details, "python 3.7.9.0") == (
            " - python 3.7.9.0 (python) - Score: 100 - removed: d:\\gone\\python.exe"
        )

    def test_perfdata_metrics_keep_the_raw_curve(self):
        """Raw/stale/unverified are published next to the net score."""
        outcome = VerificationOutcome(
            stale={_STALE_KEY: StaleEntry("removed", "d:\\gone\\python.exe")},
            unverified=1,
        )

        result = _service(outcome).get_result(machine_id="m1")

        assert result["metrics"] == [("raw", 105), ("stale", 100), ("unverified", 1)]

    def test_probe_failure_keeps_the_raw_score(self):
        """Fail closed: an unreachable host reports the full score, and says why."""
        outcome = VerificationOutcome(unverified=2, error="timeout after 20s")

        result = _service(outcome).get_result(machine_id="m1")

        assert result["value"] == 105
        assert result["verify_error"] == "timeout after 20s"
        assert result["details"][0] == (
            "2 vulnerable products, score: 105 "
            "(path verification FAILED: timeout after 20s)"
        )
        assert result["metrics"] == [("raw", 105), ("stale", 0), ("unverified", 2)]

    def test_verifier_is_asked_about_the_resolved_host(self):
        """The probe targets the machine Defender resolved, not the raw argument."""
        verifier = _verifier(VerificationOutcome())
        client = Mock()
        client.get_machine_by_id.return_value = {"computerDnsName": "q.arcantel.ch"}
        client.get_products.return_value = {"value": [_MEDIUM]}

        ProductsService(client, verifier=verifier).get_result(machine_id="m1")

        assert verifier.verify.call_args[0][0] == "q.arcantel.ch"

    def test_without_verifier_nothing_changes(self):
        """The unverified check keeps its exact output and publishes no side metric."""
        client = Mock()
        client.get_machine_by_id.return_value = {"computerDnsName": "q.arcantel.ch"}
        client.get_products.return_value = {"value": [_CRITICAL, _MEDIUM]}

        result = ProductsService(client).get_result(machine_id="m1")

        assert result["value"] == 105
        assert result["details"][0] == "2 vulnerable products, score: 105"
        assert "d:\\gone\\python.exe" in result["details"][3]
        assert "metrics" not in result
        assert "raw_value" not in result
