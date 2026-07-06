"""Unit tests for Nagios plugin threshold handling."""

from unittest.mock import Mock

import nagiosplugin
import pytest

from check_msdefender.core.nagios import DefenderScalarContext, NagiosPlugin


class TestDefenderScalarContextZeroThresholds:
    """Zero thresholds must not be silently dropped.

    nagiosplugin's Range() does ``spec = spec or ''``, so a numeric 0
    threshold collapses to "no threshold" (ken #973). One unresolved
    alert with the default ``critical=0`` then reported OK instead of
    CRITICAL.
    """

    def test_critical_zero_triggers_critical(self):
        """Value 1 with critical=0 must evaluate to Critical."""
        context = DefenderScalarContext("alerts", 1, 0)
        metric = nagiosplugin.Metric("alerts", 1)

        result = context.evaluate(metric, Mock())

        assert result.state == nagiosplugin.Critical

    def test_critical_zero_value_zero_is_ok(self):
        """Value 0 with critical=0 stays OK."""
        context = DefenderScalarContext("alerts", 1, 0)
        metric = nagiosplugin.Metric("alerts", 0)

        result = context.evaluate(metric, Mock())

        assert result.state == nagiosplugin.Ok

    def test_warning_zero_triggers_warning(self):
        """Value 1 with warning=0 and no critical must evaluate to Warn."""
        context = DefenderScalarContext("alerts", 0, None)
        metric = nagiosplugin.Metric("alerts", 1)

        result = context.evaluate(metric, Mock())

        assert result.state == nagiosplugin.Warn

    def test_performance_data_keeps_zero_critical(self):
        """Perfdata must render the critical threshold: alerts=1;1;0."""
        context = DefenderScalarContext("alerts", 1, 0)
        metric = nagiosplugin.Metric("alerts", 1)

        performance = context.performance(metric, Mock())

        assert str(performance) == "alerts=1;1;0"

    def test_found_context_keeps_inverted_logic(self):
        """The detail command ('found' context) keeps its <= logic."""
        context = DefenderScalarContext("found", 1, 0)
        metric = nagiosplugin.Metric("found", 1)

        result = context.evaluate(metric, Mock())

        assert result.state == nagiosplugin.Warn


class TestNagiosPluginAlertsDefaults:
    """End-to-end check() with the alerts command default thresholds."""

    def _plugin(self, value: int, details: list[str]) -> NagiosPlugin:
        service = Mock()
        service.get_result.return_value = {"value": value, "details": details}
        return NagiosPlugin(service, "alerts")

    def test_one_unresolved_alert_is_critical(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """One unresolved alert with defaults (w=1, c=0) exits CRITICAL."""
        exit_code = self._plugin(1, ["Unresolved alerts for test.domain.com"]).check(
            dns_name="test.domain.com", warning=1, critical=0
        )

        output = capsys.readouterr().out
        assert exit_code == 2
        assert "DEFENDER CRITICAL" in output
        assert "alerts=1;1;0" in output

    def test_no_unresolved_alert_is_ok(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Zero unresolved alerts with defaults (w=1, c=0) exits OK."""
        exit_code = self._plugin(0, []).check(
            dns_name="test.domain.com", warning=1, critical=0
        )

        output = capsys.readouterr().out
        assert exit_code == 0
        assert "DEFENDER OK" in output
