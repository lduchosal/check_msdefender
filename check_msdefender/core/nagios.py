"""Nagios plugin implementation."""
import traceback

import nagiosplugin
from typing import List, Optional, Union, Any


class DefenderScalarContext(nagiosplugin.ScalarContext):
    """Custom scalar context with modified threshold logic for detail command."""

    def __init__(
        self,
        name: str,
        warning: Optional[Union[float, int]] = None,
        critical: Optional[Union[float, int]] = None,
    ) -> None:
        """Initialize with custom threshold logic."""
        # Store original values to know what was actually set
        self._original_warning = warning
        self._original_critical = critical
        super().__init__(name, warning, critical)

    def evaluate(
        self, metric: nagiosplugin.Metric, resource: nagiosplugin.Resource
    ) -> nagiosplugin.Result:
        """Evaluate metric against thresholds with <= logic for detail command."""
        if self.name == "found":
            # For detail command, use <= threshold logic (not < threshold)
            # Use original values instead of Range objects for threshold comparison
            critical_val = self._original_critical
            warning_val = self._original_warning

            # Check most restrictive threshold first
            warning_triggered = (
                self._original_warning is not None
                and warning_val is not None
                and metric.value <= warning_val
            )
            critical_triggered = (
                self._original_critical is not None
                and critical_val is not None
                and metric.value <= critical_val
            )

            if critical_triggered and warning_triggered:
                # Both triggered - determine priority based on which threshold is more restrictive
                # For this application, choose the threshold that equals the metric value
                if warning_val == metric.value:
                    return self.result_cls(
                        nagiosplugin.Warn,
                        f"{metric.name} is {metric.value} (outside range {warning_val}:)",
                        metric,
                    )
                else:
                    # If no exact match, use the more severe one (critical)
                    return self.result_cls(
                        nagiosplugin.Critical,
                        f"{metric.name} is {metric.value} (outside range {critical_val}:)",
                        metric,
                    )
            elif critical_triggered:
                return self.result_cls(
                    nagiosplugin.Critical,
                    f"{metric.name} is {metric.value} (outside range {critical_val}:)",
                    metric,
                )
            elif warning_triggered:
                return self.result_cls(
                    nagiosplugin.Warn,
                    f"{metric.name} is {metric.value} (outside range {warning_val}:)",
                    metric,
                )
            else:
                return self.result_cls(nagiosplugin.Ok, None, metric)
        else:
            # For other commands, use standard threshold logic
            return super().evaluate(metric, resource)


class DefenderSummary(nagiosplugin.Summary):
    """Custom summary class for detailed Nagios output."""

    def __init__(self, details: Optional[List[str]]) -> None:
        """Initialize with detailed output lines."""
        self.details = details or []

    def ok(self, results: nagiosplugin.Results) -> str:
        """Return detailed output for OK state."""
        return self._format_details()

    def problem(self, results: nagiosplugin.Results) -> str:
        """Return detailed output for problem states (WARNING, CRITICAL)."""
        return self._format_details()

    def _format_details(self) -> str:
        """Format details for output."""
        if not self.details:
            return ""
        return "\n" + "\n".join(self.details)


class NagiosPlugin:
    """Nagios plugin for Microsoft Defender monitoring."""

    def __init__(self, service: Any, command_name: str) -> None:
        """Initialize with a service and command name."""
        self.service = service
        self.command_name = command_name

    def check(
        self,
        machine_id: Optional[str] = None,
        dns_name: Optional[str] = None,
        warning: Optional[Union[float, int]] = None,
        critical: Optional[Union[float, int]] = None,
        verbose: int = 0,
    ) -> int:
        """Execute the check and return Nagios exit code."""
        try:
            result = self.service.get_result(machine_id=machine_id, dns_name=dns_name)
            value = result["value"]
            details = result.get("details", [])

            # Create Nagios check with custom summary
            # Use 'found' as context name for detail command, otherwise use command name
            context_name = "found" if self.command_name == "detail" else self.command_name
            check = nagiosplugin.Check(
                DefenderResource(self.command_name, value),
                DefenderScalarContext(context_name, warning, critical),
                DefenderSummary(details),
            )

            # Run check and return exit code instead of exiting
            try:
                check.main(verbose=verbose)
                return 0  # If main() doesn't exit, it's OK
            except SystemExit as e:
                return int(e.code) if e.code is not None else 0

        except Exception as e:
            print(f"UNKNOWN: {str(e)}\n{traceback.format_exc()}")
            return 3


class DefenderResource(nagiosplugin.Resource):
    """Defender resource for getting values with custom service name."""

    def __init__(self, command_name: str, value: Union[int, float]) -> None:
        super().__init__()
        self.command_name = command_name
        self.value = value

    @property
    def name(self) -> str:
        """Return custom service name."""
        return "DEFENDER"

    def probe(self) -> List[nagiosplugin.Metric]:
        # Use 'found' as metric name for detail command, otherwise use command name
        metric_name = "found" if self.command_name == "detail" else self.command_name
        return [nagiosplugin.Metric(metric_name, self.value)]
