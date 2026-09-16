"""
Date the software entries Defender reports against the host's real filesystem.

The Defender export lags reality by days: an uninstalled product keeps being reported, and so does a
product that has since been patched. Both show up as score, and an operator cannot tell them apart
from a machine that really carries the vulnerable binary.

This module asks the host and takes an entry out of the score only when the host says, without
ambiguity, that nothing confirms it any more. Every uncertain answer -- a path we were not allowed
to read, a probe that failed, an entry the export gave no path for -- keeps its product counted.
Removing a real finding is a monitoring failure; keeping a stale one for one more cycle is only
noise.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import SoftwareEntry
from check_msdefender.core.path_probe import PathProbeError, PathState, PathVerdict

REASON_REMOVED = "removed"
REASON_UPGRADED = "upgraded"


@dataclass(frozen=True)
class StaleEntry:
    """A software entry the host no longer confirms, and why."""

    reason: str
    evidence: str


def _no_stale() -> dict[str, StaleEntry]:
    """Return the empty stale mapping used as the outcome's default."""
    return {}


@dataclass
class VerificationOutcome:
    """What the host answered about a machine's reported software."""

    stale: dict[str, StaleEntry] = field(default_factory=_no_stale)
    unverified: int = 0
    error: str | None = None


class PathProbeProtocol(Protocol):
    """Protocol of the oracle answering whether paths still exist on a host."""

    def probe(self, host: str, paths: Sequence[str]) -> dict[str, PathVerdict]:
        """Return the verdict for each path on that host."""
        ...


class ProductsVerifier:
    """Split reported software into what the host still confirms and what it does not."""

    def __init__(
        self,
        probe: PathProbeProtocol,
        verbose_level: int = 0,
        host_override: str | None = None,
    ) -> None:
        """
        Initialize with the path probe to question and the verbosity level.

        host_override is the name the probe should dial, when it differs from the name Defender
        knows the machine by. The two are not the same thing: Defender reports the machine's own DNS
        name, while the monitoring server reaches it under whatever name its transport trusts -- its
        Nagios host_name, the entry in known_hosts. On a machine whose Defender name is an alias,
        dialing the Defender name fails with "Host key verification failed" even though every other
        check on that host works.
        """
        self.probe = probe
        self.host_override = host_override
        self.logger = get_verbose_logger(__name__, verbose_level)

    def verify(
        self, host: str, software: dict[str, SoftwareEntry]
    ) -> VerificationOutcome:
        """
        Ask the host about every reported path and classify each software entry.

        Args:
            host: DNS name of the machine the entries were reported for.
            software: Software entries keyed as ProductsService groups them.

        Returns:
            The stale entries, the number of entries that could not be decided, and the
            probe error when the host could not be questioned at all.
        """
        target = self.host_override or host
        self.logger.method_entry("verify", host=target, software=len(software))
        paths = sorted(
            {path for entry in software.values() for path in _evidence(entry)}
        )
        if not paths:
            return VerificationOutcome(unverified=len(software))
        try:
            verdicts = self.probe.probe(target, paths)
        except PathProbeError as exc:
            self.logger.info(f"Path verification unavailable: {exc}")
            return VerificationOutcome(unverified=len(software), error=str(exc))
        return self._classify_all(software, verdicts)

    def _classify_all(
        self,
        software: dict[str, SoftwareEntry],
        verdicts: dict[str, PathVerdict],
    ) -> VerificationOutcome:
        """Classify every software entry against the verdicts the host returned."""
        outcome = VerificationOutcome()
        for key, entry in software.items():
            stale, decided = _classify(entry, verdicts)
            if not decided:
                outcome.unverified += 1
            elif stale is not None:
                outcome.stale[key] = stale
                self.logger.info(
                    f"Stale entry {key}: {stale.reason} ({stale.evidence})"
                )
        return outcome


def _evidence(entry: SoftwareEntry) -> list[str]:
    """Return the paths Defender offers as proof that the product is installed."""
    return sorted(entry["paths"]) + sorted(entry["registryPaths"])


def _classify(
    entry: SoftwareEntry, verdicts: dict[str, PathVerdict]
) -> tuple[StaleEntry | None, bool]:
    """
    Decide whether the host still confirms one software entry.

    Args:
        entry: The aggregated software entry to decide about.
        verdicts: Verdicts returned by the probe, keyed by path.

    Returns:
        The stale entry when the host confirms nothing, and whether the entry could be
        decided at all. An undecided entry is never stale.
    """
    evidence = _evidence(entry)
    if not evidence:
        return None, False
    seen = [
        (path, verdicts.get(path, PathVerdict(PathState.ERROR))) for path in evidence
    ]
    if any(verdict.state in _UNDECIDED for _, verdict in seen):
        return None, False
    present = [
        (path, verdict) for path, verdict in seen if verdict.state is PathState.PRESENT
    ]
    if any(not _is_newer(verdict.version, entry["version"]) for _, verdict in present):
        return None, True
    if present:
        path, verdict = present[0]
        return StaleEntry(REASON_UPGRADED, f"{path} is {verdict.version}"), True
    return StaleEntry(REASON_REMOVED, evidence[0]), True


_UNDECIDED = (PathState.DENIED, PathState.ERROR)


def _is_newer(found: str | None, reported: str) -> bool:
    """Return True only when the version found on disk is provably above the reported one."""
    found_parts = _version_tuple(found)
    reported_parts = _version_tuple(reported)
    if found_parts is None or reported_parts is None:
        return False
    width = max(len(found_parts), len(reported_parts))
    return _pad(found_parts, width) > _pad(reported_parts, width)


def _version_tuple(raw: str | None) -> tuple[int, ...] | None:
    """Return the numeric components of a version string, None when there are none."""
    if not raw:
        return None
    parts = tuple(int(number) for number in re.findall(r"\d+", raw))
    return parts or None


def _pad(parts: tuple[int, ...], width: int) -> tuple[int, ...]:
    """Right-pad a version tuple with zeros so two versions compare component-wise."""
    return parts + (0,) * (width - len(parts))
