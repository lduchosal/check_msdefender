"""
Ask a monitored host whether the paths Defender reports still exist.

Microsoft's ``SoftwareVulnerabilitiesByMachine`` export is a snapshot regenerated on Microsoft's own
cadence: a product uninstalled today keeps being reported for days, and an entry whose files were
deleted long ago can linger. The evidence needed to date an entry is already in the export -- every
record carries the disk and registry paths where the product was seen -- so the only missing piece
is an oracle answering "is this path still there?".

The oracle is a single command run once per check, configured as a template so the plugin stays
transport-agnostic (the Nagios host already reaches its Windows machines over SSH, but nothing here
depends on that). Paths go in on stdin, one per line; verdicts come back as
``STATE<TAB>VERSION<TAB>PATH``.
"""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from check_msdefender.core.exceptions import CheckMSDefenderError
from check_msdefender.core.logging_config import get_verbose_logger

# The probe on the Nagios side of the Arcantel estate: same account and same script
# directory as every other Windows check (check_by_ssh -l nagioscmd). Overridable
# through [verify] command in the ini file.
DEFAULT_VERIFY_COMMAND = (
    "ssh -o BatchMode=yes -o ConnectTimeout=5 -l nagioscmd {host} "
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    "-File c:/programdata/nagioscmd/scripts/test_paths.ps1"
)

# A machine with a large vulnerable surface reports a few hundred paths. The cap is a
# safety bound on a remote command built from API data, not a tuning knob: paths beyond
# it simply get no verdict, which keeps their product counted.
MAX_PROBE_PATHS = 1000


class PathState(Enum):
    """Verdict returned by the remote probe for a single path."""

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    DENIED = "DENIED"
    ERROR = "ERROR"

    @classmethod
    def parse(cls, raw: str) -> PathState:
        """Return the state named by the probe, ERROR when it is not one we know."""
        try:
            return cls(raw.strip().upper())
        except ValueError:
            return cls.ERROR


@dataclass(frozen=True)
class PathVerdict:
    """State of one path on the host, with the file version when it could be read."""

    state: PathState
    version: str | None = None


class PathProbeError(CheckMSDefenderError):
    """Raised when the probe could not run, or ran without a trustworthy answer."""


class CommandPathProbe:
    """Run the configured verification command and parse its verdicts."""

    def __init__(
        self, command_template: str, timeout: int, verbose_level: int = 0
    ) -> None:
        """Initialize with the command template, its timeout and the verbosity."""
        self.command_template = command_template
        self.timeout = timeout
        self.logger = get_verbose_logger(__name__, verbose_level)

    def probe(self, host: str, paths: Sequence[str]) -> dict[str, PathVerdict]:
        """
        Return the verdict for each path, keyed by the path as it was submitted.

        Args:
            host: DNS name substituted into the command template.
            paths: Disk or registry paths to test on that host.

        Returns:
            Verdicts for the paths the probe answered about. A path missing from the
            mapping has no verdict and must be treated as unverified, never as absent.
            A command that cannot be run, times out or exits non-zero raises
            PathProbeError rather than returning an empty mapping: "no answer" and
            "nothing found" must never look alike.
        """
        self.logger.method_entry("probe", host=host, paths=len(paths))
        submitted = list(paths)[:MAX_PROBE_PATHS]
        argv = self._build_argv(host)
        self.logger.info(f"Verifying {len(submitted)} path(s) on {host}")
        completed = self._run(argv, submitted)
        verdicts = self._parse(completed.stdout)
        self.logger.method_exit("probe", f"{len(verdicts)} verdict(s)")
        return verdicts

    def _build_argv(self, host: str) -> list[str]:
        """Split the template and substitute the host, without invoking a shell."""
        argv = [
            part.replace("{host}", host) for part in shlex.split(self.command_template)
        ]
        if not argv:
            raise PathProbeError("empty verification command")
        return argv

    def _run(
        self, argv: list[str], paths: list[str]
    ) -> subprocess.CompletedProcess[str]:
        """Run the probe command with the paths on stdin."""
        try:
            completed = subprocess.run(
                argv,
                input="\n".join(paths) + "\n",
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PathProbeError(f"timeout after {self.timeout}s") from exc
        except OSError as exc:
            raise PathProbeError(f"{argv[0]}: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise PathProbeError(f"exit {completed.returncode}: {_first_line(detail)}")
        return completed

    @staticmethod
    def _parse(stdout: str) -> dict[str, PathVerdict]:
        """Parse STATE<TAB>VERSION<TAB>PATH lines into verdicts."""
        verdicts: dict[str, PathVerdict] = {}
        for line in stdout.splitlines():
            fields = line.rstrip("\r").split("\t", 2)
            if len(fields) != 3 or not fields[2]:
                continue
            state = PathState.parse(fields[0])
            version = fields[1].strip() or None
            verdicts[fields[2]] = PathVerdict(state, version)
        return verdicts


def _first_line(text: str) -> str:
    """Return the first non-empty line of the text, for one-line error reporting."""
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return "no output"
