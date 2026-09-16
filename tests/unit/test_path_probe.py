"""Unit tests for the remote path probe."""

import subprocess
from unittest.mock import Mock, patch

import pytest

from check_msdefender.core.path_probe import (
    DEFAULT_VERIFY_COMMAND,
    MAX_PROBE_PATHS,
    CommandPathProbe,
    PathProbeError,
    PathState,
)


def _completed(stdout="", stderr="", returncode=0):
    """Build a CompletedProcess as subprocess.run would return it."""
    return subprocess.CompletedProcess(
        args=["ssh"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestCommandPathProbe:
    """The probe turns one remote command into a verdict per path."""

    def test_parses_states_and_versions(self):
        """PRESENT carries the file version; the other states carry none."""
        stdout = (
            "PRESENT\t3.0.15\tc:\\rider\\libcrypto-3.dll\n"
            "ABSENT\t\td:\\gone\\python.exe\n"
            "DENIED\t\tc:\\users\\other\\python.exe\n"
        )
        with patch("subprocess.run", return_value=_completed(stdout)):
            verdicts = CommandPathProbe("probe {host}", 5).probe("host.dom", ["a"])

        assert verdicts["c:\\rider\\libcrypto-3.dll"].state is PathState.PRESENT
        assert verdicts["c:\\rider\\libcrypto-3.dll"].version == "3.0.15"
        assert verdicts["d:\\gone\\python.exe"].state is PathState.ABSENT
        assert verdicts["d:\\gone\\python.exe"].version is None
        assert verdicts["c:\\users\\other\\python.exe"].state is PathState.DENIED

    def test_unknown_state_is_error_not_absent(self):
        """A state we do not know must never be read as 'the file is gone'."""
        with patch("subprocess.run", return_value=_completed("WAT\t\tc:\\x\n")):
            verdicts = CommandPathProbe("probe {host}", 5).probe("h", ["c:\\x"])

        assert verdicts["c:\\x"].state is PathState.ERROR

    def test_malformed_lines_are_skipped(self):
        """Short or path-less lines yield no verdict at all."""
        stdout = "PRESENT\t3.0\n\nABSENT\t\t\nPRESENT\t1.0\tc:\\ok\n"
        with patch("subprocess.run", return_value=_completed(stdout)):
            verdicts = CommandPathProbe("probe {host}", 5).probe("h", ["c:\\ok"])

        assert list(verdicts) == ["c:\\ok"]

    def test_host_is_substituted_and_no_shell_is_used(self):
        """{host} is replaced in the split argv, and the paths go in on stdin."""
        with patch("subprocess.run", return_value=_completed()) as run:
            CommandPathProbe("ssh -l nagioscmd {host} script.ps1", 7).probe(
                "q.arcantel.ch", ["c:\\a", "c:\\b"]
            )

        argv, kwargs = run.call_args[0][0], run.call_args[1]
        assert argv == ["ssh", "-l", "nagioscmd", "q.arcantel.ch", "script.ps1"]
        assert kwargs["input"] == "c:\\a\nc:\\b\n"
        assert kwargs["timeout"] == 7
        assert "shell" not in kwargs

    def test_non_zero_exit_raises_with_first_error_line(self):
        """A failing command is an error, never an empty set of verdicts."""
        probe = CommandPathProbe("probe {host}", 5)
        failure = _completed(
            stderr="Host key verification failed.\nmore\n", returncode=255
        )
        with (
            patch("subprocess.run", return_value=failure),
            pytest.raises(PathProbeError, match="Host key verification failed."),
        ):
            probe.probe("h", ["c:\\a"])

    def test_timeout_raises(self):
        """A probe that hangs must surface as an error, not as a silent all-clear."""
        probe = CommandPathProbe("probe {host}", 3)
        with (
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ssh", 3)),
            pytest.raises(PathProbeError, match="timeout after 3s"),
        ):
            probe.probe("h", ["c:\\a"])

    def test_missing_binary_raises(self):
        """No ssh on the monitoring host is an error like any other."""
        probe = CommandPathProbe("probe {host}", 5)
        with (
            patch("subprocess.run", side_effect=OSError("No such file")),
            pytest.raises(PathProbeError, match="No such file"),
        ):
            probe.probe("h", ["c:\\a"])

    def test_empty_command_raises(self):
        """An empty template is a configuration error, caught before running anything."""
        with pytest.raises(PathProbeError, match="empty verification command"):
            CommandPathProbe("   ", 5).probe("h", ["c:\\a"])

    def test_paths_are_capped(self):
        """Beyond the cap, paths are simply not submitted (so they stay unverified)."""
        run = Mock(return_value=_completed())
        with patch("subprocess.run", run):
            CommandPathProbe("probe {host}", 5).probe(
                "h", [f"c:\\p{index}" for index in range(MAX_PROBE_PATHS + 50)]
            )

        assert run.call_args[1]["input"].count("\n") == MAX_PROBE_PATHS

    def test_default_command_targets_the_nagios_account(self):
        """The shipped default is the estate's existing Windows check transport."""
        assert "-l nagioscmd" in DEFAULT_VERIFY_COMMAND
        assert "{host}" in DEFAULT_VERIFY_COMMAND
        assert "test_paths.ps1" in DEFAULT_VERIFY_COMMAND
