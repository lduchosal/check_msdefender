"""Integration tests for lastseen command."""

from unittest.mock import Mock, patch

import click
import pytest
from click.testing import CliRunner

from check_msdefender.cli.commands.lastseen import register_lastseen_commands


@pytest.fixture
def cli_runner():
    """Create CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def mock_app():
    """Create mock CLI app with lastseen command."""

    @click.group()
    def app():
        pass

    register_lastseen_commands(app)
    return app


@patch("check_msdefender.cli.commands.lastseen.load_config")
@patch("check_msdefender.cli.commands.lastseen.get_authenticator")
@patch("check_msdefender.cli.commands.lastseen.DefenderClient")
@patch("check_msdefender.cli.commands.lastseen.LastSeenService")
@patch("check_msdefender.cli.commands.lastseen.NagiosPlugin")
def test_lastseen_command_success(
    mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner, mock_app
):
    """Test successful lastseen command execution."""
    # Setup mocks
    mock_config.return_value = {"config": "test"}
    mock_auth.return_value = Mock()
    mock_client.return_value = Mock()
    mock_service_instance = Mock()
    mock_service.return_value = mock_service_instance
    mock_plugin = Mock()
    mock_nagios.return_value = mock_plugin
    mock_plugin.check.return_value = 0

    # Execute command
    result = cli_runner.invoke(
        mock_app,
        [
            "lastseen",
            "--machine-id",
            "test-machine-id",
            "--warning",
            "5",
            "--critical",
            "10",
        ],
    )

    # Verify result
    assert result.exit_code == 0
    mock_nagios.assert_called_once_with(mock_service_instance, "lastseen")
    mock_plugin.check.assert_called_once_with(
        machine_id="test-machine-id",
        dns_name=None,
        warning=5,
        critical=10,
        verbose=False,
    )


@patch("check_msdefender.cli.commands.lastseen.load_config")
def test_lastseen_command_exception(mock_config, cli_runner, mock_app):
    """Test lastseen command with exception."""
    # Setup mock to raise exception
    mock_config.side_effect = Exception("Test error")

    # Execute command
    result = cli_runner.invoke(
        mock_app, ["lastseen", "--machine-id", "test-machine-id"]
    )

    # Verify error handling
    assert result.exit_code == 3  # Now properly returns exit code 3 for UNKNOWN
    assert "UNKNOWN: Test error" in result.output
