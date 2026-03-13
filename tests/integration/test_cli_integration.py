"""Integration tests for CLI interface end-to-end without external dependencies."""

from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from check_msdefender.cli import main


@pytest.fixture
def cli_runner():
    """Create CLI runner for testing."""
    return CliRunner()


class TestHelpCommand:
    """Test help command functionality."""

    def test_help_command(self, cli_runner):
        """Test help command displays usage information."""
        result = cli_runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert (
            "Check Microsoft Defender API endpoints and validate values."
            in result.output
        )
        assert "Commands:" in result.output
        assert "lastseen" in result.output
        assert "onboarding" in result.output
        assert "vulnerabilities" in result.output
        assert "detail" in result.output

    def test_help_flag(self, cli_runner):
        """Test --help flag displays usage information."""
        result = cli_runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert (
            "Check Microsoft Defender API endpoints and validate values."
            in result.output
        )


class TestLastSeenCommand:
    """Test lastseen command functionality."""

    @patch("check_msdefender.cli.commands.lastseen.load_config")
    @patch("check_msdefender.cli.commands.lastseen.get_authenticator")
    @patch("check_msdefender.cli.commands.lastseen.DefenderClient")
    @patch("check_msdefender.cli.commands.lastseen.LastSeenService")
    @patch("check_msdefender.cli.commands.lastseen.NagiosPlugin")
    def test_lastseen_without_args(
        self, mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test lastseen command without arguments."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_plugin = Mock()
        mock_nagios.return_value = mock_plugin
        mock_plugin.check.return_value = 0

        result = cli_runner.invoke(main, ["lastseen"])

        assert result.exit_code == 0
        mock_plugin.check.assert_called_once_with(
            machine_id=None, dns_name=None, warning=7, critical=30, verbose=0
        )

    @patch("check_msdefender.cli.commands.lastseen.load_config")
    @patch("check_msdefender.cli.commands.lastseen.get_authenticator")
    @patch("check_msdefender.cli.commands.lastseen.DefenderClient")
    @patch("check_msdefender.cli.commands.lastseen.LastSeenService")
    @patch("check_msdefender.cli.commands.lastseen.NagiosPlugin")
    def test_lastseen_with_dns_name(
        self, mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test lastseen command with DNS name."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_plugin = Mock()
        mock_nagios.return_value = mock_plugin
        mock_plugin.check.return_value = 0

        result = cli_runner.invoke(main, ["lastseen", "-d", "machine.domain.tld"])

        assert result.exit_code == 0
        mock_plugin.check.assert_called_once_with(
            machine_id=None,
            dns_name="machine.domain.tld",
            warning=7,
            critical=30,
            verbose=0,
        )

    @patch("check_msdefender.cli.commands.lastseen.load_config")
    def test_lastseen_command_error(self, mock_config, cli_runner):
        """Test lastseen command error handling."""
        mock_config.side_effect = Exception("Configuration error")

        result = cli_runner.invoke(main, ["lastseen", "-d", "machine.domain.tld"])

        # Exit code should be 3 for UNKNOWN error
        assert result.exit_code == 3
        assert "UNKNOWN: Configuration error" in result.output


class TestOnboardingCommand:
    """Test onboarding command functionality."""

    @patch("check_msdefender.cli.commands.onboarding.load_config")
    @patch("check_msdefender.cli.commands.onboarding.get_authenticator")
    @patch("check_msdefender.cli.commands.onboarding.DefenderClient")
    @patch("check_msdefender.cli.commands.onboarding.OnboardingService")
    @patch("check_msdefender.cli.commands.onboarding.NagiosPlugin")
    def test_onboarding_with_dns_name(
        self, mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test onboarding command with DNS name."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_plugin = Mock()
        mock_nagios.return_value = mock_plugin
        mock_plugin.check.return_value = 0

        result = cli_runner.invoke(main, ["onboarding", "-d", "machine.domain.tld"])

        assert result.exit_code == 0
        mock_plugin.check.assert_called_once_with(
            machine_id=None,
            dns_name="machine.domain.tld",
            warning=1,
            critical=2,
            verbose=0,
        )

    @patch("check_msdefender.cli.commands.onboarding.load_config")
    def test_onboarding_command_error(self, mock_config, cli_runner):
        """Test onboarding command error handling."""
        mock_config.side_effect = Exception("Authentication failed")

        result = cli_runner.invoke(main, ["onboarding", "-d", "machine.domain.tld"])

        assert result.exit_code == 3
        assert "UNKNOWN: Authentication failed" in result.output


class TestVulnerabilitiesCommand:
    """Test vulnerabilities command functionality."""

    @patch("check_msdefender.cli.commands.vulnerabilities.load_config")
    @patch("check_msdefender.cli.commands.vulnerabilities.get_authenticator")
    @patch("check_msdefender.cli.commands.vulnerabilities.DefenderClient")
    @patch("check_msdefender.cli.commands.vulnerabilities.VulnerabilitiesService")
    @patch("check_msdefender.cli.commands.vulnerabilities.NagiosPlugin")
    def test_vulnerabilities_with_dns_name(
        self, mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test vulnerabilities command with DNS name."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_plugin = Mock()
        mock_nagios.return_value = mock_plugin
        mock_plugin.check.return_value = 0

        result = cli_runner.invoke(
            main, ["vulnerabilities", "-d", "machine.domain.tld"]
        )

        assert result.exit_code == 0
        mock_plugin.check.assert_called_once_with(
            machine_id=None,
            dns_name="machine.domain.tld",
            warning=50,
            critical=500,
            verbose=0,
        )

    @patch("check_msdefender.cli.commands.vulnerabilities.load_config")
    @patch("check_msdefender.cli.commands.vulnerabilities.get_authenticator")
    @patch("check_msdefender.cli.commands.vulnerabilities.DefenderClient")
    @patch("check_msdefender.cli.commands.vulnerabilities.VulnerabilitiesService")
    @patch("check_msdefender.cli.commands.vulnerabilities.NagiosPlugin")
    def test_vulnerabilities_with_verbose(
        self, mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test vulnerabilities command with verbose flag."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_plugin = Mock()
        mock_nagios.return_value = mock_plugin
        mock_plugin.check.return_value = 0

        result = cli_runner.invoke(
            main, ["vulnerabilities", "-d", "machine.domain.tld", "-v"]
        )

        assert result.exit_code == 0
        mock_plugin.check.assert_called_once_with(
            machine_id=None,
            dns_name="machine.domain.tld",
            warning=50,
            critical=500,
            verbose=1,
        )

    @patch("check_msdefender.cli.commands.vulnerabilities.load_config")
    @patch("check_msdefender.cli.commands.vulnerabilities.get_authenticator")
    @patch("check_msdefender.cli.commands.vulnerabilities.DefenderClient")
    @patch("check_msdefender.cli.commands.vulnerabilities.VulnerabilitiesService")
    @patch("check_msdefender.cli.commands.vulnerabilities.NagiosPlugin")
    def test_vulnerabilities_with_multiple_verbose(
        self, mock_nagios, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test vulnerabilities command with multiple verbose flags."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_plugin = Mock()
        mock_nagios.return_value = mock_plugin
        mock_plugin.check.return_value = 0

        result = cli_runner.invoke(
            main, ["vulnerabilities", "-d", "machine.domain.tld", "-vvvv"]
        )

        assert result.exit_code == 0
        mock_plugin.check.assert_called_once_with(
            machine_id=None,
            dns_name="machine.domain.tld",
            warning=50,
            critical=500,
            verbose=4,
        )

    @patch("check_msdefender.cli.commands.vulnerabilities.load_config")
    def test_vulnerabilities_command_error(self, mock_config, cli_runner):
        """Test vulnerabilities command error handling."""
        mock_config.side_effect = Exception("Service unavailable")

        result = cli_runner.invoke(
            main, ["vulnerabilities", "-d", "machine.domain.tld"]
        )

        assert result.exit_code == 3
        assert "UNKNOWN: Service unavailable" in result.output


class TestDetailCommand:
    """Test detail command functionality."""

    @patch("check_msdefender.cli.commands.detail.load_config")
    @patch("check_msdefender.cli.commands.detail.get_authenticator")
    @patch("check_msdefender.cli.commands.detail.DefenderClient")
    @patch("check_msdefender.cli.commands.detail.DetailService")
    def test_detail_with_machine_id_using_i_flag(
        self, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test detail command with machine ID using -i flag."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_service_instance.get_result.return_value = 1
        mock_service_instance.get_result.return_value = {
            "value": 1,
            "details": ["Machine ID: test-machine", "Computer Name: test-pc"],
        }
        mock_service_instance.get_machine_details_json.return_value = (
            '{"id": "test-machine"}'
        )

        result = cli_runner.invoke(main, ["detail", "-i", "test-machine-123"])

        assert result.exit_code == 0
        assert "DEFENDER OK - Machine ID:" in result.output
        assert "test-machine" in result.output
        mock_service_instance.get_result.assert_called_once_with(
            machine_id="test-machine-123", dns_name=None
        )

    @patch("check_msdefender.cli.commands.detail.load_config")
    @patch("check_msdefender.cli.commands.detail.get_authenticator")
    @patch("check_msdefender.cli.commands.detail.DefenderClient")
    @patch("check_msdefender.cli.commands.detail.DetailService")
    def test_detail_with_machine_id_using_m_flag(
        self, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test detail command with machine ID using -m flag."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_service_instance.get_result.return_value = 1
        mock_service_instance.get_result.return_value = {
            "value": 1,
            "details": ["Machine ID: test-machine", "Computer Name: test-pc"],
        }
        mock_service_instance.get_machine_details_json.return_value = (
            '{"id": "test-machine"}'
        )

        result = cli_runner.invoke(main, ["detail", "-m", "test-machine-456"])

        assert result.exit_code == 0
        assert "DEFENDER OK - Machine ID:" in result.output
        mock_service_instance.get_result.assert_called_once_with(
            machine_id="test-machine-456", dns_name=None
        )

    @patch("check_msdefender.cli.commands.detail.load_config")
    @patch("check_msdefender.cli.commands.detail.get_authenticator")
    @patch("check_msdefender.cli.commands.detail.DefenderClient")
    @patch("check_msdefender.cli.commands.detail.DetailService")
    def test_detail_with_dns_name(
        self, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test detail command with DNS name."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_service_instance.get_result.return_value = 1
        mock_service_instance.get_result.return_value = {
            "value": 1,
            "details": ["Machine ID: test-machine", "Computer Name: test.domain.com"],
        }
        mock_service_instance.get_machine_details_json.return_value = (
            '{"computerDnsName": "test.domain.com"}'
        )

        result = cli_runner.invoke(main, ["detail", "-d", "test.domain.com"])

        assert result.exit_code == 0
        assert "DEFENDER OK - Machine ID:" in result.output
        assert "test.domain.com" in result.output
        mock_service_instance.get_result.assert_called_once_with(
            machine_id=None, dns_name="test.domain.com"
        )

    @patch("check_msdefender.cli.commands.detail.load_config")
    @patch("check_msdefender.cli.commands.detail.get_authenticator")
    @patch("check_msdefender.cli.commands.detail.DefenderClient")
    @patch("check_msdefender.cli.commands.detail.DetailService")
    def test_detail_machine_not_found_warning(
        self, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test detail command when machine not found with warning threshold."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_service_instance.get_result.return_value = 0  # Not found
        mock_service_instance.get_result.return_value = {
            "value": 0,
            "details": ["Machine not found with DNS name: nonexistent.domain.com"],
        }

        result = cli_runner.invoke(
            main, ["detail", "-d", "nonexistent.domain.com", "-W", "0"]
        )

        assert result.exit_code == 1  # Warning
        assert "DEFENDER WARNING - Machine not found" in result.output
        assert "found=0;;1" in result.output

    @patch("check_msdefender.cli.commands.detail.load_config")
    @patch("check_msdefender.cli.commands.detail.get_authenticator")
    @patch("check_msdefender.cli.commands.detail.DefenderClient")
    @patch("check_msdefender.cli.commands.detail.DetailService")
    def test_detail_machine_not_found_critical(
        self, mock_service, mock_client, mock_auth, mock_config, cli_runner
    ):
        """Test detail command when machine not found with critical threshold."""
        # Setup mocks
        mock_config.return_value = {"config": "test"}
        mock_auth.return_value = Mock()
        mock_client.return_value = Mock()
        mock_service_instance = Mock()
        mock_service.return_value = mock_service_instance
        mock_service_instance.get_result.return_value = 0  # Not found
        mock_service_instance.get_result.return_value = {
            "value": 0,
            "details": ["Machine not found with DNS name: nonexistent.domain.com"],
        }

        result = cli_runner.invoke(
            main, ["detail", "-d", "nonexistent.domain.com", "-C", "0"]
        )

        assert result.exit_code == 2  # Critical
        assert "DEFENDER CRITICAL - Machine not found" in result.output
        assert "found=0;1" in result.output

    @patch("check_msdefender.cli.commands.detail.load_config")
    def test_detail_command_error(self, mock_config, cli_runner):
        """Test detail command error handling."""
        mock_config.side_effect = Exception("Authentication failed")

        result = cli_runner.invoke(main, ["detail", "-i", "test-machine"])

        assert result.exit_code == 3
        assert "DEFENDER UNKNOWN - Authentication failed" in result.output

    def test_detail_command_help(self, cli_runner):
        """Test detail command help includes both -i and -m options."""
        result = cli_runner.invoke(main, ["detail", "--help"])

        assert result.exit_code == 0
        assert (
            "Get detailed machine information from Microsoft Defender." in result.output
        )
        assert "-m, -i, --machine-id, --id TEXT" in result.output
        assert "-d, --dns-name TEXT" in result.output
