"""Error handlers and formatters for click CLI."""

import click


class ClickErrorHandler:
    """Custom error handler for Click commands."""

    @staticmethod
    def handle_config_error(error: Exception) -> int:
        """Handle configuration-related errors."""
        click.echo(f"UNKNOWN: Configuration error - {error}", err=True)
        return 3

    @staticmethod
    def handle_auth_error(error: Exception) -> int:
        """Handle authentication-related errors."""
        click.echo(f"UNKNOWN: Authentication error - {error}", err=True)
        return 3

    @staticmethod
    def handle_api_error(error: Exception) -> int:
        """Handle API-related errors."""
        click.echo(f"UNKNOWN: API error - {error}", err=True)
        return 3


class OutputFormatter:
    """Output formatters for different verbosity levels."""

    @staticmethod
    def format_verbose_output(message: str, verbose_level: int) -> None:
        """Format output based on verbosity level."""
        if verbose_level > 0:
            click.echo(f"DEBUG: {message}", err=True)

    @staticmethod
    def format_warning(message: str) -> None:
        """Format warning messages."""
        click.echo(f"WARNING: {message}", err=True)

    @staticmethod
    def format_error(message: str) -> None:
        """Format error messages."""
        click.echo(f"ERROR: {message}", err=True)
