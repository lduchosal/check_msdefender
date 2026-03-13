"""Logging configuration for verbose mode."""

import logging
import sys
from typing import Any, Optional


class VerboseLogger:
    """Logger configured for different verbosity levels."""

    def __init__(self, name: str, verbose_level: int = 0):
        """
        Initialize logger with verbosity level.

        Args:
            name: Logger name
            verbose_level: Verbosity level (0=none, 1=info, 2=debug, 3+=trace)
        """
        self.logger = logging.getLogger(name)
        self.verbose_level = verbose_level
        self._configure_logger()

    def _configure_logger(self) -> None:
        """Configure logger based on verbosity level."""
        # Clear any existing handlers
        self.logger.handlers.clear()

        if self.verbose_level == 0:
            # No verbose logging
            self.logger.setLevel(logging.WARNING)
            return

        # Create console handler
        handler = logging.StreamHandler(sys.stderr)

        # Set format based on verbosity
        if self.verbose_level >= 3:
            # Full trace format
            formatter = logging.Formatter(
                "[%(levelname)s] %(asctime)s %(name)s:%(lineno)d - %(message)s",
                datefmt="%H:%M:%S",
            )
        elif self.verbose_level >= 2:
            # Debug format
            formatter = logging.Formatter("[%(levelname)s] %(name)s - %(message)s")
        else:
            # Basic format
            formatter = logging.Formatter("%(message)s")

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Set level based on verbosity
        if self.verbose_level >= 3:
            self.logger.setLevel(logging.DEBUG)
        elif self.verbose_level >= 2:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log info message if verbose >= 1."""
        if self.verbose_level >= 1:
            self.logger.info(message, *args, **kwargs)

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message if verbose >= 2."""
        if self.verbose_level >= 2:
            self.logger.debug(message, *args, **kwargs)

    def trace(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log trace message if verbose >= 3."""
        if self.verbose_level >= 3:
            self.logger.debug(f"TRACE: {message}", *args, **kwargs)

    def api_call(
        self,
        method: str,
        url: str,
        status_code: Optional[int] = None,
        response_time: Optional[float] = None,
    ) -> None:
        """Log API call details if verbose >= 2."""
        if self.verbose_level >= 2:
            if status_code and response_time:
                self.logger.debug(
                    f"API {method} {url} -> {status_code} ({response_time:.3f}s)"
                )
            else:
                self.logger.debug(f"API {method} {url}")

    def json_response(self, data: str) -> None:
        """Log JSON response if verbose >= 2."""
        if self.verbose_level >= 2:
            self.logger.debug(f"JSON Response: {data}")

    def method_entry(self, method_name: str, **kwargs: Any) -> None:
        """Log method entry if verbose >= 3."""
        if self.verbose_level >= 3:
            args_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
            self.logger.debug(f"TRACE: -> {method_name}({args_str})")

    def method_exit(self, method_name: str, result: Any = None) -> None:
        """Log method exit if verbose >= 3."""
        if self.verbose_level >= 3:
            result_str = f" = {result}" if result is not None else ""
            self.logger.debug(f"TRACE: <- {method_name}{result_str}")


def get_verbose_logger(name: str, verbose_level: int = 0) -> VerboseLogger:
    """
    Get a configured verbose logger.

    Args:
        name: Logger name (typically __name__)
        verbose_level: Verbosity level from CLI

    Returns:
        Configured VerboseLogger instance
    """
    return VerboseLogger(name, verbose_level)
