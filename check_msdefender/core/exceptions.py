"""Custom exceptions for check_msdefender."""


class CheckMSDefenderError(Exception):
    """Base exception for check_msdefender."""

    pass


class ConfigurationError(CheckMSDefenderError):
    """Raised when there's a configuration error."""

    pass


class AuthenticationError(CheckMSDefenderError):
    """Raised when there's an authentication error."""

    pass


class DefenderAPIError(CheckMSDefenderError):
    """Raised when there's an error with the Defender API."""

    pass


class ValidationError(CheckMSDefenderError):
    """Raised when there's a validation error."""

    pass
