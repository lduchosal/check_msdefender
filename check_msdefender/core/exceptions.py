"""Custom exceptions for check_msdefender."""


class CheckMSDefenderError(Exception):
    """Base exception for check_msdefender."""


class ConfigurationError(CheckMSDefenderError):
    """Raised when there's a configuration error."""


class AuthenticationError(CheckMSDefenderError):
    """Raised when there's an authentication error."""


class DefenderAPIError(CheckMSDefenderError):
    """Raised when there's an error with the Defender API."""


class ValidationError(CheckMSDefenderError):
    """Raised when there's a validation error."""
