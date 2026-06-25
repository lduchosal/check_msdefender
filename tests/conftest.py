"""
Shared pytest configuration.

Markers are registered here via ``pytest_configure`` so they are recognised regardless of which ini
file pytest resolves as its config source.
"""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers used across the test suite."""
    config.addinivalue_line(
        "markers",
        "e2e: end-to-end tests that hit the real Microsoft Defender API "
        "(require credentials; opt-in via CHECK_MSDEFENDER_E2E=1)",
    )
    config.addinivalue_line(
        "markers",
        "reverseproxy: tests that require a reverse proxy",
    )
