"""Unit tests for the shared machine-resolution helpers."""

from unittest.mock import Mock

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.machine_resolver import (
    resolve_machine,
    resolve_machine_id,
)


class TestResolveMachine:
    """Tests for resolve_machine (returns id + dns)."""

    def test_by_machine_id(self):
        """machine_id given → looks up its DNS name."""
        defender = Mock()
        defender.get_machine_by_id.return_value = {"computerDnsName": "host.dom"}
        assert resolve_machine(defender, "m1", None) == ("m1", "host.dom")
        defender.get_machine_by_id.assert_called_once_with("m1")

    def test_by_machine_id_without_dns(self):
        """machine_id given but no computerDnsName → 'Unknown'."""
        defender = Mock()
        defender.get_machine_by_id.return_value = {}
        assert resolve_machine(defender, "m1", None) == ("m1", "Unknown")

    def test_by_dns_name(self):
        """dns_name given → looks up its id."""
        defender = Mock()
        defender.get_machine_by_dns_name.return_value = {"value": [{"id": "m2"}]}
        assert resolve_machine(defender, None, "host.dom") == ("m2", "host.dom")

    def test_neither_raises(self):
        """No identifier → ValidationError."""
        with pytest.raises(ValidationError, match="Either machine_id or dns_name"):
            resolve_machine(Mock(), None, None)

    def test_dns_not_found_raises(self):
        """dns_name with no machine → ValidationError."""
        defender = Mock()
        defender.get_machine_by_dns_name.return_value = {"value": []}
        with pytest.raises(ValidationError, match="Machine not found with DNS name"):
            resolve_machine(defender, None, "nope.dom")

    def test_dns_machine_without_id_raises(self):
        """Resolved machine has no id → ValidationError."""
        defender = Mock()
        defender.get_machine_by_dns_name.return_value = {"value": [{"id": ""}]}
        with pytest.raises(ValidationError, match="Could not resolve a machine id"):
            resolve_machine(defender, None, "host.dom")


class TestResolveMachineId:
    """Tests for resolve_machine_id (returns id only)."""

    def test_by_machine_id(self):
        """machine_id given → returned as-is, no lookup."""
        defender = Mock()
        assert resolve_machine_id(defender, "m1", None) == "m1"
        defender.get_machine_by_dns_name.assert_not_called()

    def test_by_dns_name(self):
        """dns_name given → resolved to id."""
        defender = Mock()
        defender.get_machine_by_dns_name.return_value = {"value": [{"id": "m2"}]}
        assert resolve_machine_id(defender, None, "host.dom") == "m2"

    def test_neither_raises(self):
        """No identifier → ValidationError."""
        with pytest.raises(ValidationError, match="Either machine_id or dns_name"):
            resolve_machine_id(Mock(), None, None)

    def test_dns_not_found_raises(self):
        """dns_name with no machine → ValidationError."""
        defender = Mock()
        defender.get_machine_by_dns_name.return_value = {"value": []}
        with pytest.raises(ValidationError, match="Machine not found with DNS name"):
            resolve_machine_id(defender, None, "nope.dom")

    def test_dns_machine_without_id_raises(self):
        """Resolved machine has no id → ValidationError."""
        defender = Mock()
        defender.get_machine_by_dns_name.return_value = {"value": [{"id": ""}]}
        with pytest.raises(ValidationError, match="Could not resolve a machine id"):
            resolve_machine_id(defender, None, "host.dom")
