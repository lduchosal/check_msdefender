"""Data models for check_msdefender."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Protocol, TypedDict

# ---------------------------------------------------------------------------
# TypedDict definitions for Microsoft Defender API JSON responses
# ---------------------------------------------------------------------------


class MachineDict(TypedDict, total=False):
    """Single machine object returned by the Defender API."""

    id: str
    computerDnsName: str
    osPlatform: str
    osVersion: str
    healthStatus: str
    riskScore: str
    onboardingStatus: str
    lastSeen: str


class MachineListResponse(TypedDict):
    """Response from endpoints that return a list of machines."""

    value: list[MachineDict]


class AlertDict(TypedDict, total=False):
    """Single alert object returned by the Defender API."""

    machineId: str
    computerDnsName: str
    status: str
    title: str
    alertCreationTime: str
    severity: str


class AlertListResponse(TypedDict):
    """Response from the alerts endpoint."""

    value: list[AlertDict]


class VulnerabilityDict(TypedDict, total=False):
    """Single vulnerability object returned by the Defender API."""

    id: str
    name: str
    severity: str
    description: str


class VulnerabilityListResponse(TypedDict):
    """Response from the vulnerabilities endpoint."""

    value: list[VulnerabilityDict]


class ProductVulnerabilityDict(TypedDict, total=False):
    """Single product/software vulnerability object."""

    deviceId: str
    softwareName: str
    softwareVersion: str
    softwareVendor: str
    cveId: str
    cvssScore: float
    diskPaths: list[str]
    registryPaths: list[str]
    vulnerabilitySeverityLevel: str


class ProductListResponse(TypedDict):
    """Response from the products/software vulnerabilities endpoint."""

    value: list[ProductVulnerabilityDict]


# ---------------------------------------------------------------------------
# Service result TypedDicts
# ---------------------------------------------------------------------------


class ServiceResult(TypedDict, total=False):
    """Common service result shape."""

    value: int
    details: list[str]


class ProductsResult(TypedDict, total=False):
    """Extended result returned by ProductsService."""

    value: int
    details: list[str]
    vulnerable_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_cves: int
    total_software: int


# ---------------------------------------------------------------------------
# Protocol for the Defender client (used by services instead of Any)
# ---------------------------------------------------------------------------


class DefenderClientProtocol(Protocol):
    """Protocol describing the Defender API client methods used by services."""

    def get_machine_by_dns_name(self, dns_name: str) -> MachineListResponse:
        """Get machine information by DNS name."""
        ...

    def get_machine_by_id(self, machine_id: str) -> MachineDict:
        """Get machine information by machine ID."""
        ...

    def get_machine_vulnerabilities(
        self, machine_id: str
    ) -> VulnerabilityListResponse:
        """Get vulnerabilities for a machine."""
        ...

    def list_machines(self) -> MachineListResponse:
        """Get list of all machines."""
        ...

    def get_alerts(self) -> AlertListResponse:
        """Get alerts from Microsoft Defender."""
        ...

    def get_products(self) -> ProductListResponse:
        """Get installed products for a machine."""
        ...


# ---------------------------------------------------------------------------
# Existing dataclass models
# ---------------------------------------------------------------------------


class OnboardingStatus(Enum):
    """Onboarding status enumeration."""

    ONBOARDED = 0
    INSUFFICIENT_INFO = 1
    UNKNOWN = 2


@dataclass
class Machine:
    """Machine data model."""

    id: str
    computer_dns_name: str
    last_seen: Optional[datetime] = None
    onboarding_status: Optional[OnboardingStatus] = None


@dataclass
class Vulnerability:
    """Vulnerability data model."""

    id: str
    severity: str
    title: str
    description: Optional[str] = None


@dataclass
class VulnerabilityScore:
    """Vulnerability score calculation."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total_score(self) -> int:
        """Calculate total weighted score."""
        return self.critical * 100 + self.high * 10 + self.medium * 5 + self.low * 1
