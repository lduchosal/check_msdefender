"""Authentication management."""

import configparser
from typing import Union

from azure.identity import CertificateCredential, ClientSecretCredential

from check_msdefender.core.exceptions import ConfigurationError


def get_authenticator(
    config: configparser.ConfigParser,
) -> Union[ClientSecretCredential, CertificateCredential]:
    """Get appropriate authenticator based on configuration."""
    if not config.has_section("auth"):
        raise ConfigurationError("Missing [auth] section in configuration")

    auth_section = config["auth"]

    # Required fields
    client_id = auth_section.get("client_id")
    tenant_id = auth_section.get("tenant_id")

    if not client_id or not tenant_id:
        raise ConfigurationError(
            "client_id and tenant_id are required in [auth] section"
        )

    # Check for client secret authentication
    client_secret = auth_section.get("client_secret")
    if client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
        )

    # Check for certificate authentication
    certificate_path = auth_section.get("certificate_path")
    private_key_path = auth_section.get("private_key_path")

    if certificate_path and private_key_path:
        return CertificateCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_path=certificate_path,
            key_path=private_key_path,
        )

    raise ConfigurationError(
        "Either client_secret or certificate_path/private_key_path must be provided"
    )
