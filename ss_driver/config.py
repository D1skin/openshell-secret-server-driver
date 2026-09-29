# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""Driver configuration: a JSON file, with SS_* environment variables taking precedence."""

import ipaddress
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class DriverConfig:
    base_url: str
    folder_id: int
    template_id: int
    field_slug: str = "password"
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    domain: Optional[str] = None
    bearer_token: Optional[str] = field(default=None, repr=False)
    platform_hostname: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = field(default=None, repr=False)
    site_id: Optional[int] = None
    ca_bundle: Optional[str] = None
    timeout_secs: float = 15.0

    @property
    def uses_platform(self) -> bool:
        return bool(self.platform_hostname)


_ENV = {
    "base_url": "SS_BASE_URL",
    "folder_id": "SS_FOLDER_ID",
    "template_id": "SS_TEMPLATE_ID",
    "field_slug": "SS_FIELD_SLUG",
    "username": "SS_USERNAME",
    "password": "SS_PASSWORD",
    "password_file": "SS_PASSWORD_FILE",
    "domain": "SS_DOMAIN",
    "bearer_token": "SS_BEARER_TOKEN",
    "bearer_token_file": "SS_BEARER_TOKEN_FILE",
    "platform_hostname": "SS_PLATFORM_HOSTNAME",
    "client_id": "SS_CLIENT_ID",
    "client_secret": "SS_CLIENT_SECRET",
    "client_secret_file": "SS_CLIENT_SECRET_FILE",
    "site_id": "SS_SITE_ID",
    "ca_bundle": "SS_CA_BUNDLE",
    "timeout_secs": "SS_TIMEOUT_SECS",
}


def _read_secret_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise ConfigError(f"secret file '{path}' is empty")
    return value


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _checked_url(value: str, name: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ConfigError(f"{name} must be an absolute https:// URL")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise ConfigError(f"{name} must use https:// unless it points at a loopback address")
    return value


def load_config(path: Optional[str]) -> DriverConfig:
    raw: Dict[str, Any] = {}
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, dict):
            raise ConfigError("driver config must be a JSON object")
    for key, env_name in _ENV.items():
        if os.environ.get(env_name):
            raw[key] = os.environ[env_name]

    if raw.get("password_file") and not raw.get("password"):
        raw["password"] = _read_secret_file(raw["password_file"])
    if raw.get("bearer_token_file") and not raw.get("bearer_token"):
        raw["bearer_token"] = _read_secret_file(raw["bearer_token_file"])
    if raw.get("client_secret_file") and not raw.get("client_secret"):
        raw["client_secret"] = _read_secret_file(raw["client_secret_file"])

    base_url = _checked_url(str(raw.get("base_url", "")), "base_url")

    platform_hostname = str(raw.get("platform_hostname") or "").strip() or None
    if platform_hostname:
        if "://" not in platform_hostname:
            platform_hostname = f"https://{platform_hostname}"
        platform_hostname = _checked_url(platform_hostname, "platform_hostname")

    try:
        folder_id = int(raw.get("folder_id", 0))
        template_id = int(raw.get("template_id", 0))
    except (TypeError, ValueError) as err:
        raise ConfigError("folder_id and template_id must be integers") from err
    if folder_id <= 0 or template_id <= 0:
        raise ConfigError("folder_id and template_id must be positive Secret Server IDs")

    username = raw.get("username") or None
    password = raw.get("password") or None
    bearer_token = raw.get("bearer_token") or None
    client_id = raw.get("client_id") or None
    client_secret = raw.get("client_secret") or None
    if platform_hostname:
        if not (client_id and client_secret):
            raise ConfigError("platform_hostname requires client_id and client_secret (or client_secret_file)")
    elif not bearer_token and not (username and password):
        raise ConfigError(
            "configure username and password (or password_file), a Delinea Platform "
            "service account (platform_hostname, client_id, client_secret), or bearer_token"
        )

    field_slug = str(raw.get("field_slug") or "password").strip()
    if not field_slug:
        raise ConfigError("field_slug must not be empty")

    site_id = None
    if raw.get("site_id") not in (None, ""):
        try:
            site_id = int(raw["site_id"])
        except (TypeError, ValueError) as err:
            raise ConfigError("site_id must be an integer") from err
        if site_id <= 0:
            raise ConfigError("site_id must be a positive Secret Server site ID")

    return DriverConfig(
        base_url=base_url,
        site_id=site_id,
        folder_id=folder_id,
        template_id=template_id,
        field_slug=field_slug,
        username=username,
        password=password,
        domain=raw.get("domain") or None,
        bearer_token=bearer_token,
        platform_hostname=platform_hostname,
        client_id=client_id,
        client_secret=client_secret,
        ca_bundle=raw.get("ca_bundle") or None,
        timeout_secs=float(raw.get("timeout_secs", 15.0)),
    )
