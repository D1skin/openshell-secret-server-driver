# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""Deterministic Secret Server names for gateway-managed provider credentials.

A handle only ever resolves to the secret whose name matches the identity the
gateway presents (workspace, provider ID, provider name, credential key and
write object ID). This mirrors the path binding in OpenShell's Vault driver and
stops one provider's handle from being replayed to read another provider's
secret.
"""

import hashlib

NAME_PREFIX = "openshell-"
_DOMAIN = b"openshell/provider-credential/v1"


def managed_secret_name(
    workspace: str,
    provider_id: str,
    provider: str,
    credential_key: str,
    object_id: str,
) -> str:
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    for part in (workspace, provider_id, provider, credential_key):
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    if object_id != provider_id:
        digest.update(b"\0")
        digest.update(object_id.encode("utf-8"))
    return NAME_PREFIX + digest.hexdigest()[:40]


_REFERENCE_DOMAIN = b"openshell/provider-credential-reference/v1"


def reference_binding(
    workspace: str,
    provider_id: str,
    provider: str,
    credential_key: str,
    object_id: str,
    secret_id: int,
    slug: str,
) -> str:
    """Tie an attached secret to the provider credential it was attached for.

    Stored in the reference handle's metadata and re-derived on every resolve,
    so a handle replayed under another provider or key is refused. Like the
    managed names, this is a consistency check: what the driver can read at all
    is bounded by reference_folder_ids and the service account's permissions.
    """
    digest = hashlib.sha256()
    digest.update(_REFERENCE_DOMAIN)
    for part in (workspace, provider_id, provider, credential_key, object_id, str(secret_id), slug):
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return digest.hexdigest()[:40]


def requested_object_id(object_id: str, provider_id: str) -> str:
    """Return the per-write object identity, defaulting to the provider ID."""
    value = object_id if object_id else provider_id
    if not value or value.strip() != value:
        raise ValueError("object_id must not be empty or contain surrounding whitespace")
    return value
