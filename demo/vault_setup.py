# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""Prepare the Secret Server side of the demo and print shell assignments.

Reads SS_PLATFORM_HOSTNAME, SS_CLIENT_ID, SS_CLIENT_SECRET and, optionally, SS_BASE_URL
(the vault URL). Finds the vault behind the Platform tenant and the template, then:

* the driver's own folder (OpenShell Agents), where values passed to OpenShell are stored;
* the security team's folder (Acme Production) and the production Orders API key in it.

Each is reused if it already exists, so you can create the security team's folder and
secret yourself in the Secret Server UI and give the service account View on them only.
Progress goes to stderr; stdout carries only KEY=value lines (IDs, never values).
"""

import os
import secrets
import string
import sys
from urllib.parse import urlparse

from ss_driver.config import DriverConfig
from ss_driver.secret_server import SecretServerClient, SecretServerError

FOLDER_NAME = os.environ.get("DEMO_FOLDER_NAME", "OpenShell Agents")
SECURITY_FOLDER_NAME = os.environ.get("DEMO_SECURITY_FOLDER_NAME", "Acme Production")
ORDERS_SECRET_NAME = os.environ.get("DEMO_ORDERS_SECRET_NAME", "Acme Orders API (production)")
TEMPLATE_NAME = os.environ.get("DEMO_TEMPLATE_NAME", "Password")


def say(message):
    print(f"  {message}", file=sys.stderr)


def client(base_url, folder_id=1, template_id=1):
    return SecretServerClient(DriverConfig(
        base_url=base_url, folder_id=folder_id, template_id=template_id,
        platform_hostname=os.environ["SS_PLATFORM_HOSTNAME"].rstrip("/"),
        client_id=os.environ["SS_CLIENT_ID"], client_secret=os.environ["SS_CLIENT_SECRET"]))


def usable(url):
    parsed = urlparse(url)
    return parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost"))


def find_urls(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and "url" in key.lower() and usable(value):
                found.append(value.rstrip("/"))
            else:
                find_urls(value, found)
    elif isinstance(node, list):
        for value in node:
            find_urls(value, found)


def discover_vault(platform):
    listing = client(platform)._call("GET", "/vaultbroker/api/vaults", "list Platform vaults")
    urls = []
    find_urls(listing, urls)
    platform_host = urlparse(platform).hostname
    urls = [u for u in dict.fromkeys(urls) if urlparse(u).hostname != platform_host]
    if not urls:
        raise SystemExit("the Platform vault listing has no Secret Server URL; set SS_BASE_URL")
    return urls[0]


def ensure_folder(vault, name):
    existing = vault.find_folder_id(name)
    if existing:
        say(f"reusing folder '{name}' (id {existing})")
        return existing
    try:
        folder_id = vault.create_folder(name)
        say(f"created folder '{name}' at the vault root (id {folder_id})")
        return folder_id
    except SecretServerError:
        pass
    try:
        owned = vault.list_folders(permission="Owner")
    except SecretServerError:
        owned = []
    for parent in owned or vault.list_folders():
        try:
            folder_id = vault.create_folder(name, int(parent["id"]))
        except SecretServerError:
            continue
        say(f"created folder '{name}' inside '{parent.get('folderPath') or parent.get('folderName')}' (id {folder_id})")
        return folder_id
    raise SystemExit(f"the service account can't create '{name}'; create it, give the account access, and rerun")


def orders_secret(vault, folder_id, template_id):
    existing = vault.find_active_by_name(folder_id, ORDERS_SECRET_NAME)
    if existing:
        say(f"reusing secret '{ORDERS_SECRET_NAME}' (id {existing[0]})")
        return existing[0]
    slugs = vault.template_slugs(template_id, folder_id)
    key = "acme_live_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    values = {"password": key}
    optional = {"username": "orders-api", "resource": "https://orders.acme.example",
                "notes": "Owned by Acme Security. Production key for the Acme Orders API."}
    values.update({slug: value for slug, value in optional.items() if slug in slugs})
    secret_id = vault.create_simple_secret(ORDERS_SECRET_NAME, template_id, folder_id, values)
    say(f"created secret '{ORDERS_SECRET_NAME}' (id {secret_id}) with a new random acme_live_ key")
    return secret_id


def main():
    platform = os.environ["SS_PLATFORM_HOSTNAME"].rstrip("/")
    if "://" not in platform:
        platform = f"https://{platform}"
        os.environ["SS_PLATFORM_HOSTNAME"] = platform
    vault_url = os.environ.get("SS_BASE_URL") or discover_vault(platform)
    say(f"vault: {urlparse(vault_url).hostname}")
    vault = client(vault_url)
    template_id = vault.find_template_id(TEMPLATE_NAME)
    if not template_id:
        raise SystemExit(f"no template named '{TEMPLATE_NAME}'; set DEMO_TEMPLATE_NAME")
    folder_id = ensure_folder(vault, FOLDER_NAME)
    security_folder_id = ensure_folder(vault, SECURITY_FOLDER_NAME)
    if security_folder_id == folder_id:
        raise SystemExit("the driver's folder and the security team's folder must differ")
    secret_id = orders_secret(vault, security_folder_id, template_id)
    print(f"VAULT_URL={vault_url}")
    print(f"FOLDER_ID={folder_id}")
    print(f"TEMPLATE_ID={template_id}")
    print(f"SECURITY_FOLDER_ID={security_folder_id}")
    print(f"ORDERS_SECRET_ID={secret_id}")


if __name__ == "__main__":
    try:
        main()
    except SecretServerError as err:
        raise SystemExit(f"Secret Server call failed: {err}")
