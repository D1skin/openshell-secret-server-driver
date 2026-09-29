# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""Prepare the Secret Server side of the demo and print shell assignments.

Reads SS_PLATFORM_HOSTNAME, SS_CLIENT_ID, SS_CLIENT_SECRET and, optionally, SS_BASE_URL
(the vault URL). Finds the vault behind the Platform tenant, the template and a demo
folder (reused if it exists, otherwise created at the root or inside a folder the
account owns). Progress goes to stderr; stdout carries only KEY=value lines.
"""

import os
import sys
from urllib.parse import urlparse

from ss_driver.config import DriverConfig
from ss_driver.secret_server import SecretServerClient, SecretServerError

FOLDER_NAME = os.environ.get("DEMO_FOLDER_NAME", "OpenShell Demo")
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


def demo_folder(vault):
    existing = vault.find_folder_id(FOLDER_NAME)
    if existing:
        say(f"reusing folder '{FOLDER_NAME}' (id {existing})")
        return existing
    try:
        folder_id = vault.create_folder(FOLDER_NAME)
        say(f"created folder '{FOLDER_NAME}' at the vault root (id {folder_id})")
        return folder_id
    except SecretServerError:
        pass
    try:
        owned = vault.list_folders(permission="Owner")
    except SecretServerError:
        owned = []
    for parent in owned or vault.list_folders():
        try:
            folder_id = vault.create_folder(FOLDER_NAME, int(parent["id"]))
        except SecretServerError:
            continue
        say(f"created folder '{FOLDER_NAME}' inside '{parent.get('folderPath') or parent.get('folderName')}' (id {folder_id})")
        return folder_id
    raise SystemExit(f"the service account can't create '{FOLDER_NAME}'; create it, give the account Owner, and rerun")


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
    folder_id = demo_folder(vault)
    print(f"VAULT_URL={vault_url}")
    print(f"FOLDER_ID={folder_id}")
    print(f"TEMPLATE_ID={template_id}")


if __name__ == "__main__":
    try:
        main()
    except SecretServerError as err:
        raise SystemExit(f"Secret Server call failed: {err}")
