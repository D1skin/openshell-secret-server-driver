"""Minimal Delinea Secret Server REST client (standard library only).

Covers the calls the credential driver needs: OAuth2 password-grant login,
secret stub/create/get, field read/update, search and deactivate. Secret
values and tokens are never logged or included in exception messages.
"""

import json
from http.client import HTTPException
import logging
import ssl
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .config import DriverConfig

log = logging.getLogger("ss_driver.secret_server")

_TOKEN_REFRESH_MARGIN_SECS = 30.0


class SecretServerError(Exception):
    """A Secret Server call failed. `status` is the HTTP status, or 0 when unreachable."""

    def __init__(self, status: int, message: str, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


class SecretServerClient:
    def __init__(self, config: DriverConfig):
        self._config = config
        self._base = config.base_url.rstrip("/")
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        # Certificate and hostname verification always stay on. A private CA is
        # added through ca_bundle; there is deliberately no bypass.
        self._ssl = self._tls_context(self._base)
        self._platform_ssl = self._tls_context(config.platform_hostname or "")

    def _tls_context(self, url: str) -> Optional[ssl.SSLContext]:
        if not url.startswith("https://"):
            return None
        return ssl.create_default_context(cafile=self._config.ca_bundle)

    # -- authentication -------------------------------------------------

    def _access_token(self, force_refresh: bool = False) -> str:
        if self._config.bearer_token:
            return self._config.bearer_token
        with self._lock:
            if not force_refresh and self._token and time.time() < self._token_expires_at:
                return self._token
            if self._config.uses_platform:
                # Delinea Platform service account (client credentials).
                token_url = f"{self._config.platform_hostname}/identity/api/oauth2/token/xpmplatform"
                form = {
                    "grant_type": "client_credentials",
                    "client_id": self._config.client_id or "",
                    "client_secret": self._config.client_secret or "",
                    "scope": "xpmheadless",
                }
                principal = f"Delinea Platform as {self._config.client_id}"
                context = self._platform_ssl
            else:
                # Secret Server application account (password grant).
                token_url = f"{self._base}/oauth2/token"
                form = {
                    "grant_type": "password",
                    "username": self._config.username or "",
                    "password": self._config.password or "",
                }
                if self._config.domain:
                    form["domain"] = self._config.domain
                principal = f"Secret Server as {self._config.username}"
                context = self._ssl
            request = Request(
                token_url,
                data=urlencode(form).encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            payload = self._send(request, "authenticate", context=context)
            token = payload.get("access_token") if isinstance(payload, dict) else None
            if not token:
                raise SecretServerError(401, "token response did not include an access token")
            expires_in = float(payload.get("expires_in", 300))
            self._token = token
            self._token_expires_at = time.time() + max(expires_in - _TOKEN_REFRESH_MARGIN_SECS, 5.0)
            log.info("authenticated to %s", principal)
            return token

    # -- transport ------------------------------------------------------

    def _send(self, request: Request, operation: str, context: Optional[ssl.SSLContext] = None) -> Any:
        tls = context if context is not None else self._ssl
        try:
            with urlopen(request, timeout=self._config.timeout_secs, context=tls) as response:
                body = response.read()
        except HTTPError as err:
            detail, code = _error_detail(err)
            raise SecretServerError(err.code, f"{operation}: {detail}", code) from None
        except (URLError, TimeoutError, OSError) as err:
            reason = getattr(err, "reason", err)
            raise SecretServerError(0, f"{operation}: Secret Server is unreachable ({reason})") from None
        except (HTTPException, ValueError) as err:
            raise SecretServerError(0, f"{operation}: invalid request or response ({type(err).__name__})") from None
        if not body:
            return None
        try:
            return json.loads(body)
        except ValueError:
            raise SecretServerError(502, f"{operation}: Secret Server returned a non-JSON response") from None

    def _call(
        self,
        method: str,
        path: str,
        operation: str,
        query: Optional[Dict[str, Any]] = None,
        body: Any = None,
    ) -> Any:
        url = f"{self._base}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        for attempt in (0, 1):
            headers = {
                "Authorization": f"Bearer {self._access_token(force_refresh=attempt == 1)}",
                "Accept": "application/json",
            }
            if data is not None:
                headers["Content-Type"] = "application/json"
            request = Request(url, data=data, method=method, headers=headers)
            try:
                return self._send(request, operation)
            except SecretServerError as err:
                # An expired session token gets one fresh login; a static bearer token does not.
                if err.status == 401 and attempt == 0 and not self._config.bearer_token:
                    log.info("Secret Server session expired; re-authenticating")
                    continue
                raise
        raise SecretServerError(401, f"{operation}: authentication failed")

    # -- secret operations ----------------------------------------------

    def get_stub(self, template_id: int, folder_id: int) -> Dict[str, Any]:
        return self._call(
            "GET",
            "/api/v1/secrets/stub",
            "get secret stub",
            query={"filter.secretTemplateId": template_id, "filter.folderId": folder_id},
        )

    def create_secret(self, model: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("POST", "/api/v1/secrets", "create secret", body=model)

    def get_secret(self, secret_id: int) -> Dict[str, Any]:
        return self._call("GET", f"/api/v1/secrets/{secret_id}", "read secret")

    def get_field(self, secret_id: int, slug: str) -> str:
        value = self._call("GET", f"/api/v1/secrets/{secret_id}/fields/{quote(slug)}", "read secret field")
        return "" if value is None else str(value)

    def update_field(self, secret_id: int, slug: str, value: str) -> None:
        self._call(
            "PUT",
            f"/api/v1/secrets/{secret_id}/fields/{quote(slug)}",
            "update secret field",
            body={"value": value},
        )

    def deactivate_secret(self, secret_id: int) -> None:
        self._call("DELETE", f"/api/v1/secrets/{secret_id}", "deactivate secret")

    def find_active_by_name(self, folder_id: int, name: str) -> List[int]:
        page = self._call(
            "GET",
            "/api/v1/secrets",
            "search secrets",
            query={
                "filter.folderId": folder_id,
                "filter.searchText": name,
                "filter.includeInactive": "false",
                "take": 50,
            },
        )
        records = page.get("records", []) if isinstance(page, dict) else []
        return [
            int(record["id"])
            for record in records
            if record.get("name") == name and record.get("active", True)
        ]


    def discover_site_id(self) -> Optional[int]:
        """Find a usable site: the first active distributed-engine site, else the
        site of any secret this account can see. Returns None if neither works."""
        try:
            page = self._call("GET", "/api/v1/distributed-engine/sites", "list sites", query={"take": 50})
            records = page.get("records", page) if isinstance(page, dict) else page
            for record in records if isinstance(records, list) else []:
                site = record.get("siteId") or record.get("id")
                if site and int(site) > 0 and record.get("active", True) is not False:
                    return int(site)
        except SecretServerError as err:
            log.info("site listing unavailable (%s); trying an existing secret's site", err)
        try:
            page = self._call("GET", "/api/v1/secrets", "search secrets", query={"take": 10})
            for record in page.get("records", []) if isinstance(page, dict) else []:
                site = record.get("siteId")
                if site and int(site) > 0:
                    return int(site)
        except SecretServerError as err:
            log.info("secret search unavailable for site discovery (%s)", err)
        return None

    # -- setup helpers (used by the live-tenant test) ---------------------

    def find_template_id(self, name: str) -> Optional[int]:
        page = self._call("GET", "/api/v1/secret-templates", "search templates",
                          query={"filter.searchText": name, "take": 50})
        records = page.get("records", []) if isinstance(page, dict) else []
        for record in records:
            if str(record.get("name", "")).lower() == name.lower():
                return int(record["id"])
        return None

    def template_slugs(self, template_id: int, folder_id: int) -> List[str]:
        stub = self.get_stub(template_id, folder_id)
        return [str(item.get("slug")) for item in stub.get("items") or [] if item.get("slug")]

    def find_folder_id(self, name: str) -> Optional[int]:
        page = self._call("GET", "/api/v1/folders", "search folders",
                          query={"filter.searchText": name, "take": 50})
        records = page.get("records", []) if isinstance(page, dict) else []
        for record in records:
            if record.get("folderName") == name:
                return int(record["id"])
        return None

    def template_fields(self, template_id: int) -> List[Dict[str, Any]]:
        template = self._call("GET", f"/api/v1/secret-templates/{template_id}", "read template")
        return template.get("fields", []) if isinstance(template, dict) else []

    def list_folders(self, take: int = 500, permission: Optional[str] = None) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"take": take}
        if permission:
            query["filter.permissionRequired"] = permission
        page = self._call("GET", "/api/v1/folders", "list folders", query=query)
        return page.get("records", []) if isinstance(page, dict) else []

    def folders_with_prefix(self, prefix: str) -> List[Dict[str, Any]]:
        page = self._call("GET", "/api/v1/folders", "search folders",
                          query={"filter.searchText": prefix, "take": 200})
        records = page.get("records", []) if isinstance(page, dict) else []
        return [r for r in records if str(r.get("folderName", "")).startswith(prefix)]

    def active_secret_ids(self, folder_id: int, text: str = "") -> List[int]:
        page = self._call("GET", "/api/v1/secrets", "search secrets", query={
            "filter.folderId": folder_id, "filter.searchText": text,
            "filter.includeInactive": "false", "take": 200})
        records = page.get("records", []) if isinstance(page, dict) else []
        return [int(r["id"]) for r in records if r.get("active", True)]

    def delete_folder(self, folder_id: int) -> None:
        self._call("DELETE", f"/api/v1/folders/{folder_id}", "delete folder")

    def create_folder(self, name: str, parent_folder_id: int = -1) -> int:
        created = self._call("POST", "/api/v1/folders", "create folder", body={
            "folderName": name,
            "folderTypeId": 1,
            "parentFolderId": parent_folder_id,
            "inheritPermissions": True,
            "inheritSecretPolicy": True,
        })
        return int(created["id"])


def _error_detail(err: HTTPError) -> Tuple[str, str]:
    try:
        payload = json.loads(err.read() or b"{}")
    except ValueError:
        payload = {}
    code = payload.get("errorCode") if isinstance(payload, dict) else None
    message = payload.get("message") if isinstance(payload, dict) else None
    parts = [f"HTTP {err.code}"]
    if code:
        parts.append(str(code))
    if message:
        parts.append(str(message)[:200])
    # Validation failures carry per-field reasons in modelState (field names and
    # rule messages, not submitted values).
    model_state = payload.get("modelState") if isinstance(payload, dict) else None
    if isinstance(model_state, dict) and model_state:
        reasons = []
        for key, errors in list(model_state.items())[:5]:
            text = ", ".join(str(e) for e in errors) if isinstance(errors, list) else str(errors)
            reasons.append(f"{key}: {text[:120]}")
        parts.append("(" + "; ".join(reasons) + ")")
    return " ".join(parts), str(code or "")
