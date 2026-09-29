# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""In-process test double for the Delinea Secret Server REST API subset the driver uses.

Implements: POST /oauth2/token, the Platform token endpoint, GET /api/v1/secrets/stub,
POST /api/v1/secrets, GET /api/v1/secrets/{id}, GET|PUT /api/v1/secrets/{id}/fields/{slug},
GET /api/v1/secrets/{id}/audits, DELETE /api/v1/secrets/{id}, GET /api/v1/secrets (search),
folders, templates and sites. Reads honor autoComment/autoCheckout/autoCheckIn, and secrets
can require a comment or checkout. Endpoints under /_test/ exist only for the test harness.
"""

import json
import secrets as pysecrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

# Shaped like the built-in "Password" template: resource, username, password, notes.
TEMPLATE_ID = 6001
SECRET_FLAGS = ("requiresComment", "checkOutEnabled", "checkOutChangePasswordEnabled")
TEMPLATE_FIELDS = [
    {"fieldId": 301, "fieldName": "Resource", "slug": "resource", "isPassword": False},
    {"fieldId": 302, "fieldName": "Username", "slug": "username", "isPassword": False},
    {"fieldId": 303, "fieldName": "Password", "slug": "password", "isPassword": True, "required": True},
    {"fieldId": 304, "fieldName": "Notes", "slug": "notes", "isPassword": False},
]


class MockState:
    def __init__(self, users: Dict[str, str], platform_clients: Optional[Dict[str, str]] = None):
        self.lock = threading.Lock()
        self.users = users
        self.platform_clients = platform_clients or {}
        self.grants: List[str] = []
        self.folders: Dict[int, str] = {}
        # Some Secret Server versions still return deactivated secrets with active=false.
        self.inactive_readable = False
        # Folders this account can't add secrets to (mimics API_AccessDeniedOnFolder).
        self.denied_folders: set = set()
        self.deny_folder_create = False
        self.allow_create_under: set = set()
        self.tokens: Dict[str, Tuple[str, float]] = {}
        self.secrets: Dict[int, Dict[str, Any]] = {}
        self.next_id = 1000
        self.audit: List[Dict[str, Any]] = []

    def add_secret(self, name: str, folder_id: int, value: str, extra: Optional[Dict[str, str]] = None) -> int:
        """Seed a secret the way a person would create it in the UI (no driver involved)."""
        values = dict(extra or {}, password=value)
        with self.lock:
            secret_id = self.next_id
            self.next_id += 1
            self.secrets[secret_id] = dict(
                {flag: False for flag in SECRET_FLAGS},
                id=secret_id,
                name=name,
                folderId=folder_id,
                secretTemplateId=TEMPLATE_ID,
                active=True,
                items=[dict(field, itemId=secret_id * 10 + index, itemValue=values.get(field["slug"], ""))
                       for index, field in enumerate(TEMPLATE_FIELDS)],
            )
            return secret_id


def _json(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def make_handler(state: MockState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        # -- helpers ------------------------------------------------------

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def _user(self) -> Optional[str]:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return None
            with state.lock:
                entry = state.tokens.get(header[len("Bearer "):])
            if not entry or entry[1] < time.time():
                return None
            return entry[0]

        def _audit(self, user: str, action: str, secret_id: Optional[int], notes: str = "") -> None:
            with state.lock:
                state.audit.append({"user": user, "action": action, "secretId": secret_id, "notes": notes,
                                    "at": time.time()})

        def _open(self, user: str, secret: Dict[str, Any], query: Dict[str, str], action: str) -> Optional[Any]:
            """Apply the secret's access policy to one read; return the model as read, or None if refused."""
            comment = query.get("autoComment", "")
            if secret.get("requiresComment") and not comment:
                _json(self, 400, {"errorCode": "API_CommentRequired", "message": "A comment is required to view this secret"})
                return None
            checkout = bool(secret.get("checkOutEnabled"))
            if checkout and query.get("autoCheckout") != "true":
                _json(self, 400, {"errorCode": "API_CheckOutRequired", "message": "The secret must be checked out"})
                return None
            if checkout:
                self._audit(user, "CHECKOUT", secret["id"], comment)
            self._audit(user, action, secret["id"], comment)
            snapshot = json.loads(json.dumps(secret))
            if checkout and query.get("autoCheckIn") == "true":
                self._audit(user, "CHECKIN", secret["id"], comment)
                if secret.get("checkOutChangePasswordEnabled"):
                    with state.lock:
                        for item in secret["items"]:
                            if item["slug"] == "password":
                                item["itemValue"] = pysecrets.token_urlsafe(12)
                    self._audit("RPC", "PASSWORD_CHANGE", secret["id"])
            return snapshot

        def _secret(self, secret_id: int) -> Optional[Dict[str, Any]]:
            secret = state.secrets.get(secret_id)
            if not secret or not secret["active"]:
                return None
            return secret

        def _unauthorized(self) -> None:
            _json(self, 401, {"errorCode": "API_AuthenticationFailed", "message": "Authentication failed or token expired"})

        def _not_found(self) -> None:
            _json(self, 404, {"errorCode": "API_SecretNotFound", "message": "Secret not found or inactive"})

        # -- routes -------------------------------------------------------

        def do_POST(self):  # noqa: N802
            url = urlparse(self.path)
            if url.path == "/oauth2/token":
                form = {key: values[0] for key, values in parse_qs(self._body().decode("utf-8")).items()}
                if form.get("grant_type") != "password" or state.users.get(form.get("username", "")) != form.get("password"):
                    _json(self, 400, {"error": "invalid_grant"})
                    return
                token = pysecrets.token_urlsafe(24)
                with state.lock:
                    state.tokens[token] = (form["username"], time.time() + 1199)
                    state.grants.append("password")
                _json(self, 200, {"access_token": token, "token_type": "bearer", "expires_in": 1199})
                return
            if url.path == "/identity/api/oauth2/token/xpmplatform":
                form = {key: values[0] for key, values in parse_qs(self._body().decode("utf-8")).items()}
                client = form.get("client_id", "")
                if (form.get("grant_type") != "client_credentials" or form.get("scope") != "xpmheadless"
                        or state.platform_clients.get(client) != form.get("client_secret")):
                    _json(self, 400, {"error": "invalid_client"})
                    return
                token = pysecrets.token_urlsafe(24)
                with state.lock:
                    state.tokens[token] = (client, time.time() + 3600)
                    state.grants.append("client_credentials")
                _json(self, 200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600})
                return
            if url.path.startswith("/_test/"):
                self._test_route(url.path, json.loads(self._body() or b"{}"))
                return
            user = self._user()
            if not user:
                self._unauthorized()
                return
            if url.path == "/api/v1/folders":
                body = json.loads(self._body() or b"{}")
                if state.deny_folder_create and int(body.get("parentFolderId", -1)) not in state.allow_create_under:
                    _json(self, 403, {"errorCode": "API_AccessDenied", "message": "Access denied"})
                    return
                with state.lock:
                    folder_id = 500 + len(state.folders)
                    state.folders[folder_id] = body.get("folderName", "")
                _json(self, 200, {"id": folder_id, "folderName": state.folders[folder_id], "parentFolderId": -1})
                return
            if url.path == "/api/v1/secrets":
                model = json.loads(self._body() or b"{}")
                allowed = {"name", "secretTemplateId", "folderId", "siteId", "items"}
                if set(model) - allowed:
                    _json(self, 400, {"message": "The request is invalid.",
                                      "modelState": {f"args.{k}": ["Unexpected field"] for k in sorted(set(model) - allowed)}})
                    return
                by_id = {f["fieldId"]: f for f in TEMPLATE_FIELDS}
                items = []
                for item in model.get("items") or []:
                    field = by_id.get(item.get("fieldId"))
                    if field is None:
                        _json(self, 400, {"message": "The request is invalid.",
                                          "modelState": {"args.items": ["Unknown fieldId"]}})
                        return
                    items.append(dict(field, itemId=0, itemValue=item.get("itemValue", "")))
                if not isinstance(model.get("siteId"), int) or model["siteId"] < 1:
                    _json(self, 400, {"message": "The request is invalid.", "modelState": {
                        "secretCreateArgs.SiteId": ["The field SiteId must be between 1 and 2147483647."]}})
                    return
                present = {i["slug"] for i in items}
                items += [dict(f, itemId=0, itemValue="") for f in TEMPLATE_FIELDS if f["slug"] not in present]
                model["items"] = items
                password = next((i["itemValue"] for i in items if i["slug"] == "password"), "")
                if not model.get("name") or not password:
                    _json(self, 400, {"errorCode": "API_ValidationFailed", "message": "Name and Password are required"})
                    return
                with state.lock:
                    secret_id = state.next_id
                    state.next_id += 1
                    model["id"] = secret_id
                    model["active"] = True
                    model.update({flag: False for flag in SECRET_FLAGS})
                    state.secrets[secret_id] = model
                self._audit(user, "CREATE", secret_id)
                _json(self, 200, model)
                return
            _json(self, 404, {"message": "route not found"})

        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            if url.path.startswith("/_test/"):
                self._test_route(url.path, {})
                return
            user = self._user()
            if not user:
                self._unauthorized()
                return
            query = {key: values[0] for key, values in parse_qs(url.query).items()}
            parts = [unquote(part) for part in url.path.strip("/").split("/")]
            if url.path == "/api/v1/distributed-engine/sites":
                _json(self, 200, {"records": [{"siteId": 1, "siteName": "Local", "active": True}], "total": 1})
                return
            if url.path == "/vaultbroker/api/vaults":
                _json(self, 200, {"vaults": [{"vaultId": "vault-1", "name": "Mock Secret Server",
                                              "type": "SecretServer",
                                              "connection": {"url": f"http://127.0.0.1:{self.server.server_address[1]}"}}]})
                return
            if url.path == "/api/v1/secrets/stub":
                if int(query.get("filter.folderId", -1)) in state.denied_folders:
                    _json(self, 400, {"errorCode": "API_AccessDeniedOnFolder", "message": "Access Denied on Folder"})
                    return
                if int(query.get("filter.secretTemplateId", 0)) != TEMPLATE_ID:
                    _json(self, 400, {"errorCode": "API_InvalidTemplate", "message": "Unknown template"})
                    return
                _json(self, 200, {
                    "id": 0,
                    "name": "",
                    "folderId": int(query.get("filter.folderId", -1)),
                    "secretTemplateId": TEMPLATE_ID,
                    "siteId": 0,
                    "items": [dict(field, itemId=0, itemValue="") for field in TEMPLATE_FIELDS],
                })
                return
            if url.path == "/api/v1/folders":
                text = query.get("filter.searchText", "")
                owner_only = query.get("filter.permissionRequired") == "Owner"
                with state.lock:
                    records = [r for r in [{"id": fid, "folderName": name.rsplit("\\", 1)[-1], "folderPath": "\\" + name, "parentFolderId": -1}
                               for fid, name in state.folders.items() if text in name]
                               if not owner_only or r["id"] in state.allow_create_under]
                _json(self, 200, {"records": records, "total": len(records)})
                return
            if len(parts) == 4 and parts[:3] == ["api", "v1", "secret-templates"] and parts[3].isdigit():
                if int(parts[3]) != TEMPLATE_ID:
                    _json(self, 404, {"message": "template not found"})
                    return
                _json(self, 200, {"id": TEMPLATE_ID, "name": "Password", "fields": [
                    {"fieldSlugName": f["slug"], "displayName": f["fieldName"], "isPassword": f["isPassword"]}
                    for f in TEMPLATE_FIELDS]})
                return
            if url.path == "/api/v1/secret-templates":
                text = query.get("filter.searchText", "").lower()
                records = [{"id": TEMPLATE_ID, "name": "Password"}] if text in "password" else []
                _json(self, 200, {"records": records, "total": len(records)})
                return
            if url.path == "/api/v1/secrets":
                folder = int(query.get("filter.folderId", -1))
                text = query.get("filter.searchText", "")
                with state.lock:
                    records = [
                        {"id": s["id"], "name": s["name"], "folderId": s["folderId"], "active": s["active"]}
                        for s in state.secrets.values()
                        if s["folderId"] == folder and text in s["name"] and s["active"]
                    ]
                _json(self, 200, {"records": records, "total": len(records)})
                return
            if len(parts) == 4 and parts[:3] == ["api", "v1", "secrets"] and parts[3].isdigit():
                secret = self._secret(int(parts[3]))
                if not secret and state.inactive_readable:
                    secret = state.secrets.get(int(parts[3]))
                if not secret:
                    self._not_found()
                    return
                snapshot = self._open(user, secret, query, "VIEW")
                if snapshot is not None:
                    _json(self, 200, snapshot)
                return
            if len(parts) == 5 and parts[:3] == ["api", "v1", "secrets"] and parts[4] == "audits":
                secret_id = int(parts[3]) if parts[3].isdigit() else -1
                with state.lock:
                    records = [{"secretAuditId": index + 1, "secretId": entry["secretId"], "action": entry["action"],
                                "notes": entry.get("notes", ""), "byUserDisplayName": entry["user"],
                                "dateRecorded": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(entry["at"]))}
                               for index, entry in enumerate(state.audit) if entry["secretId"] == secret_id]
                records.reverse()  # newest first, like Secret Server
                _json(self, 200, {"records": records[:int(query.get("take", 25))], "total": len(records)})
                return
            if len(parts) == 6 and parts[:3] == ["api", "v1", "secrets"] and parts[4] == "fields":
                secret = self._secret(int(parts[3]))
                if not secret:
                    self._not_found()
                    return
                item = next((i for i in secret["items"] if i["slug"] == parts[5]), None)
                if not item:
                    _json(self, 404, {"message": "field not found"})
                    return
                value = item.get("itemValue", "")
                if self._open(user, secret, query, "VIEW_FIELD") is not None:
                    _json(self, 200, value)
                return
            _json(self, 404, {"message": "route not found"})

        def do_PUT(self):  # noqa: N802
            user = self._user()
            if not user:
                self._unauthorized()
                return
            url = urlparse(self.path)
            query = {key: values[0] for key, values in parse_qs(url.query).items()}
            parts = [unquote(part) for part in url.path.strip("/").split("/")]
            if len(parts) == 6 and parts[:3] == ["api", "v1", "secrets"] and parts[4] == "fields":
                secret = self._secret(int(parts[3]))
                if not secret:
                    self._not_found()
                    return
                body = json.loads(self._body() or b"{}")
                item = next((i for i in secret["items"] if i["slug"] == parts[5]), None)
                if not item:
                    _json(self, 404, {"message": "field not found"})
                    return
                with state.lock:
                    item["itemValue"] = body.get("value", "")
                self._audit(user, "EDIT", secret["id"], query.get("autoComment", ""))
                _json(self, 200, item["itemValue"])
                return
            _json(self, 404, {"message": "route not found"})

        def do_DELETE(self):  # noqa: N802
            user = self._user()
            if not user:
                self._unauthorized()
                return
            parts = urlparse(self.path).path.strip("/").split("/")
            if len(parts) == 4 and parts[:3] == ["api", "v1", "folders"] and parts[3].isdigit():
                folder_id = int(parts[3])
                if folder_id not in state.folders:
                    _json(self, 404, {"message": "folder not found"})
                    return
                if any(s["folderId"] == folder_id and s["active"] for s in state.secrets.values()):
                    _json(self, 400, {"errorCode": "API_FolderNotEmpty", "message": "Folder contains secrets"})
                    return
                with state.lock:
                    del state.folders[folder_id]
                self._audit(user, "DELETE_FOLDER", None)
                _json(self, 200, {"id": folder_id, "objectType": "Folder", "responseCodes": []})
                return
            if len(parts) == 4 and parts[:3] == ["api", "v1", "secrets"] and parts[3].isdigit():
                secret = self._secret(int(parts[3]))
                if not secret:
                    self._not_found()
                    return
                with state.lock:
                    secret["active"] = False
                self._audit(user, "DEACTIVATE", secret["id"])
                _json(self, 200, {"id": secret["id"], "objectType": "Secret", "responseCodes": []})
                return
            _json(self, 404, {"message": "route not found"})

        # -- test-only controls ------------------------------------------

        def _test_route(self, path: str, body: Dict[str, Any]) -> None:
            if path.startswith("/_test/rotate/"):
                secret = state.secrets.get(int(path.rsplit("/", 1)[1]))
                if not secret:
                    self._not_found()
                    return
                with state.lock:
                    for item in secret["items"]:
                        if item["slug"] == "password":
                            item["itemValue"] = body["value"]
                    state.audit.append({"user": "RPC", "action": "PASSWORD_CHANGE", "secretId": secret["id"],
                                        "notes": "", "at": time.time()})
                _json(self, 200, {"ok": True})
            elif path.startswith("/_test/secret-flags/"):
                secret = state.secrets.get(int(path.rsplit("/", 1)[1]))
                if not secret:
                    self._not_found()
                    return
                with state.lock:
                    for key in SECRET_FLAGS + ("active",):
                        if key in body:
                            secret[key] = bool(body[key])
                    if "folderId" in body:
                        secret["folderId"] = int(body["folderId"])
                    state.audit.append({"user": "security-admin", "action": "EDIT", "secretId": secret["id"],
                                        "notes": "", "at": time.time()})
                _json(self, 200, {"ok": True})
            elif path == "/_test/inactive-readable":
                state.inactive_readable = bool(body.get("enabled", True))
                _json(self, 200, {"ok": True})
            elif path == "/_test/expire-tokens":
                with state.lock:
                    state.tokens.clear()
                _json(self, 200, {"ok": True})
            elif path == "/_test/audit":
                with state.lock:
                    _json(self, 200, list(state.audit))
            else:
                _json(self, 404, {"message": "unknown test route"})

    return Handler


def start(users: Dict[str, str], platform_clients: Optional[Dict[str, str]] = None
          ) -> Tuple[ThreadingHTTPServer, MockState, str]:
    state = MockState(users, platform_clients)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state, f"http://127.0.0.1:{server.server_address[1]}"
