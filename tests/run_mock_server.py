"""Run the mock Secret Server as a standalone process (for dry runs of live_tenant_test.py).

Prints its base URL, then serves until interrupted. Test credentials:
  Platform service account: mock-svc / mock-client-secret
  Secret Server account:    mock-user / mock-password
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mock_secret_server as mock  # noqa: E402

if __name__ == "__main__":
    server, state, base_url = mock.start({"mock-user": "mock-password"}, {"mock-svc": "mock-client-secret"})
    state.denied_folders = {int(f) for f in os.environ.get("MOCK_DENY_FOLDERS", "").split(",") if f.strip()}
    state.deny_folder_create = os.environ.get("MOCK_DENY_FOLDER_CREATE") == "1"
    state.allow_create_under = {int(f) for f in os.environ.get("MOCK_ALLOW_CREATE_UNDER", "").split(",") if f.strip()}
    for spec in filter(None, os.environ.get("MOCK_FOLDERS", "").split(";")):
        fid, name = spec.split("=", 1)
        state.folders[int(fid)] = name
    if os.environ.get("MOCK_SEED_SECRET_FOLDER"):
        state.add_secret("mcp-live-test-secret", int(os.environ["MOCK_SEED_SECRET_FOLDER"]), "mock-live-value")
    print(base_url, flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
