"""Entry point. The OpenShell gateway launches this with `--bind-socket <path>`
when `command` is set in `[openshell.credential_drivers.<name>]`, or you can run
it yourself and point the gateway at the socket with `socket_path` only.
"""

import argparse
import logging
import os
import signal
import stat
import sys
import threading
from concurrent import futures

import grpc

import credential_driver_pb2_grpc as pb_grpc

from . import __version__
from .config import ConfigError, load_config
from .secret_server import SecretServerClient
from .service import CredentialDriverService

log = logging.getLogger("ss_driver")


def _prepare_socket_path(path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise SystemExit(f"refusing to replace '{path}': it exists and is not a Unix socket")
    if info.st_uid != os.geteuid():
        raise SystemExit(f"refusing to replace '{path}': it is owned by another user")
    os.unlink(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Delinea Secret Server credential driver for OpenShell")
    parser.add_argument("--bind-socket", default=os.environ.get("SS_DRIVER_SOCKET"), help="Unix socket to listen on")
    parser.add_argument("--config", default=os.environ.get("SS_DRIVER_CONFIG"), help="JSON config file")
    parser.add_argument("--log-level", default=os.environ.get("SS_DRIVER_LOG_LEVEL", "INFO"))
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    if not args.bind_socket:
        parser.error("--bind-socket (or SS_DRIVER_SOCKET) is required")
    try:
        config = load_config(args.config)
    except (ConfigError, OSError, ValueError) as err:
        log.error("invalid driver configuration: %s", err)
        return 2

    socket_path = args.bind_socket
    _prepare_socket_path(socket_path)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb_grpc.add_CredentialDriverServicer_to_server(
        CredentialDriverService(config, SecretServerClient(config)), server
    )
    old_umask = os.umask(0o177)
    try:
        server.add_insecure_port(f"unix:{socket_path}")
        server.start()
    finally:
        os.umask(old_umask)
    os.chmod(socket_path, 0o600)
    log.info(
        "delinea-secret-server driver %s listening on %s (folder %s, template %s)",
        __version__,
        socket_path,
        config.folder_id,
        config.template_id,
    )

    stopped = threading.Event()

    def _shutdown(signum, _frame):
        log.info("received signal %s; shutting down", signum)
        server.stop(grace=5).wait()
        stopped.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        while not stopped.is_set():
            stopped.wait(1.0)
    finally:
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
