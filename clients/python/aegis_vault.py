"""Fetch secrets from aegis-vault over its read socket. Stdlib only: copy this file into an app.

    from aegis_vault import fetch_scope
    secrets = fetch_scope("epiphyte/prod")      # {"DATABASE_URL": "...", ...}

The vault decides who may read a scope from the uid of the process on the other end of the socket, so
there is nothing to configure here but the scope name (and, in dev, the socket path). Fetch once at
startup and keep the values in memory; never write them to a file or a log. If the vault is down or says
no, `VaultError` is raised: fail fast and let the supervisor retry.

The socket path is `socket_path` if given, else $AEGIS_VAULT_SOCKET, else /run/aegis-vault/read.sock.

Source: aegis, clients/python/aegis_vault.py. Keep vendored copies in step with it.
"""

import http.client
import json
import os
import re
import socket

__all__ = ["DEFAULT_SOCKET", "VaultError", "fetch_scope"]

DEFAULT_SOCKET = "/run/aegis-vault/read.sock"

# Same rules as the vault: segments of [a-z0-9._-] joined by "/", at most 128 bytes, no "." or "..".
_SEGMENT = re.compile(r"[a-z0-9._-]+\Z")
_MAX_NAME = 128


class VaultError(Exception):
    """The vault couldn't be reached, refused the request, or answered something unexpected.

    `status` is the HTTP status when the vault answered, else None. Messages never contain values.
    """

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("aegis-vault", timeout=timeout)
        self._socket_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def _check_scope(scope):
    if not isinstance(scope, str) or not scope or len(scope.encode()) > _MAX_NAME:
        raise ValueError("scope must be a non-empty string of at most 128 bytes")
    for segment in scope.split("/"):
        if not _SEGMENT.match(segment) or segment in (".", ".."):
            raise ValueError("bad scope name %r: segments of [a-z0-9._-] joined by /" % scope)


def fetch_scope(scope, socket_path=None, timeout=5.0):
    """Return every value in `scope` as a dict of str to str.

    Raises ValueError for a malformed scope name and VaultError for anything the vault (or the lack of
    one) does wrong. An allowed scope with no values yet returns an empty dict.
    """
    _check_scope(scope)
    path = socket_path or os.environ.get("AEGIS_VAULT_SOCKET") or DEFAULT_SOCKET
    connection = _UnixHTTPConnection(path, timeout)
    try:
        try:
            connection.request("GET", "/v1/scope/" + scope, headers={"Accept": "application/json"})
            response = connection.getresponse()
            body = response.read()
        except OSError as e:
            raise VaultError("aegis-vault at %s: %s" % (path, e.strerror or e)) from None
        except http.client.HTTPException as e:
            raise VaultError("aegis-vault at %s: bad response (%s)" % (path, type(e).__name__)) from None
    finally:
        connection.close()

    try:
        data = json.loads(body)
    except ValueError:
        raise VaultError("aegis-vault answered %d with a body that isn't JSON" % response.status,
                         response.status) from None
    if response.status != 200:
        message = data.get("error") if isinstance(data, dict) else None
        raise VaultError("aegis-vault refused scope %s (%d): %s"
                         % (scope, response.status, message or "no message"), response.status)
    secrets = data.get("secrets") if isinstance(data, dict) else None
    if not isinstance(secrets, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in secrets.items()):
        raise VaultError("aegis-vault answered without a secrets object", response.status)
    return secrets
