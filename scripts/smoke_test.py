#!/usr/bin/env python3
"""Exercise a compiled management service; this never builds or runs an implant."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


def request(host, port, path, token=None):
    connection = http.client.HTTPConnection(host, port, timeout=4)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(16384)
    finally:
        connection.close()


def raw_request(host, port, data):
    with socket.create_connection((host, port), timeout=4) as stream:
        stream.settimeout(4)
        stream.sendall(data)
        response = http.client.HTTPResponse(stream)
        response.begin()
        response.read(16384)
        return response.status


def wait_ready(host, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if request(host, port, "/healthz")[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise AssertionError("management service did not become ready")


def exercise(host, port, token):
    wait_ready(host, port)
    assert request(host, port, "/healthz")[0] == 200
    assert request(host, port, "/api/v1/status")[0] == 401
    assert request(host, port, "/api/v1/status", "wrong")[0] == 401
    status, body = request(host, port, "/api/v1/status", token)
    assert status == 200 and json.loads(body)["scope"] == "management-only"
    assert json.loads(body)["max_in_flight"] == 32
    # One unfinished connection must not serialize four other clients.
    with socket.create_connection((host, port), timeout=4) as slow:
        slow.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Pending: ")
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(
                lambda _: request(host, port, "/api/v1/status", token), range(4)
            ))
        assert all(result[0] == 200 for result in results)
        assert time.monotonic() - started < 1.5, "clients were serialized behind an incomplete request"
    assert request(host, port, "/api/v1/payloads/generate", token)[0] == 404
    assert request(host, port, "/api/v1/listeners", token)[0] == 404
    duplicate = (
        f"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n"
        f"Authorization: Bearer {token}\r\nAuthorization: Bearer {token}\r\n\r\n"
    ).encode()
    assert raw_request(host, port, duplicate) == 400
    assert raw_request(
        host, port,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n"
    ) == 400
    assert raw_request(
        host, port,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: " + b"x" * 8192 + b"\r\n\r\n"
    ) == 431
    assert raw_request(
        host, port, b"POST /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ) == 405
    print("Runtime checks passed: health, authentication, four-client concurrency, scope, and request rejection.")


def native(binary):
    binary = Path(binary).resolve()
    if not binary.is_file():
        raise FileNotFoundError("build the management binary before running its smoke test")
    with tempfile.TemporaryDirectory() as directory:
        token_file = Path(directory) / "admin-token"
        token = secrets.token_hex(32)
        token_file.write_text(token + "\n")
        token_file.chmod(0o600)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        environment = dict(os.environ)
        environment.update({
            "GRAVENLACE_BIND": f"127.0.0.1:{port}",
            "GRAVENLACE_TOKEN_FILE": str(token_file),
            "GRAVENLACE_HEALTH_ADDR": f"127.0.0.1:{port}",
        })
        environment.pop("GRAVENLACE_ALLOW_NON_LOOPBACK", None)
        process = subprocess.Popen(
            [str(binary)], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        succeeded = False
        try:
            exercise("127.0.0.1", port, token)
            subprocess.run([str(binary), "--health-check"], env=environment, check=True)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 0
            assert "shutdown_complete" in stderr
            assert token not in stdout + stderr
            succeeded = True
            print("Native shutdown and token-redaction checks passed.")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            if not succeeded:
                print("Native checks failed; the management build is not verified.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?")
    parser.add_argument("--url")
    parser.add_argument("--token-file")
    args = parser.parse_args()
    if args.url:
        parsed = urlsplit(args.url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            parser.error("runtime validation accepts loopback HTTP endpoints only")
        if not args.token_file:
            parser.error("--token-file is required with --url")
        exercise(parsed.hostname, parsed.port or 80, Path(args.token_file).read_text().strip())
    elif args.binary:
        native(args.binary)
    else:
        parser.error("provide a compiled binary, or --url with --token-file")


if __name__ == "__main__":
    main()
