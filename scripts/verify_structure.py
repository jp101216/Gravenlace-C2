#!/usr/bin/env python3
"""Inspect management-only metadata; does not claim compiler/runtime validation."""
from pathlib import Path
import re
import tomllib


def verify(root: Path) -> dict:
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    package = manifest["package"]
    assert package["name"] == "gravenlace-management"
    assert package["version"] == "0.2.0"
    assert package["publish"] is False
    assert package["license"] == "MIT"
    expected = {
        "axum": "=0.8.9", "tokio": "=1.54.1", "serde": "=1.0.229",
        "serde_json": "=1.0.154", "subtle": "=2.6.1",
    }
    actual = manifest["dependencies"]
    assert set(actual) == set(expected)
    for name, version in expected.items():
        item = actual[name]
        assert (item if isinstance(item, str) else item["version"]) == version
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())
    assert toolchain["toolchain"]["channel"] == "1.99.1"
    lock_path = root / "Cargo.lock"
    if lock_path.exists():
        lock = tomllib.loads(lock_path.read_text())
        assert isinstance(lock.get("version"), int)
        resolved = {(p["name"], p["version"]) for p in lock["package"]}
        for name, version in expected.items():
            assert (name, version.removeprefix("=")) in resolved
    docker = (root / "Dockerfile").read_text()
    compose = (root / "compose.yaml").read_text()
    unit = (root / "deploy/gravenlace-management.service").read_text()
    source = (root / "src/lib.rs").read_text()
    main = (root / "src/main.rs").read_text()
    required = [
        "src/lib.rs", "src/main.rs", "Cargo.toml", "rust-toolchain.toml", "Dockerfile",
        "compose.yaml", "deploy/gravenlace-management.service", "README.md",
        "VALIDATION.md", "DEPENDENCIES.md", "LICENSE", ".gitignore", ".dockerignore",
        ".github/workflows/ci.yml", ".github/dependabot.yml", "scripts/smoke_test.py",
    ]
    for path in required:
        assert (root / path).is_file(), path
    assert "FROM rust:1.99.1-bookworm AS builder" in docker
    assert "cargo generate-lockfile" in docker and "cargo build --release --locked" in docker
    assert "USER 10001:10001" in docker and '"--health-check"' in docker
    assert "127.0.0.1:${GRAVENLACE_HTTP_PORT:-8000}:8000/tcp" in compose
    assert "read_only: true" in compose and "no-new-privileges:true" in compose
    assert "GRAVENLACE_TOKEN_FILE=%d/admin-token" in unit and "DynamicUser=yes" in unit
    routes = re.findall(r'\.route\("([^\"]+)"', source)
    assert set(routes) == {"/healthz", "/api/v1/status"} and len(routes) == 2
    assert "with_graceful_shutdown" in main and "Duration::from_secs(8)" in main
    for path in [root / "secrets/admin-token", root / ".env"]:
        if path.exists():
            assert path.is_file() and path.stat().st_mode & 0o077 == 0
    ignored = (root / ".gitignore").read_text()
    assert "/secrets/" in ignored and "/.env" in ignored
    return {
        "required_files": len(required), "external_dependencies": len(actual),
        "lockfile_present": lock_path.exists(), "compilation_verified": False,
    }


if __name__ == "__main__":
    print(verify(Path(__file__).resolve().parents[1]))
