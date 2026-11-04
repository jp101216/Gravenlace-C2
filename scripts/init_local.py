#!/usr/bin/env python3
"""Create a local token and non-secret Compose UID mapping without overwriting."""
import os
from pathlib import Path
import secrets
import sys


def create_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


def initialize(root: Path, uid: int | None = None, gid: int | None = None) -> None:
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    if uid == 0 or gid == 0:
        raise ValueError("run local setup as a regular user, not root")
    secret_dir = root / "secrets"
    token_path = secret_dir / "admin-token"
    env_path = root / ".env"
    if token_path.exists() or env_path.exists():
        raise FileExistsError("local setup exists; existing files were not replaced")
    secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_dir.chmod(0o700)
    create_private(token_path, secrets.token_hex(32) + "\n")
    create_private(env_path, f"GRAVENLACE_UID={uid}\nGRAVENLACE_GID={gid}\n")


if __name__ == "__main__":
    try:
        initialize(Path(__file__).resolve().parents[1])
    except (OSError, ValueError) as error:
        print(f"setup failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("Created private local configuration. The token was not printed.")
