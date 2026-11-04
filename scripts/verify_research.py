#!/usr/bin/env python3
"""Check preserved research material without compiling or executing it."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "research/snapshots/server/main.rs",
    "research/snapshots/crypto_exchange.rs",
    "research/snapshots/server/Dockerfile",
    "research/snapshots/server/compose.yaml",
}


def verify(metadata_path=None):
    provenance = json.loads((ROOT / "research/PROVENANCE.json").read_text())
    records = provenance["files"]
    assert len(records) == len(EXPECTED)
    assert {item["path"] for item in records} == EXPECTED
    assert provenance["historical_original_claim"] is False
    hashes = {}
    for item in records:
        path = ROOT / item["path"]
        assert path.is_file() and not path.is_symlink()
        data = path.read_bytes()
        assert len(data) == item["bytes"], item["path"]
        assert len(data.splitlines()) == item["lines"], item["path"]
        assert sha256(data).hexdigest() == item["sha256"], item["path"]
        assert item["content_changed_during_import"] is False
        assert item["encoding"] == "UTF-8"
        data.decode("utf-8")
        ending = "CRLF" if b"\r\n" in data else "LF"
        assert ending == item["line_endings"], item["path"]
        hashes[item["path"].removeprefix("research/")] = item["sha256"]

    actual = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "research/snapshots").rglob("*") if path.is_file()
    }
    assert actual == EXPECTED
    recorded = {}
    for line in (ROOT / "research/SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert name not in recorded
        recorded[name] = digest
    assert recorded == hashes
    assert not list((ROOT / "research").rglob("Cargo.toml"))
    assert not list((ROOT / "research").rglob("Cargo.lock"))
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    assert manifest["package"]["name"] == "gravenlace-management"
    assert "workspace" not in manifest
    assert "research/snapshots/** -text" in (ROOT / ".gitattributes").read_text()
    assert (ROOT / ".dockerignore").read_text().strip().splitlines()[-1] == "research/"

    links = 0
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts or "target" in path.parts:
            continue
        for target in re.findall(r"\[[^\]]+\]\(([^\s)]+)\)", path.read_text()):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            links += 1
            resolved = (path.parent / unquote(parsed.path)).resolve()
            assert resolved.is_relative_to(ROOT) and resolved.exists(), (path.name, target)
            line_anchor = re.fullmatch(r"L(\d+)(?:-L\d+)?", parsed.fragment)
            if line_anchor:
                assert resolved.is_file()
                assert 1 <= int(line_anchor[1]) <= len(resolved.read_bytes().splitlines())

    if metadata_path:
        metadata = json.loads(Path(metadata_path).read_text())
        packages = [p for p in metadata["packages"]
                    if Path(p["manifest_path"]).resolve() == ROOT / "Cargo.toml"]
        assert len(packages) == 1
        targets = packages[0]["targets"]
        assert len(targets) == 2
        assert {Path(t["src_path"]).resolve() for t in targets} == {
            ROOT / "src/main.rs", ROOT / "src/lib.rs"
        }
    return {
        "preserved_snapshots": len(records),
        "local_links": links,
        "cargo_targets_checked": metadata_path is not None,
        "snapshot_code_executed": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-metadata")
    args = parser.parse_args()
    print(verify(args.cargo_metadata))
