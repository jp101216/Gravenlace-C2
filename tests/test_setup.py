import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("init_local", ROOT / "scripts/init_local.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LocalSetupTests(unittest.TestCase):
    def test_creates_private_random_token_and_non_secret_uid_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.initialize(root, uid=10001, gid=10001)
            token = (root / "secrets/admin-token").read_text().strip()
            self.assertEqual(len(token), 64)
            int(token, 16)
            self.assertEqual(stat.S_IMODE((root / "secrets/admin-token").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / ".env").stat().st_mode), 0o600)
            self.assertEqual((root / ".env").read_text(), "GRAVENLACE_UID=10001\nGRAVENLACE_GID=10001\n")

    def test_repeat_setup_preserves_existing_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.initialize(root, uid=10001, gid=10001)
            original = (root / "secrets/admin-token").read_bytes()
            with self.assertRaises(FileExistsError):
                MODULE.initialize(root, uid=10001, gid=10001)
            self.assertEqual((root / "secrets/admin-token").read_bytes(), original)

    def test_existing_env_file_is_preserved_without_creating_a_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("existing\n")
            with self.assertRaises(FileExistsError):
                MODULE.initialize(root, uid=10001, gid=10001)
            self.assertEqual((root / ".env").read_text(), "existing\n")
            self.assertFalse((root / "secrets/admin-token").exists())

    def test_root_identity_is_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                MODULE.initialize(root, uid=0, gid=0)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
