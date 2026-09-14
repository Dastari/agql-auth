"""Exercise release rejection paths in disposable repositories."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.previous_root = release.ROOT
        release.ROOT = self.root
        self.addCleanup(setattr, release, "ROOT", self.previous_root)
        self.git("init", "-q")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release@example.invalid")
        self.write_package("0.19.0")
        (self.root / "CHANGELOG.md").write_text("# Changelog\n\n## 0.19.0\n\nInitial\n")
        (self.root / "Cargo.lock").write_text("version = 4\n")
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("pub fn existing() {}\n")
        self.commit()
        self.git("tag", "v0.19.0")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def write_package(self, version, publish="false", features=""):
        (self.root / "Cargo.toml").write_text(
            '[package]\nname = "agql-auth"\nversion = "' + version + '"\n'
            'repository = "https://github.com/Dastari/agql-auth"\npublish = ' + publish + '\n' + features)

    def test_documentation_only_keeps_version(self):
        (self.root / "README.md").write_text("Release documentation\n")
        with contextlib.redirect_stdout(io.StringIO()):
            release.check_policy()

    def test_source_change_requires_bump(self):
        (self.root / "src/lib.rs").write_text("pub fn changed() {}\n")
        with self.assertRaisesRegex(ValueError, "version bump"):
            release.check_policy()

    def test_bump_requires_matching_changelog(self):
        self.write_package("0.19.1")
        with self.assertRaisesRegex(ValueError, "top changelog"):
            release.check_policy()
        (self.root / "CHANGELOG.md").write_text("# Changelog\n\n## 0.19.1\n\nFixed\n")
        with contextlib.redirect_stdout(io.StringIO()):
            release.check_policy()

    def test_reject_registry_publication(self):
        self.write_package("0.19.0", publish="true")
        with self.assertRaisesRegex(ValueError, "publish must remain false"):
            release.check_state()

    def test_new_features_require_validation_lanes(self):
        self.write_package("0.19.0", features='[features]\nnew = []\n')
        with self.assertRaisesRegex(ValueError, "explicit validation lanes"):
            release.check_state()

    def test_historical_qualified_tags_are_not_baselines(self):
        self.git("tag", "agql-auth/v9.0.0")
        self.git("tag", "v99.0.0-preview")
        self.assertEqual(release.latest_tag(), "v0.19.0")

    def test_manifest_is_deterministic_and_binds_committed_lock(self):
        output = self.root / "release.json"
        with contextlib.redirect_stdout(io.StringIO()):
            release.manifest(output)
            first = output.read_bytes()
            release.manifest(output)
        self.assertEqual(first, output.read_bytes())
        data = json.loads(first)
        self.assertEqual(data["commit"], self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(data["tag"], "v0.19.0")
        self.assertEqual(data["cargoLock"], release.hashlib.sha256((self.root / "Cargo.lock").read_bytes()).hexdigest())
        (self.root / "Cargo.lock").write_text("version = 3\n")
        with self.assertRaisesRegex(ValueError, "clean committed tree"):
            release.manifest(output)

    def test_untracked_lock_is_rejected(self):
        self.git("rm", "--cached", "Cargo.lock")
        self.git("commit", "-qm", "untrack lock")
        with self.assertRaises(subprocess.CalledProcessError):
            release.manifest(self.root / "release.json")


if __name__ == "__main__":
    unittest.main()
