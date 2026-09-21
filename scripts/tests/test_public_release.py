"""Public builds allow protocol messages but reject engine/model dependencies and payloads."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-public-release.py"
SPEC = importlib.util.spec_from_file_location("public_release", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class PublicReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def check_package(self, name, source="registry+https://github.com/rust-lang/crates.io-index"):
        lockfile = self.root / "Cargo.lock"
        lockfile.write_text(f'[[package]]\nname = "{name}"\nsource = "{source}"\n')
        release.check_dependencies(lockfile)

    def test_public_protocol_is_allowed_and_private_git_is_rejected(self):
        self.check_package("takis-biometric-engine-protocol")
        self.check_package("flamingo-verifier-sandbox-client")
        for source in ("", "git+https://github.com/worldcoin/biometric-engines"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.check_package("takis-biometric-engine-protocol", source)

    def test_engine_and_model_dependencies_are_rejected(self):
        for name in ("biometric-engines-worker", "face-engine", "flamingo-verifier-worker", "ort", "ort-sys", "hf-hub", "onnxruntime-sys"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check_package(name)
        with self.assertRaises(ValueError):
            self.check_package("renamed-engine", "git+https://github.com/worldcoin/biometric-engines?rev=abc")

    def populate(self, workload):
        for name in release.release_assets(workload):
            (self.root / name).write_bytes(b"release fixture")

    def test_exact_verifier_assets_are_allowed(self):
        self.populate("verifier")
        release.check_assets(self.root, "verifier")
        with self.assertRaises(ValueError):
            release.release_assets("di")

    def test_added_payloads_and_directories_are_rejected(self):
        self.populate("verifier")
        for name in ("worker.bundle", "biometric-engines-worker", "model.onnx", "unexpected.bin"):
            path = self.root / name
            path.write_bytes(b"private payload")
            with self.subTest(name=name), self.assertRaises(ValueError):
                release.check_assets(self.root, "verifier")
            path.unlink()
        (self.root / "nix").mkdir()
        with self.assertRaises(ValueError):
            release.check_assets(self.root, "verifier")

    def test_missing_empty_directory_and_symlink_assets_are_rejected(self):
        self.populate("verifier")
        path = self.root / "verifier-enclave.eif"
        path.unlink()
        with self.assertRaises(ValueError):
            release.check_assets(self.root, "verifier")
        path.touch()
        with self.assertRaises(ValueError):
            release.check_assets(self.root, "verifier")
        path.unlink()
        path.mkdir()
        with self.assertRaises(ValueError):
            release.check_assets(self.root, "verifier")
        path.rmdir()
        path.symlink_to(self.root / "manifest.json")
        with self.assertRaises(ValueError):
            release.check_assets(self.root, "verifier")


if __name__ == "__main__":
    unittest.main()
