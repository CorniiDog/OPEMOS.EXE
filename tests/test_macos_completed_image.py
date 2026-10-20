"""Actual file/hash guards only; fixtures are never product acceptance."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_macos_arm64_ci import verify_completed_image


class CompletedImageFiles(unittest.TestCase):
    def test_complete_transaction_and_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.img"
            source.write_bytes(b"immutable fixture source")
            source.chmod(0o444)
            image = root / "output.img"
            image.write_bytes(b"changed output" * 10000)
            manifest = root / "output.manifest.json"
            sha = hashlib.sha256(source.read_bytes()).hexdigest()
            value = {"schemaVersion": 1, "resultClass": "nvidia-mutation-valid",
                     "input": {"sourceSha256": sha},
                     "output": {"filename": image.name, "format": "raw", "bytes": image.stat().st_size,
                                "sha256": hashlib.sha256(image.read_bytes()).hexdigest()},
                     "validation": {key: True for key in ("passed", "sourceUnchanged", "candidateAttachedReadOnly", "layoutRecognized", "markerVerified", "nvidiaPayloadVerified")}}
            def store():
                manifest.write_text(json.dumps(value))
            store()
            events = [{"kind": "completed-image-ui-observed", "text":
                       f"Exported image: {image}; {image.stat().st_size} bytes; raw layout=gpt.\nBuild manifest: {manifest}.\n"}]
            result = verify_completed_image(events, source, sha)
            self.assertTrue(result["fullFileRead"])
            self.assertEqual(result["sha256"], value["output"]["sha256"])
            with self.assertRaises(RuntimeError):
                verify_completed_image([], source, sha)
            value["resultClass"] = "mutation-valid"
            store()
            with self.assertRaises(RuntimeError):
                verify_completed_image(events, source, sha)
            value["resultClass"] = "nvidia-mutation-valid"
            store()
            original = image.read_bytes()
            image.write_bytes(b"x" * len(original))
            with self.assertRaises(RuntimeError):
                verify_completed_image(events, source, sha)
            image.unlink()
            image.symlink_to(source)
            with self.assertRaises(RuntimeError):
                verify_completed_image(events, source, sha)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), sha)


if __name__ == "__main__":
    unittest.main()
