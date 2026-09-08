import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def configurable_paths(value, prefix=""):
    if isinstance(value, dict):
        paths = set()
        for key, child in value.items():
            if key != "_comment":
                paths |= configurable_paths(child, f"{prefix}.{key}" if prefix else key)
        return paths
    if isinstance(value, list):
        return {prefix}
    return {prefix}


class BaselineCapabilityMapTests(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads((ROOT / "config" / "baseline.json").read_text())
        self.capability_map = json.loads((ROOT / "config" / "baseline-capabilities.json").read_text())
        self.catalog = json.loads((ROOT / "config" / "runtime-control-catalog.json").read_text())

    def test_every_configurable_baseline_path_has_one_classification(self):
        paths = configurable_paths(self.baseline)
        entries = self.capability_map["Capabilities"]
        mapped = [entry["Path"] for entry in entries]
        self.assertEqual(len(mapped), len(set(mapped)))
        self.assertEqual(set(mapped), paths)

    def test_classifications_are_actionable_and_catalogued(self):
        control_ids = {control["Id"] for control in self.catalog["Controls"]}
        for entry in self.capability_map["Capabilities"]:
            self.assertIn(entry["State"], {"enforced", "scope_only", "unsupported"})
            self.assertTrue(entry["Explanation"].strip())
            self.assertTrue(set(entry["Controls"]) <= control_ids)
            if entry["State"] == "enforced":
                self.assertTrue(entry["Controls"], entry["Path"])


if __name__ == "__main__":
    unittest.main()
