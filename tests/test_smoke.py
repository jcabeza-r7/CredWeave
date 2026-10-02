import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "credweave.py"
spec = importlib.util.spec_from_file_location("credweave", SCRIPT)
cw = importlib.util.module_from_spec(spec)
sys.modules["credweave"] = cw
spec.loader.exec_module(cw)

class CredWeaveSmokeTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(cw.VERSION, "1.6.1")

    def test_help(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("--no-password-stats", p.stdout)
        self.assertNotIn("--password-stats", p.stdout)

    def test_adaptive_generation(self):
        hs = ["a"*32, "b"*32, "c"*32]
        result = {"hash_map": {h: [] for h in hs}}
        plains = {
            hs[0]: "Spring2025!",
            hs[1]: "Autumn2025!",
            hs[2]: "Welc0me2026!",
        }
        words, rules, masks = cw.generate_adaptive_cracking(plains, result)
        self.assertIn("spring", words)
        self.assertIn("autumn", words)
        self.assertTrue(rules)
        self.assertTrue(masks)
        self.assertTrue(all(w == w.lower() for w in words))

    def test_bloodhound_status_variants(self):
        self.assertTrue(cw.bloodhound_enabled({"enabled": True}))
        self.assertFalse(cw.bloodhound_enabled({"Enabled": "false"}))
        self.assertFalse(cw.bloodhound_enabled({"userAccountControl": 2}))
        self.assertTrue(cw.bloodhound_enabled({"userAccountControl": 512}))

if __name__ == "__main__":
    unittest.main()
