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
        self.assertEqual(cw.VERSION, "1.6.5")

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

    def test_hashcat_hex_plaintexts(self):
        self.assertEqual(cw.decode_hashcat_plaintext("$HEX[64656d6f3a74776f]"), "demo:two")
        self.assertEqual(cw.decode_hashcat_plaintext("$HEX[706173733a776f7264]"), "pass:word")
        self.assertEqual(cw.decode_hashcat_plaintext("$HEX[70617373]"), "pass")
        self.assertEqual(cw.decode_hashcat_plaintext("$HEX[zz]"), "$HEX[zz]")
        self.assertEqual(cw.decode_hashcat_plaintext("$HEX[abc]"), "$HEX[abc]")
        self.assertEqual(cw.decode_hashcat_plaintext("$HEX[ff]"), "$HEX[ff]")
        self.assertEqual(cw.decode_hashcat_plaintext("ordinary!"), "ordinary!")

    def test_potfile_hex_ingestion(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pot = pathlib.Path(d) / "sample.pot"
            pot.write_text("a" * 32 + ":$HEX[706173733a776f7264]\n")
            self.assertEqual(cw.load_potfile(str(pot))["a" * 32], "pass:word")

    def test_bloodhound_status_variants(self):
        self.assertTrue(cw.bloodhound_enabled({"enabled": True}))
        self.assertFalse(cw.bloodhound_enabled({"Enabled": "false"}))
        self.assertFalse(cw.bloodhound_enabled({"userAccountControl": 2}))
        self.assertTrue(cw.bloodhound_enabled({"userAccountControl": 512}))

if __name__ == "__main__":
    unittest.main()
