import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credweave as cw

H1 = 'a'*32
H2 = 'b'*32
LM = cw.LM_DISABLED_HASH

class MultiDomainTests(unittest.TestCase):
    def dump(self, path, lines):
        path.write_text('\n'.join(lines)+'\n')

    def test_labeled_dumps_preserve_duplicate_sam_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/'a.txt', Path(tmp)/'b.txt'
            self.dump(a, [f'same:1000:{LM}:{H1}:::'])
            self.dump(b, [f'same:1001:{LM}:{H1}:::'])
            r = cw.Registry()
            cw.parse_dump(str(a), r, domain_hint='A.LOCAL')
            cw.parse_dump(str(b), r, domain_hint='B.LOCAL')
            self.assertEqual(len(cw.human_accounts(r)), 2)
            self.assertEqual(len(cw.analyze(r)['reused']), 1)
            self.assertIsNone(r.resolve('same'))

    def test_ambiguous_unqualified_does_not_merge(self):
        r = cw.Registry()
        u = r.get('same'); u.nt_hash = H1
        r.get('same','A.LOCAL'); r.get('same','B.LOCAL')
        self.assertEqual(len(cw.reconcile_unqualified_accounts(r)), 1)
        self.assertEqual(len(cw.human_accounts(r)), 1)

    def test_unique_legacy_account_reconciles(self):
        r = cw.Registry()
        u = r.get('same'); u.nt_hash = H1
        r.get('same','A.LOCAL')
        self.assertEqual(cw.reconcile_unqualified_accounts(r), [])
        self.assertEqual(len(cw.human_accounts(r)), 1)
        self.assertEqual(r.resolve('same','A.LOCAL').nt_hash, H1)

    def test_embedded_domain_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'dump.txt'
            self.dump(path,[f'A.LOCAL\\\\same:1000:{LM}:{H1}:::'])
            with self.assertRaises(ValueError):
                cw.parse_dump(str(path), cw.Registry(), domain_hint='B.LOCAL')

    def test_explicit_alias_normalizes_mixed_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'mixed.txt'
            self.dump(path, [
                f'alias.example\\sysadmin:1000:{LM}:{H1}:::',
                f'corp.example\\operator:1001:{LM}:{H2}:::',
            ])
            registry = cw.Registry()
            counts = {}
            users, _, skipped = cw.parse_dump(
                str(path), registry, domain_hint='CORP.EXAMPLE',
                domain_aliases=cw.parse_domain_aliases(['ALIAS.EXAMPLE=CORP.EXAMPLE']),
                alias_counts=counts,
            )
            self.assertEqual((len(users), skipped), (2, 0))
            self.assertEqual(counts, {('ALIAS.EXAMPLE', 'CORP.EXAMPLE'): 1})
            self.assertEqual(registry.resolve('sysadmin', 'CORP.EXAMPLE').nt_hash, H1)
            self.assertEqual(registry.resolve('operator', 'CORP.EXAMPLE').nt_hash, H2)

    def test_alias_does_not_merge_other_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/'a.txt', Path(tmp)/'b.txt'
            self.dump(a, [f'alias.example\\same:1000:{LM}:{H1}:::'])
            self.dump(b, [f'OTHER.EXAMPLE\\same:1001:{LM}:{H1}:::'])
            registry = cw.Registry()
            aliases = cw.parse_domain_aliases(['ALIAS.EXAMPLE=CORP.EXAMPLE'])
            cw.parse_dump(str(a), registry, domain_hint='CORP.EXAMPLE', domain_aliases=aliases)
            cw.parse_dump(str(b), registry, domain_hint='OTHER.EXAMPLE', domain_aliases=aliases)
            self.assertEqual(len(cw.human_accounts(registry)), 2)
            self.assertIsNone(registry.resolve('same'))
            self.assertEqual(len(cw.analyze(registry)['reused']), 1)

    def test_alias_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'mixed.txt'
            self.dump(path, [f'UNRELATED.COM\\same:1000:{LM}:{H1}:::'])
            with self.assertRaisesRegex(ValueError, 'conflicts with label'):
                cw.parse_dump(str(path), cw.Registry(), domain_hint='CORP.EXAMPLE',
                              domain_aliases=cw.parse_domain_aliases(['ALIAS.EXAMPLE=CORP.EXAMPLE']))

    def test_alias_cycles_and_conflicts_rejected(self):
        for specs in (["A=B", "B=A"], ["A=B", "A=C"], ["A=A"]):
            with self.subTest(specs=specs), self.assertRaises(ValueError):
                cw.parse_domain_aliases(specs)

    def test_alias_collision_with_conflicting_hashes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'mixed.txt'
            self.dump(path, [
                f'alias.example\\same:1000:{LM}:{H1}:::',
                f'corp.example\\same:1000:{LM}:{H2}:::',
            ])
            with self.assertRaisesRegex(ValueError, 'conflicting NT hashes'):
                cw.parse_dump(str(path), cw.Registry(), domain_hint='CORP.EXAMPLE',
                              domain_aliases=cw.parse_domain_aliases(['ALIAS.EXAMPLE=CORP.EXAMPLE']))

    def test_same_name_different_hash_not_merged(self):
        r=cw.Registry()
        a=r.get('same','A.LOCAL'); b=r.get('same','B.LOCAL')
        a.nt_hash=H1; b.nt_hash=H2
        self.assertEqual(len(cw.analyze(r)['reused']),0)

if __name__ == '__main__': unittest.main()
