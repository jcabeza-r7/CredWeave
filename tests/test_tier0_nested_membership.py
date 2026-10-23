"""Synthetic collector ZIP / graph regression fixtures. No engagement data."""
from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from credweave import Registry, import_bloodhound
from credweave_privileges import analyze_exposure, merge_graphs, parse_graph

DOM_A = 'ONE.EXAMPLE'
DOM_B = 'TWO.EXAMPLE'


def user(name, sid, domain=DOM_A):
    return {'ObjectIdentifier': sid, 'Properties': {'name': f'{name}@{domain}',
            'samaccountname': name, 'domain': domain, 'enabled': True}}


def group(name, sid, members=(), domain=DOM_A):
    return {'ObjectIdentifier': sid, 'Properties': {'name': f'{name}@{domain}',
            'samaccountname': name, 'domain': domain},
            'Members': [{'ObjectIdentifier': msid, 'ObjectType': typ} for msid, typ in members]}


def zip_collection(root: Path, filename: str, users=(), groups=()):
    path = root / filename
    with zipfile.ZipFile(path, 'w') as archive:
        for typ, records in (('users', users), ('groups', groups)):
            archive.writestr(f'{typ}.json', json.dumps({'meta': {'type': typ, 'version': 6},
                                                        'data': list(records)}))
    return str(path)


class TierZeroMembershipTests(unittest.TestCase):
    def test_nested_admins_with_cycle_provenance_and_direct_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = zip_collection(Path(tmp), 'collector.zip',
                users=[user('sample', 'U1')],
                groups=[group('Operations', 'G1', [('U1', 'User'), ('G2', 'Group')]),
                        group('Service Team', 'G2', [('G1', 'Group')]),
                        group('Administrators', 'G0', [('G2', 'Group')])])
            registry = Registry()
            counts = import_bloodhound(path, registry)
            account = registry.resolve('sample', DOM_A)
            self.assertEqual(counts['memberships'], 1)
            self.assertEqual(counts['nested_memberships'], 3)
            self.assertTrue(account.tier0)
            self.assertEqual(account.privilege_evidence['Tier 0'],
                ('Operations@ONE.EXAMPLE', 'Service Team@ONE.EXAMPLE',
                 'Administrators@ONE.EXAMPLE'))
            self.assertEqual(account.bh_effective_groups,
                {(DOM_A, 'Operations'), (DOM_A, 'Service Team'), (DOM_A, 'Administrators')})

    def test_second_collector_completes_membership_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = zip_collection(root, 'a.zip', [user('sample', 'U1')],
                                   [group('Team', 'G1', [('U1', 'User')])])
            second = zip_collection(root, 'b.zip', [],
                                    [group('Administrators', 'G2', [('G1', 'Group')])])
            registry = Registry()
            import_bloodhound(first, registry)
            self.assertFalse(registry.resolve('sample', DOM_A).tier0)
            import_bloodhound(second, registry)
            self.assertTrue(registry.resolve('sample', DOM_A).tier0)

    def test_same_named_group_in_another_domain_does_not_grant_t0(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = zip_collection(Path(tmp), 'collector.zip',
                users=[user('same', 'U1'), user('same', 'U2', DOM_B)],
                groups=[group('Team', 'G1', [('U1', 'User')]),
                        group('Team', 'G2', [('U2', 'User')], DOM_B),
                        group('Administrators', 'G3', [('G2', 'Group')], DOM_B)])
            registry = Registry()
            import_bloodhound(path, registry)
            self.assertFalse(registry.resolve('same', DOM_A).tier0)
            self.assertTrue(registry.resolve('same', DOM_B).tier0)

    def test_unnamed_member_without_sid_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'collector.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('users.json', json.dumps({'meta': {'type': 'users'},
                    'data': [user('same', 'U1'), user('same', 'U2', DOM_B)]}))
                g = group('Administrators', 'G3')
                g['Members'] = [{'Name': 'same'}]  # ambiguous short name
                z.writestr('groups.json', json.dumps({'meta': {'type': 'groups'}, 'data': [g]}))
            registry = Registry()
            import_bloodhound(str(path), registry)
            self.assertFalse(registry.resolve('same', DOM_A).tier0)
            self.assertFalse(registry.resolve('same', DOM_B).tier0)

    def test_foreign_domain_group_bridge_scopes_names_correctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = zip_collection(Path(tmp), 'collector.zip',
                users=[user('sample', 'U1')],
                groups=[group('Team', 'G1', [('U1', 'User')], DOM_B)])
            registry = Registry()
            import_bloodhound(path, registry)
            graph = {'nodes': {
                '1': {'kind': 'User', 'label': 'SAMPLE@ONE.EXAMPLE', 'objectId': 'U1'},
                '2': {'kind': 'Group', 'label': 'TEAM@TWO.EXAMPLE', 'objectId': 'G1'},
                '3': {'kind': 'Group', 'label': 'TEAM@ONE.EXAMPLE', 'objectId': 'G2'},
                '4': {'kind': 'Computer', 'label': 'HOST.TWO.EXAMPLE', 'objectId': 'C1'}},
                'edges': [{'source': '2', 'target': '4', 'label': 'AdminTo'}]}
            merged = merge_graphs([parse_graph(graph)], registry)
            self.assertEqual(len(next(iter(merged.values()))['inherited']), 1)

    def test_merge_preserves_true_tier_zero_from_later_graph(self):
        def make(t0):
            return parse_graph({'nodes': {'u': {'kind': 'User',
                'label': 'SAMPLE@ONE.EXAMPLE', 'objectId': 'U1',
                'properties': {'domain': DOM_A, 'isTierZero': t0}}}, 'edges': []})
        merged = merge_graphs([make(False), make(True)])
        self.assertTrue(merged[('sid', 'u1')]['user']['tier0'])
        merged_rev = merge_graphs([make(True), make(False)])
        self.assertTrue(merged_rev[('sid', 'u1')]['user']['tier0'])

    def test_nested_account_flag_in_privilege_exposure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = zip_collection(Path(tmp), 'collector.zip', [user('sample', 'U1')],
                [group('Team', 'G1', [('U1', 'User')]),
                 group('Administrators', 'G2', [('G1', 'Group')])])
            registry = Registry()
            import_bloodhound(path, registry)
            graph = parse_graph({'nodes': {
                'u': {'kind': 'User', 'label': 'SAMPLE@ONE.EXAMPLE', 'objectId': 'U1'},
                'g': {'kind': 'Group', 'label': 'TEAM@ONE.EXAMPLE', 'objectId': 'G1'},
                'c': {'kind': 'Computer', 'label': 'HOST.ONE.EXAMPLE', 'objectId': 'C1'}},
                'edges': [{'source': 'g', 'target': 'c', 'label': 'AdminTo'}]})
            rows, _ = analyze_exposure(merge_graphs([graph], registry), registry, [])
            self.assertEqual(len(rows), 1)
            self.assertIn('T0_ACCOUNT', rows[0]['Flags'])
            self.assertEqual(rows[0]['Inherited AdminTo'], 1)


if __name__ == '__main__':
    unittest.main()
