import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credweave as cw
import credweave_privileges as cp


def graph():
    return {'nodes': {
        'u': {'kind': 'User', 'label': 'TESTUSER@A.LOCAL', 'objectId': 'S-U', 'properties': {'domain': 'A.LOCAL'}},
        'c': {'kind': 'Computer', 'label': 'SERVER@B.LOCAL', 'objectId': 'S-C', 'properties': {'domain': 'B.LOCAL', 'name': 'SERVER@B.LOCAL'}, 'isTierZero': True}},
        'edges': [{'source': 'u', 'target': 'c', 'label': 'AdminTo'}, {'source': 'u', 'target': 'c', 'label': 'AdminTo'}]}

class PrivilegeTests(unittest.TestCase):
    def test_direct_edges_deduplicated_and_cross_domain(self):
        merged = cp.merge_graphs([cp.parse_graph(graph()), cp.parse_graph(graph())])
        rows, groups = cp.analyze_exposure(merged, cw.Registry(), [], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['AdminTo Systems'], 1)
        self.assertIn('CROSS_DOMAIN', rows[0]['Flags'])
        self.assertIn('T0_ADMIN_ACCESS', rows[0]['Flags'])
        self.assertEqual(groups, [])

    def test_group_and_noncomputer_edges_excluded(self):
        g = graph()
        g['nodes']['u']['kind'] = 'Group'
        self.assertEqual(cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g)]), cw.Registry(), [])[0], [])

    def test_reuse_unique_target_union(self):
        g = graph()
        g['nodes']['v'] = {'kind': 'User', 'label': 'SECOND@A.LOCAL', 'objectId': 'S-V', 'properties': {'domain': 'A.LOCAL'}}
        g['edges'].append({'source': 'v', 'target': 'c', 'label': 'AdminTo'})
        reg = cw.Registry()
        a = reg.get('TESTUSER', 'A.LOCAL'); b = reg.get('SECOND', 'A.LOCAL')
        reg.bind_sid(a, 'S-U'); reg.bind_sid(b, 'S-V')
        a.nt_hash = b.nt_hash = 'a' * 32
        rows, groups = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g)]), reg, [('a'*32, [a,b])])
        self.assertEqual(len(rows), 2)
        self.assertEqual(groups[0]['AdminTo Relationships'], 2)
        self.assertEqual(groups[0]['Unique Admin Targets'], 1)

    def test_no_ambiguous_sam_matching(self):
        reg = cw.Registry()
        a = reg.get('TESTUSER')
        a.nt_hash = 'a'*32
        rows, _ = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(graph())]), reg, [])
        self.assertEqual(rows[0]['Credential Match'], 'No')

    def test_non_graph_ignored(self):
        self.assertIsNone(cp.parse_graph({'data': []}))

if __name__ == '__main__':
    unittest.main()
