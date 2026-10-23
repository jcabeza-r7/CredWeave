"""Synthetic regression tests: no client identities or credential material."""
import unittest
from credweave_privileges import parse_graph, merge_graphs, graph_diagnostics


def graph(nodes, edges):
    return {'nodes': {str(i): {'kind': kind, 'label': name, 'objectId': sid,
                               'properties': {'domain': 'EXAMPLE.TEST'}}
                      for i, kind, name, sid in nodes},
            'edges': [{'source': str(a), 'target': str(b), 'kind': rel} for a, b, rel in edges]}


class UnifiedGraphTests(unittest.TestCase):
    def test_nested_inherited_only_cycle_and_overlap(self):
        # Node ids intentionally differ between exports. SID is the stable join key.
        memberships = graph([(1,'User','SAMPLE@EXAMPLE.TEST','S-1-5-21-1-100'),
                             (2,'Group','TEAM@EXAMPLE.TEST','S-1-5-21-1-200'),
                             (3,'Group','OPS@EXAMPLE.TEST','S-1-5-21-1-300')],
                            [(1,2,'MemberOf'),(2,3,'MemberOf'),(3,2,'MemberOf')])
        grants = graph([(20,'Group','OPS@EXAMPLE.TEST','S-1-5-21-1-300'),
                        (30,'Computer','HOST@EXAMPLE.TEST','S-1-5-21-1-400')],
                       [(20,30,'AdminTo'),(20,30,'AdminTo')])
        merged = merge_graphs([parse_graph(memberships),parse_graph(grants)])
        row = next(iter(merged.values()))
        self.assertEqual(len(row['direct']),0)
        self.assertEqual(len(row['inherited']),1)
        self.assertEqual(len(row['targets']),1)
        self.assertEqual(next(iter(row['paths'].values()))[0],
                         ('TEAM@EXAMPLE.TEST','OPS@EXAMPLE.TEST'))

    def test_direct_inherited_overlap(self):
        data=graph([(1,'User','SAMPLE@EXAMPLE.TEST','U1'),
                    (2,'Group','OPS@EXAMPLE.TEST','G1'),
                    (3,'Computer','HOST@EXAMPLE.TEST','C1')],
                   [(1,2,'MemberOf'),(1,3,'AdminTo'),(2,3,'AdminTo')])
        row=next(iter(merge_graphs([parse_graph(data)]).values()))
        self.assertEqual((len(row['direct']),len(row['inherited']),len(row['targets'])),(1,1,1))

if __name__ == '__main__': unittest.main()
