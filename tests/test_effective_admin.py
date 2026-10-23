import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credweave as cw
import credweave_privileges as cp


def node(kind, name, sid, tier=False):
    return {'kind': kind, 'label': name, 'objectId': sid, 'isTierZero': tier,
            'properties': {'domain': name.split('@')[-1]}}


class EffectiveAdminTests(unittest.TestCase):
    def test_nested_cycle_dedup_and_reuse(self):
        g = {'nodes': {'u': node('User','ALICE@A.LOCAL','S-U'),
                       'g': node('Group','OPS@A.LOCAL','S-G'),
                       'da': node('Group','DOMAIN ADMINS@A.LOCAL','S-DA'),
                       'c': node('Computer','DC@A.LOCAL','S-C', True)},
             'edges': [{'source':'u','target':'g','label':'MemberOf'},
                       {'source':'g','target':'da','label':'MemberOf'},
                       {'source':'da','target':'g','label':'MemberOf'},
                       {'source':'da','target':'c','label':'AdminTo'},
                       {'source':'u','target':'c','label':'AdminTo'}]}
        reg = cw.Registry()
        a = reg.get('ALICE','A.LOCAL'); reg.bind_sid(a,'S-U'); a.nt_hash = 'a'*32
        b = reg.get('BOB','B.LOCAL'); b.nt_hash = 'a'*32
        rows, groups = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g),cp.parse_graph(g)]),reg,[('a'*32,[a,b])])
        self.assertEqual(len(rows),1)
        self.assertEqual((rows[0]['Direct AdminTo'],rows[0]['Inherited AdminTo'],rows[0]['Effective AdminTo']),(1,1,1))
        self.assertIn('DOMAIN ADMINS@A.LOCAL',rows[0]['Granting Groups'])
        self.assertIn('T0_ADMIN_ACCESS',rows[0]['Flags'])
        self.assertEqual(groups[0]['Unique Admin Targets'],1)
        self.assertEqual(groups[0]['Cross-Domain Reuse'],'Yes')

    def test_group_only_and_isolated_user(self):
        g = {'nodes': {'u':node('User','ALICE@A.LOCAL','S-U'),
                       'g':node('Group','OPS@A.LOCAL','S-G'),
                       'c':node('Computer','HOST@A.LOCAL','S-C')},
             'edges':[{'source':'u','target':'g','label':'MemberOf'},
                      {'source':'g','target':'c','label':'AdminTo'}]}
        rows,_ = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g)]),cw.Registry(),[])
        self.assertEqual((rows[0]['Direct AdminTo'],rows[0]['Inherited AdminTo'],rows[0]['Effective AdminTo']),(0,1,1))

    def test_separate_same_username_domains(self):
        g = {'nodes': {'u':node('User','SAM@A.LOCAL','S-A'),
                       'v':node('User','SAM@B.LOCAL','S-B'),
                       'c':node('Computer','HOST@A.LOCAL','S-C')},
             'edges':[{'source':'u','target':'c','label':'AdminTo'}]}
        rows,_ = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g)]),cw.Registry(),[])
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['Domain'],'A.LOCAL')

if __name__ == '__main__': unittest.main()
