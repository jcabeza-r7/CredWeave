import io
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credweave as cw
import credweave_privileges as cp

class ExposureReportingTests(unittest.TestCase):
    def test_domain_provenance_and_group_detail(self):
        nodes = {
            'u': {'kind': 'User', 'label': 'SAM@A.LOCAL', 'objectId': 'S-1-5-21-100-1001', 'properties': {'domain': 'A.LOCAL'}},
            'c': {'kind': 'Computer', 'label': 'HOST@B.LOCAL', 'objectId': 'S-1-5-21-200-2001', 'properties': {'domain': 'B.LOCAL'}}}
        g = {'nodes': nodes, 'edges': [{'source': 'u', 'target': 'c', 'label': 'AdminTo'}]}
        registry = cw.Registry()
        a = registry.get('SAM', 'A.LOCAL'); b = registry.get('SAM', 'B.LOCAL')
        a.nt_hash = b.nt_hash = 'a'*32
        registry.bind_sid(a, 'S-1-5-21-100-1001')
        rows, groups = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g)]), registry, [('a'*32, [a,b])])
        self.assertEqual(rows[0]['Match Method'], 'SID')
        self.assertEqual(rows[0]['SID'], 'S-1-5-21-100-1001')
        self.assertEqual(groups[0]['Cross-Domain Reuse'], 'Yes')
        self.assertEqual(groups[0]['Administrative Account Count'], 1)
        self.assertIn('SAM@A.LOCAL', groups[0]['Account Details'])
        self.assertIn('SAM@B.LOCAL', groups[0]['Account Details'])
        out = io.StringIO()
        with redirect_stdout(out): cp.print_exposure(rows, groups)
        self.assertIn('Admin Accounts', out.getvalue())
        self.assertIn('Unique Targets', out.getvalue())
        self.assertIn('\x1b[1m\x1b[36m=== Administrative Privilege Exposure', out.getvalue())
        self.assertIn('\x1b[1m\x1b[36mCredential-reuse groups', out.getvalue())

    def test_exposure_console_prefers_registry_casing_without_mutating_csv(self):
        reg = cw.Registry()
        account = reg.get('svcMiXeD', 'ONE.EXAMPLE')
        reg.bind_sid(account, 'U-10')
        rows = [{'Account': 'SVCMIXED', 'Domain': 'ONE.EXAMPLE', 'SID': 'U-10',
                 'Direct AdminTo': 2, 'Inherited AdminTo': 3,
                 'Effective AdminTo': 4, 'Flags': 'BROAD_ADMIN', 'Tier Zero Targets': 0}]
        original = rows[0].copy()
        out = io.StringIO()
        with redirect_stdout(out):
            cp.print_exposure(rows, [], registry=reg)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', out.getvalue())
        self.assertIn('svcMiXeD', clean)
        self.assertIn('one.example', clean)
        self.assertNotIn('SVCMIXED', clean)
        self.assertEqual(rows[0], original)

    def test_exposure_console_graph_only_normalizes_casing(self):
        rows = [{'Account': 'GRAPHONLY', 'Domain': 'TWO.EXAMPLE', 'SID': '',
                 'Direct AdminTo': 0, 'Inherited AdminTo': 1,
                 'Effective AdminTo': 1, 'Flags': '', 'Tier Zero Targets': 0}]
        out = io.StringIO()
        with redirect_stdout(out):
            cp.print_exposure(rows, [])
        clean = re.sub(r'\x1b\[[0-9;]*m', '', out.getvalue())
        self.assertIn('graphonly', clean)
        self.assertIn('two.example', clean)
        self.assertEqual(rows[0]['Account'], 'GRAPHONLY')

    def test_exposure_console_never_uses_sid_from_other_domain(self):
        reg = cw.Registry()
        foreign = reg.get('ShouldNotDisplay', 'OTHER.EXAMPLE')
        reg.bind_sid(foreign, 'U-20')
        rows = [{'Account': 'TARGETNAME', 'Domain': 'ONE.EXAMPLE', 'SID': 'U-20',
                 'Direct AdminTo': 1, 'Inherited AdminTo': 0,
                 'Effective AdminTo': 1, 'Flags': '', 'Tier Zero Targets': 0}]
        out = io.StringIO()
        with redirect_stdout(out):
            cp.print_exposure(rows, [], registry=reg)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', out.getvalue())
        self.assertIn('targetname', clean)
        self.assertNotIn('ShouldNotDisplay', clean)

    def test_no_unqualified_match_or_fabricated_sid(self):
        g = {'nodes': {'u': {'kind':'User','label':'SAM@A.LOCAL','properties':{'domain':'A.LOCAL'}},
                       'c': {'kind':'Computer','label':'HOST@A.LOCAL','properties':{'domain':'A.LOCAL'}}},
             'edges':[{'source':'u','target':'c','label':'AdminTo'}]}
        reg = cw.Registry()
        a = reg.get('SAM', 'A.LOCAL'); a.nt_hash = 'a'*32
        rows, _ = cp.analyze_exposure(cp.merge_graphs([cp.parse_graph(g)]), reg, [])
        self.assertEqual(rows[0]['Match Method'], 'Domain+Username')
        self.assertEqual(rows[0]['SID'], '')

if __name__ == '__main__': unittest.main()
