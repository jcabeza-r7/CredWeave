"""Synthetic debug-display coverage; no real assessment data."""
from __future__ import annotations

import contextlib
import io
import re
import unittest

from credweave import Registry
from credweave_privileges import (
    format_debug_identity, merge_graphs, parse_graph, print_privilege_debug,
)

ANSI = re.compile(r'\x1b\[[0-9;]*m')


class PrivilegeDebugPresentationTests(unittest.TestCase):
    def setUp(self):
        self.registry = Registry()
        self.account = self.registry.get('svcMixedCase', 'ONE.EXAMPLE')
        self.registry.bind_sid(self.account, 'U-1')
        self.account.bh_effective_groups.add(('ONE.EXAMPLE', 'OpsTeam'))
        self.graph = parse_graph({'nodes': {
            'u': {'kind': 'User', 'label': 'SVCMIXEDCASE@ONE.EXAMPLE', 'objectId': 'U-1'},
            'g': {'kind': 'Group', 'label': 'OPSTEAM@ONE.EXAMPLE', 'objectId': 'G-1'},
            'c': {'kind': 'Computer', 'label': 'SERVER01.ONE.EXAMPLE', 'objectId': 'C-1',
                  'properties': {'domain': 'ONE.EXAMPLE'}},
        }, 'edges': [
            {'source': 'u', 'target': 'g', 'label': 'MemberOf'},
            {'source': 'g', 'target': 'c', 'label': 'AdminTo'},
            {'source': 'u', 'target': 'c', 'label': 'AdminTo'},
        ]})
        self.merged = merge_graphs([self.graph])

    def _render(self, registry):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertTrue(print_privilege_debug(self.merged,
                'SVCMIXEDCASE@ONE.EXAMPLE', registry=registry))
        return stream.getvalue()

    def test_ansi_and_registry_casing_display_only(self):
        output = self._render(self.registry)
        self.assertIn('\x1b[36m', output)
        self.assertIn('\x1b[33m', output)
        self.assertIn('\x1b[32m', output)
        clean = ANSI.sub('', output)
        self.assertIn('Privilege Debug: svcMixedCase@one.example', clean)
        self.assertIn('OpsTeam@one.example', clean)
        self.assertIn('server01.one.example [one.example]', clean)
        self.assertIn('Direct: 1', clean)
        self.assertIn('Inherited: 1', clean)
        self.assertIn('Effective: 1', clean)
        self.assertIn('Direct AdminTo', clean)
        self.assertEqual(self.merged[('sid', 'u-1')]['user']['name'],
                         'SVCMIXEDCASE@ONE.EXAMPLE')

    def test_fallback_normalizes_all_caps_for_display(self):
        clean = ANSI.sub('', self._render(None))
        self.assertIn('Privilege Debug: svcmixedcase@one.example', clean)
        self.assertIn('opsteam@one.example', clean)
        self.assertNotIn('SVCMIXEDCASE@ONE.EXAMPLE', clean)

    def test_mixed_case_and_domain_display(self):
        self.assertEqual(format_debug_identity('McAdmin@ONE.EXAMPLE'), 'McAdmin@one.example')
        self.assertEqual(format_debug_identity('NODE01.ONE.EXAMPLE'), 'node01.one.example')

    def test_not_found_warning_colored(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertFalse(print_privilege_debug(self.merged, 'NOTFOUND@ONE.EXAMPLE'))
        self.assertIn('\x1b[33m', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
