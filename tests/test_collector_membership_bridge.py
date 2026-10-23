import unittest
from credweave import Registry
from credweave_privileges import merge_graphs, parse_graph


class CollectorMembershipBridgeTests(unittest.TestCase):
    def test_group_admin_inherited_from_collector_membership(self):
        user_sid = 'S-1-5-21-100-1100'
        graph = {'nodes': {
            'u': {'kind': 'User', 'label': 'ALICE@EXAMPLE.TEST', 'objectId': user_sid, 'properties': {'domain': 'EXAMPLE.TEST'}},
            'g': {'kind': 'Group', 'label': 'DOMAIN ADMINS@EXAMPLE.TEST', 'objectId': 'S-1-5-21-100-512', 'properties': {'domain': 'EXAMPLE.TEST'}},
            'c1': {'kind': 'Computer', 'label': 'HOST1.EXAMPLE.TEST', 'objectId': 'S-1-5-21-100-2001', 'properties': {'domain': 'EXAMPLE.TEST'}},
            'c2': {'kind': 'Computer', 'label': 'HOST2.EXAMPLE.TEST', 'objectId': 'S-1-5-21-100-2002', 'properties': {'domain': 'EXAMPLE.TEST'}},
        }, 'edges': [
            {'source': 'u', 'target': 'c1', 'label': 'AdminTo'},
            {'source': 'g', 'target': 'c1', 'label': 'AdminTo'},
            {'source': 'g', 'target': 'c2', 'label': 'AdminTo'},
        ]}
        registry = Registry()
        account = registry.get('alice', 'EXAMPLE.TEST')
        registry.bind_sid(account, user_sid)
        account.groups.add('Domain Admins')
        result = merge_graphs([parse_graph(graph)], registry)[('sid', user_sid.casefold())]
        self.assertEqual((len(result['direct']), len(result['inherited']), len(result['targets'])), (1, 2, 2))

    def test_does_not_cross_domain_group_names(self):
        graph = {'nodes': {
            'u': {'kind': 'User', 'label': 'ALICE@ONE.TEST', 'properties': {'domain': 'ONE.TEST'}},
            'g': {'kind': 'Group', 'label': 'DOMAIN ADMINS@TWO.TEST', 'properties': {'domain': 'TWO.TEST'}},
            'c': {'kind': 'Computer', 'label': 'HOST.TWO.TEST', 'properties': {'domain': 'TWO.TEST'}},
        }, 'edges': [{'source': 'g', 'target': 'c', 'label': 'AdminTo'}]}
        registry = Registry()
        registry.get('alice', 'ONE.TEST').groups.add('Domain Admins')
        result = next(iter(merge_graphs([parse_graph(graph)], registry).values()))
        self.assertFalse(result['targets'])
