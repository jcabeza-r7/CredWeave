"""Read-only BloodHound graph administrative exposure with nested group inheritance.

Only explicit AdminTo edges are counted. MemberOf edges convey inheritance, not
new AdminTo grants. Results describe graph-observed reach, not verified access.
"""
from __future__ import annotations

import csv
from collections import defaultdict, deque
from pathlib import Path


def parse_graph(obj):
    if not isinstance(obj, dict) or not isinstance(obj.get('nodes'), dict) or not isinstance(obj.get('edges'), list):
        return None
    users, groups, computers = {}, {}, {}
    for nid, node in obj['nodes'].items():
        if not isinstance(node, dict):
            continue
        props = node.get('properties') or {}
        label = str(node.get('label') or props.get('name') or '').strip()
        domain = str(props.get('domain') or '').strip().upper()
        if not domain and '@' in label:
            domain = label.rsplit('@', 1)[1].upper()
        kind = str(node.get('kind') or '').casefold()
        tags = props.get('system_tags') or []
        tier0 = bool(node.get('isTierZero') or props.get('isTierZero') or
                     (isinstance(tags, str) and 'admin_tier_0' in tags.casefold()) or
                     (isinstance(tags, list) and any('admin_tier_0' in str(t).casefold() for t in tags)))
        record = {'name': label, 'domain': domain, 'sid': str(node.get('objectId') or props.get('objectid') or ''),
                  'tier0': tier0, 'enabled': props.get('enabled'), 'description': str(props.get('description') or '')}
        if kind == 'user':
            users[str(nid)] = record
        elif kind == 'group':
            groups[str(nid)] = record
        elif kind == 'computer':
            computers[str(nid)] = record
    direct = defaultdict(set)
    group_admin = defaultdict(set)
    memberships = defaultdict(set)
    for edge in obj['edges']:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get('label') or edge.get('kind') or '').casefold()
        source, target = str(edge.get('source')), str(edge.get('target'))
        if relation == 'adminto' and target in computers:
            c = computers[target]
            t = (c['sid'] or f'{c["name"].casefold()}@{c["domain"]}', c['name'], c['domain'], c['tier0'])
            if source in users:
                direct[source].add(t)
            elif source in groups:
                group_admin[source].add(t)
        elif relation == 'memberof' and (source in users or source in groups) and target in groups:
            memberships[source].add(target)
    return users, groups, direct, group_admin, memberships


def _identity(record):
    return ('sid', record['sid'].casefold()) if record['sid'] else ('name', record['name'].casefold(), record['domain'])


def _merge_node(records, identity, incoming):
    """Combine enrichment from repeated nodes, preserving positive Tier 0 evidence.

    A missing/false classification in one graph must not erase a true indicator
    from another export. Enabled-state conflicts are deliberately unresolved.
    """
    if identity not in records:
        records[identity] = dict(incoming)
        return
    existing = records[identity]
    existing['tier0'] = bool(existing.get('tier0') or incoming.get('tier0'))
    for field in ('name', 'sid', 'domain', 'description'):
        if not existing.get(field) and incoming.get(field):
            existing[field] = incoming[field]
    if existing.get('enabled') is None:
        if not existing.get('_enabled_conflict'):
            existing['enabled'] = incoming.get('enabled')
    elif incoming.get('enabled') is not None and existing['enabled'] != incoming['enabled']:
        existing['enabled'] = None
        existing['_enabled_conflict'] = True


def merge_graphs(graphs, registry=None):
    """Merge graph nodes by SID or qualified name, then resolve group paths.

    Graph-local node identifiers are never used across graph boundaries.
    """
    users, groups = {}, {}
    direct, group_admin, memberships = defaultdict(set), defaultdict(set), defaultdict(set)
    for raw_users, raw_groups, raw_direct, raw_group_admin, raw_memberships in graphs:
        user_ids = {nid: _identity(u) for nid, u in raw_users.items()}
        group_ids = {nid: _identity(g) for nid, g in raw_groups.items()}
        for nid, user in raw_users.items():
            _merge_node(users, user_ids[nid], user)
            direct[user_ids[nid]].update(raw_direct.get(nid, ()))
        for nid, group in raw_groups.items():
            _merge_node(groups, group_ids[nid], group)
            group_admin[group_ids[nid]].update(raw_group_admin.get(nid, ()))
        for source, targets in raw_memberships.items():
            identity = user_ids.get(source, group_ids.get(source))
            if identity is not None:
                memberships[identity].update(group_ids[t] for t in targets if t in group_ids)
    # Collector ZIP membership is imported into Registry, not graph JSON.
    # Join it to exported Group AdminTo edges by domain-qualified group name.
    # Never join groups by short name alone across domains.
    if registry is not None:
        groups_by_name = defaultdict(set)
        for gid, group in groups.items():
            short = group['name'].split('@', 1)[0].casefold()
            groups_by_name[(group['domain'].casefold(), short)].add(gid)
        for account in registry.accounts.values():
            if not account.domain or not account.groups:
                continue
            user_id = ('sid', account.sid.casefold()) if account.sid else None
            if user_id not in users:
                user_id = next((uid for uid, user in users.items()
                                if user['domain'].casefold() == account.domain.casefold()
                                and user['name'].split('@', 1)[0].casefold() == account.username.casefold()), None)
            if user_id is None:
                continue
            # Collector-derived effective groups carry their OWN domain,
            # including foreign-domain membership. Legacy enrichment sources
            # still supply unqualified direct groups in account.groups.
            effective = {(d.casefold(), n.casefold()) for d, n in account.bh_effective_groups}
            for group_domain, group_name in effective:
                memberships[user_id].update(groups_by_name.get((group_domain, group_name), ()))
            effective_names = {name for _, name in effective}
            for group_name in account.groups:
                if group_name.casefold() not in effective_names:
                    memberships[user_id].update(groups_by_name.get((account.domain.casefold(), group_name.casefold()), ()))
    merged = {}
    for identity, user in users.items():
        # BFS retains one shortest, deterministic path to each granting group.
        queue = deque((gid, (gid,)) for gid in sorted(memberships.get(identity, ()), key=str))
        paths = {}
        while queue:
            gid, path = queue.popleft()
            if gid in paths:
                continue
            paths[gid] = path
            for parent in sorted(memberships.get(gid, ()), key=str):
                if parent not in paths and parent not in path:
                    queue.append((parent, path + (parent,)))
        inherited, granting = set(), defaultdict(set)
        evidence = defaultdict(list)
        for gid, path in paths.items():
            names = tuple(groups[g]['name'] for g in path)
            for target in group_admin.get(gid, ()):
                inherited.add(target)
                granting[target].add(groups[gid]['name'])
                evidence[target].append(names)
        direct_targets = direct.get(identity, set())
        merged[identity] = {'user': user, 'direct': direct_targets,
                            'inherited': inherited, 'targets': direct_targets | inherited,
                            'granting': granting, 'paths': evidence,
                            'groups': [groups[g] for g in paths]}
    return merged


def graph_diagnostics(graphs, registry=None):
    stats = defaultdict(int)
    for users, groups, direct, group_admin, memberships in graphs:
        stats['user_nodes'] += len(users)
        stats['group_nodes'] += len(groups)
        stats['direct_edges'] += sum(map(len, direct.values()))
        stats['group_admin_edges'] += sum(map(len, group_admin.values()))
        stats['user_memberships'] += sum(len(v) for k, v in memberships.items() if k in users)
        stats['nested_memberships'] += sum(len(v) for k, v in memberships.items() if k in groups)
    return stats


# Match the ANSI palette used by the main CredWeave terminal report.
_DEBUG_GREEN = '\033[32m'
_DEBUG_YELLOW = '\033[33m'
_DEBUG_CYAN = '\033[36m'
_DEBUG_BOLD = '\033[1m'
_DEBUG_DIM = '\033[2m'
_DEBUG_RESET = '\033[0m'


def format_debug_identity(label, domain='', preferred_name=None):
    """Present an identity without modifying canonical graph/CSV identifiers.

    The graph exporter often uppercases entire labels. Prefer the account or
    group spelling collected from AD; otherwise avoid rendering all-caps
    account/host labels as if they were headings. DNS domains are lowercased
    only for display (domain identifiers are case-insensitive).
    """
    label = str(label)
    if '@' in label:
        name, suffix = label.rsplit('@', 1)
        domain = suffix or domain
    else:
        name = label
    name = preferred_name or (name.lower() if name.isupper() else name)
    return f'{name}@{domain.lower()}' if domain else name


def _debug_registry_account(registry, user):
    if registry is None:
        return None
    account = registry.by_sid(user['sid']) if user['sid'] else None
    if account is not None and account.domain and user['domain'] and account.domain.casefold() != user['domain'].casefold():
        account = None
    if account is None:
        username = user['name'].split('@', 1)[0].rsplit('\\', 1)[-1]
        account = registry.resolve(username, user['domain']) if user['domain'] else None
    return account


def print_privilege_debug(merged, query, max_targets=30, registry=None):
    matches = []
    q = query.casefold()
    for item in merged.values():
        user = item['user']
        qualified = user['name'] if '@' in user['name'] else f"{user['name']}@{user['domain']}"
        if q in (qualified.casefold(), user['sid'].casefold()):
            matches.append(item)
    if not matches:
        print(f'{_DEBUG_YELLOW}[!]{_DEBUG_RESET} Privilege debug: account not found in graph: {query}')
        return False
    if len(matches) > 1:
        print(f'{_DEBUG_YELLOW}[!]{_DEBUG_RESET} Privilege debug: ambiguous account identity: {query}')
        return False

    item = matches[0]
    user = item['user']
    account = _debug_registry_account(registry, user)
    display_name = format_debug_identity(user['name'], user['domain'], account.username if account else None)
    preferred_groups = {}
    if account is not None:
        preferred_groups = {(domain.casefold(), name.casefold()): name
                            for domain, name in account.bh_effective_groups}

    print(f'\n{_DEBUG_BOLD}{_DEBUG_CYAN}=== Privilege Debug: {_DEBUG_RESET}'
          f'{_DEBUG_BOLD}{display_name}{_DEBUG_CYAN} ==={_DEBUG_RESET}')
    print(f'  {_DEBUG_DIM}Direct:{_DEBUG_RESET} {_DEBUG_CYAN}{len(item["direct"])}{_DEBUG_RESET}'
          f'  {_DEBUG_DIM}Inherited:{_DEBUG_RESET} {_DEBUG_YELLOW}{len(item["inherited"])}{_DEBUG_RESET}'
          f'  {_DEBUG_DIM}Effective:{_DEBUG_RESET} {_DEBUG_GREEN}{len(item["targets"])}{_DEBUG_RESET}')

    for target in sorted(item['targets'], key=lambda t: (t[2], t[1]))[:max_targets]:
        target_name = format_debug_identity(target[1])
        print(f'  {_DEBUG_CYAN}{target_name}{_DEBUG_RESET} '
              f'{_DEBUG_DIM}[{target[2].lower()}]{_DEBUG_RESET}')
        if target in item['direct']:
            print(f'    {_DEBUG_GREEN}Direct AdminTo{_DEBUG_RESET}')
        for path in sorted(item['paths'].get(target, ()), key=lambda p: (len(p), p)):
            display_path = []
            for group in path:
                group_name, separator, group_domain = group.rpartition('@')
                preferred = preferred_groups.get((group_domain.casefold(), group_name.casefold())) if separator else None
                display_path.append(format_debug_identity(group, preferred_name=preferred))
            print(f'    {_DEBUG_DIM}MemberOf{_DEBUG_RESET} '
                  + f' {_DEBUG_DIM}-> MemberOf{_DEBUG_RESET} '.join(
                      f'{_DEBUG_YELLOW}{group}{_DEBUG_RESET}' for group in display_path)
                  + f' {_DEBUG_DIM}-> AdminTo{_DEBUG_RESET}')
    remaining = len(item['targets']) - max_targets
    if remaining > 0:
        print(f'  {_DEBUG_DIM}... {remaining} additional target(s); '
              f'use --privilege-debug-limit to increase{_DEBUG_RESET}')
    return True


def analyze_exposure(merged, registry, reused, threshold=10):
    by_name = defaultdict(list)
    for account in registry.accounts.values():
        by_name[account.username.casefold()].append(account)
    rows, matched = [], {}
    for identity, item in merged.items():
        user, targets = item['user'], item['targets']
        if not targets:
            continue
        sam = user['name'].split('@', 1)[0].rsplit('\\', 1)[-1]
        domain = user['domain']
        account = registry.by_sid(user['sid']) if user['sid'] else None
        match_method = 'SID' if account is not None else 'None'
        if account is not None and account.domain and domain and account.domain.casefold() != domain.casefold():
            account, match_method = None, 'None'
        if account is None:
            candidates = [a for a in by_name.get(sam.casefold(), ()) if a.domain and domain and a.domain.casefold() == domain.casefold()]
            if len(candidates) == 1:
                account, match_method = candidates[0], 'Domain+Username'
        if account is not None:
            matched[id(account)] = targets
        domains = sorted({t[2] for t in targets if t[2]})
        t0targets = {t for t in targets if t[3]}
        flags = []
        if len(targets) >= threshold: flags.append('BROAD_ADMIN')
        if domain and any(d != domain for d in domains): flags.append('CROSS_DOMAIN')
        if account is not None and account.tier0: flags.append('T0_ACCOUNT')
        if t0targets: flags.append('T0_ADMIN_ACCESS')
        if 'test' in sam.casefold() or 'qa' in sam.casefold(): flags.append('TEST_NAMING')
        if 'svc' in sam.casefold() or 'service' in sam.casefold(): flags.append('SERVICE_NAMING')
        granting = sorted({g for names in item['granting'].values() for g in names})
        rows.append({'Account': sam, 'Domain': domain, 'AdminTo Systems': len(targets),
                     'Direct AdminTo': len(item['direct']), 'Inherited AdminTo': len(item['inherited']),
                     'Effective AdminTo': len(targets),
                     'Direct Targets': '; '.join(sorted(t[1] for t in item['direct'])),
                     'Inherited Targets': '; '.join(sorted(t[1] for t in item['inherited'])),
                     'Effective Targets': '; '.join(sorted(t[1] for t in targets)),
                     'Granting Groups': '; '.join(granting),
                     'Target Domains': '; '.join(domains), 'Tier Zero Targets': len(t0targets),
                     'Tier Zero Systems': '; '.join(sorted(t[1] for t in t0targets)),
                     'Flags': '; '.join(flags), 'SID': user['sid'],
                     'Credential Match': 'Yes' if account and account.nt_hash else 'No',
                     'Match Method': match_method if account and account.nt_hash else 'None',
                     'Review Status': 'Candidate - validate business need'})
    rows.sort(key=lambda r: (-r['Effective AdminTo'], r['Domain'], r['Account']))
    group_rows = []
    for h, accounts in reused:
        reachable, admin_accounts, details = set(), [], []
        relationships = 0
        for account in accounts:
            name = f'{account.username}@{account.domain or "UNKNOWN"}'
            status = 'Enabled' if account.enabled is True else 'Disabled' if account.enabled is False else 'Unknown'
            classification = 'Tier 0' if account.tier0 else 'Privileged' if account.privileged else 'Standard/Unclassified'
            details.append(f'{name} [{status}; {classification}]')
            if id(account) in matched:
                admin_accounts.append(name)
                relationships += len(matched[id(account)])
                reachable.update(matched[id(account)])
        if not reachable: continue
        domains = sorted({a.domain or 'UNKNOWN' for a in accounts})
        group_rows.append({'Hash': h, 'Accounts Sharing': len(accounts),
                           'Account Domains': '; '.join(domains),
                           'Cross-Domain Reuse': 'Yes' if len(domains) > 1 else 'No',
                           'Accounts by Domain': '; '.join(f'{d}: {sum((a.domain or "UNKNOWN") == d for a in accounts)}' for d in domains),
                           'Account Details': '; '.join(sorted(details, key=str.casefold)),
                           'Administrative Account Count': len(admin_accounts),
                           'Privileged Account Count': sum(a.privileged for a in accounts),
                           'Tier Zero Account Count': sum(a.tier0 for a in accounts),
                           'Admin Accounts': '; '.join(sorted(admin_accounts)),
                           'AdminTo Relationships': relationships,
                           'Unique Admin Targets': len(reachable),
                           'Target Domains': '; '.join(sorted({t[2] for t in reachable if t[2]})),
                           'Tier Zero Targets': sum(t[3] for t in reachable)})
    group_rows.sort(key=lambda r: (-r['Unique Admin Targets'], -r['Accounts Sharing'], r['Hash']))
    return rows, group_rows


def write_csv(path, rows, fields):
    with Path(path).open('w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def format_exposure_identity(row, registry=None):
    """Format the console-only identity without changing graph or CSV records.

    Prefer the registry's original username spelling for a verified SID or a
    unique domain-qualified match. Graph-only labels may be uppercased by the
    exporter, so normalize those for display, as in --privilege-debug.
    """
    username = str(row.get('Account') or '')
    domain = str(row.get('Domain') or '')
    account = None
    if registry is not None:
        sid = str(row.get('SID') or '')
        account = registry.by_sid(sid) if sid else None
        if account is not None and domain and (not account.domain or account.domain.casefold() != domain.casefold()):
            account = None
        if account is None and domain:
            account = registry.resolve(username, domain)
    name = format_debug_identity(username, preferred_name=account.username if account else None)
    return name, domain.lower()


def print_exposure(rows, groups, threshold=10, width=120, registry=None):
    cyan, red, yellow, reset, bold = '\033[36m', '\033[31m', '\033[33m', '\033[0m', '\033[1m'
    print(f'\n{bold}{cyan}=== Administrative Privilege Exposure (Effective AdminTo) ==={reset}')
    print(f'{len(rows)} accounts with graph-observed administrative reach; broad reach threshold: {threshold}')
    if not rows:
        print('No user administrative reach found in supplied graph exports.')
        return
    print(f'{cyan}{"Account":<25} {"Domain":<20} {"Direct":>6} {"Inherited":>9} {"Effective":>9}  Flags{reset}')
    for row in rows:
        flags = row['Flags']
        tint = red if row['Tier Zero Targets'] else yellow if 'BROAD_ADMIN' in flags else ''
        display_account, display_domain = format_exposure_identity(row, registry)
        print(f'{display_account[:25]:<25} {display_domain[:20]:<20} {row["Direct AdminTo"]:>6} '
              f'{row["Inherited AdminTo"]:>9} {row["Effective AdminTo"]:>9}  {tint}{flags}{reset if tint else ""}')
    print(f'\n{bold}{cyan}Credential-reuse groups with administrative reach: {len(groups)}{reset}')
    if groups:
        headers = ('Accounts', 'Admin Accounts', 'Unique Targets', 'Relationships', 'Cross-Domain')
        data = [(g['Accounts Sharing'], g['Administrative Account Count'], g['Unique Admin Targets'],
                 g['AdminTo Relationships'], g['Cross-Domain Reuse']) for g in groups[:10]]
        widths = [max(len(headers[i]), *(len(str(row[i])) for row in data)) for i in range(len(headers))]
        print('  ' + '  '.join(f'{h:>{widths[i]}}' for i, h in enumerate(headers)))
        print('  ' + '  '.join('-' * w for w in widths))
        for row in data:
            print('  ' + '  '.join(f'{v:>{widths[i]}}' for i, v in enumerate(row)))
