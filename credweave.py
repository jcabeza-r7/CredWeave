#!/usr/bin/env python3


"""
CredWeave
Credential Relationship Analysis for Active Directory

Created by Jaime Cabeza
Developed with assistance from OpenAI's ChatGPT

Correlates credential dumps with BloodHound collector JSON/ZIP data,
enum4linux-ng JSON, explicit privileged-account lists, and hashcat potfiles.

Python 3.10+; standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
from datetime import datetime
import sys
import zipfile
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

VERSION = "1.6.2"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

LM_DISABLED_HASH = "aad3b435b51404eeaad3b435b51404ee"
NT_EMPTY_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
HASH_RE = re.compile(r"^[0-9a-f]{32}$", re.I)

HASH_COL_WIDTH = 40
COUNT_COL_WIDTH = 16
SEPARATOR_WIDTH = 2
MIN_USER_COL_WIDTH = 40
DEFAULT_TERMINAL_WIDTH = 120

# Confirmed membership in these groups is treated as a privilege boundary.
# This is deliberately classification, not a "severity" score.
PRIVILEGED_GROUPS = {
    "domain admins": "Domain Admin",
    "enterprise admins": "Enterprise Admin",
    "schema admins": "Schema Admin",
    "administrators": "Administrator",
    "account operators": "Account Operator",
    "backup operators": "Backup Operator",
    "server operators": "Server Operator",
    "print operators": "Print Operator",
    "dnsadmins": "DNS Admin",
    "group policy creator owners": "GPO Creator Owner",
    "protected users": "Protected User",
}

TIER0_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
}

ADMIN_PREFIXES = ("adm", "admin-", "admin_")
STATUS_RE = re.compile(r"\(\s*status\s*=\s*(enabled|disabled)\s*\)", re.I)


@dataclass
class Observation:
    value: bool
    source: str


@dataclass
class Account:
    username: str
    domain: str | None = None
    rid: str | None = None
    sid: str | None = None
    lm_hash: str | None = None
    nt_hash: str | None = None
    machine: bool = False
    status_observations: list[Observation] = field(default_factory=list)
    groups: set[str] = field(default_factory=set)
    privileges: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    annotations: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return account_key(self.username)

    @property
    def enabled(self) -> bool | None:
        """Resolved account state.

        Explicit dump status is authoritative when present. BloodHound and
        other enrichment sources fill otherwise-unknown state. Conflicting
        observations are retained separately via status_conflict.
        """
        dump_obs = [o.value for o in self.status_observations if o.source.startswith("dump:")]
        if dump_obs:
            vals = set(dump_obs)
            return next(iter(vals)) if len(vals) == 1 else None

        vals = {o.value for o in self.status_observations}
        return next(iter(vals)) if len(vals) == 1 else None

    @property
    def status_conflict(self) -> bool:
        return len({o.value for o in self.status_observations}) > 1

    @property
    def privileged(self) -> bool:
        return bool(self.privileges)

    @property
    def tier0(self) -> bool:
        return "Tier 0" in self.privileges

    def observe_status(self, value: bool, source: str) -> None:
        obs = Observation(value, source)
        if obs not in self.status_observations:
            self.status_observations.append(obs)


class Registry:
    def __init__(self) -> None:
        self.accounts: dict[str, Account] = {}
        self.sid_index: dict[str, str] = {}

    def get(self, username: str, domain: str | None = None) -> Account:
        username = normalize_username(username)
        key = account_key(username)
        if key not in self.accounts:
            self.accounts[key] = Account(
                username=username,
                domain=domain,
                machine=username.endswith("$"),
            )
        elif domain and not self.accounts[key].domain:
            self.accounts[key].domain = domain
        return self.accounts[key]

    def by_sid(self, sid: str) -> Account | None:
        key = self.sid_index.get(sid.casefold())
        return self.accounts.get(key) if key else None

    def bind_sid(self, account: Account, sid: str | None) -> None:
        if sid:
            account.sid = sid
            self.sid_index[sid.casefold()] = account.key


def normalize_username(value: str) -> str:
    value = value.strip().strip('"')
    return value.rsplit("\\", 1)[-1]


def account_key(value: str) -> str:
    return normalize_username(value).casefold()


def clean_bh_name(value: Any) -> str:
    s = str(value or "").strip()
    # BloodHound commonly stores SAM names as USER@DOMAIN.
    return s.split("@", 1)[0] if "@" in s else normalize_username(s)


def base_identity(user: str) -> str:
    name = account_key(user)
    for prefix in ADMIN_PREFIXES:
        if name.startswith(prefix) and len(name) > len(prefix):
            return name[len(prefix):]
    return name


def is_admin_like(user: str) -> bool:
    name = account_key(user)
    return any(name.startswith(p) for p in ADMIN_PREFIXES)


def valid_hash(value: str) -> bool:
    return bool(HASH_RE.fullmatch(value))


def mask_hash(value: str) -> str:
    return value if len(value) != 32 else value[:8] + "*" * 16 + value[-8:]


def shown_hash(value: str, raw: bool) -> str:
    return value if raw else mask_hash(value)


def get_terminal_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return DEFAULT_TERMINAL_WIDTH


def wrap_user_chunks(users: Iterable[str], width: int) -> list[list[str]]:
    width = max(width, 10)
    chunks, current, current_len = [], [], 0
    for user in users:
        added = len(user) + (2 if current else 0)
        if current and current_len + added > width:
            chunks.append(current)
            current, current_len = [user], len(user)
        else:
            current.append(user)
            current_len += added
    if current:
        chunks.append(current)
    return chunks


def status_label(a: Account) -> str:
    if a.status_conflict:
        return "CONFLICT"
    if a.enabled is True:
        return "ENABLED"
    if a.enabled is False:
        return "DISABLED"
    return "UNKNOWN"


def user_label(a: Account, compact: bool = False) -> str:
    """Visible account label used for both rendering and width calculations."""
    suffix = []
    if a.tier0:
        suffix.append("T0" if compact else "Tier 0")
    elif a.privileged:
        suffix.append("P" if compact else "Privileged")
    elif is_admin_like(a.username):
        suffix.append("A" if compact else "Admin-like")

    if a.enabled is False:
        suffix.append("D" if compact else "Disabled")
    elif a.status_conflict:
        suffix.append("!" if compact else "Status Conflict")

    return a.username + (f" [{' / '.join(suffix)}]" if suffix else "")


def display_user(a: Account, compact: bool = False) -> str:
    label = user_label(a, compact=compact)
    if a.tier0 or a.privileged:
        return f"{BOLD}{RED}{label}{RESET}"
    if is_admin_like(a.username):
        return f"{YELLOW}{label}{RESET}"
    if a.enabled is False:
        return f"{DIM}{label}{RESET}"
    return f"{GREEN}{label}{RESET}"


def wrap_accounts(accounts: Iterable[Account], width: int, compact: bool = False) -> list[list[Account]]:
    """Wrap complete account labels using their visible width, ignoring ANSI."""
    width = max(width, 10)
    chunks: list[list[Account]] = []
    current: list[Account] = []
    current_len = 0

    for account in accounts:
        label_len = len(user_label(account, compact=compact))
        added = label_len + (2 if current else 0)

        if current and current_len + added > width:
            chunks.append(current)
            current = [account]
            current_len = label_len
        else:
            current.append(account)
            current_len += added

    if current:
        chunks.append(current)

    return chunks


def parse_dump(path: str, registry: Registry, strict: bool = False) -> tuple[list[Account], list[Account], int]:
    users, machines, skipped = [], [], 0
    source = f"dump:{Path(path).name}"

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) < 4:
                msg = f"{path}:{lineno}: expected user:rid:lmhash:nthash"
                if strict:
                    raise ValueError(msg)
                print(f"{YELLOW}[!] {msg}; skipped{RESET}", file=sys.stderr)
                skipped += 1
                continue

            raw_user, rid, lm, nt = (x.strip() for x in parts[:4])
            lm, nt = lm.lower(), nt.lower()
            if not valid_hash(lm) or not valid_hash(nt):
                msg = f"{path}:{lineno}: invalid LM/NT hash"
                if strict:
                    raise ValueError(msg)
                print(f"{YELLOW}[!] {msg}; skipped{RESET}", file=sys.stderr)
                skipped += 1
                continue

            domain = raw_user.rsplit("\\", 1)[0] if "\\" in raw_user else None
            a = registry.get(raw_user, domain)
            a.rid, a.lm_hash, a.nt_hash = rid, lm, nt
            a.machine = a.username.endswith("$")
            a.sources.add(source)

            tail = ":".join(parts[4:]).strip()
            for match in STATUS_RE.finditer(tail):
                a.observe_status(match.group(1).casefold() == "enabled", source)
            if tail:
                a.annotations.add(tail)

            (machines if a.machine else users).append(a)

    # dedupe if source contained duplicate account rows
    users = list({a.key: a for a in users}.values())
    machines = list({a.key: a for a in machines}.values())
    return users, machines, skipped


def load_admins_file(path: str, registry: Registry) -> None:
    source = f"admins:{Path(path).name}"
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            a = registry.get(name)
            a.privileges.add("Explicit Privileged")
            a.sources.add(source)


def json_objects_from_bloodhound(path: str) -> Iterable[tuple[str, Any]]:
    p = Path(path)
    if p.is_dir():
        for child in p.rglob("*.json"):
            try:
                yield str(child), json.loads(child.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
    elif zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            for name in z.namelist():
                if not name.lower().endswith(".json"):
                    continue
                try:
                    yield f"{p.name}:{name}", json.loads(z.read(name).decode("utf-8", errors="replace"))
                except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
    else:
        yield str(p), json.loads(p.read_text(encoding="utf-8", errors="replace"))


def bh_records(obj: Any) -> list[dict[str, Any]]:
    if isinstance(obj, dict):
        data = obj.get("data")
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        # tolerate raw arrays wrapped under another obvious key
        for key in ("users", "groups"):
            if isinstance(obj.get(key), list):
                return [x for x in obj[key] if isinstance(x, dict)]
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    return []


def bh_type(obj: Any, source_name: str) -> str | None:
    if isinstance(obj, dict):
        meta = obj.get("meta", {})
        if isinstance(meta, dict):
            t = str(meta.get("type", "")).casefold()
            if "user" in t:
                return "users"
            if "group" in t:
                return "groups"
    n = source_name.casefold()
    if "users" in n:
        return "users"
    if "groups" in n:
        return "groups"
    return None



def bloodhound_enabled(props: dict[str, Any]) -> bool | None:
    """Extract enabled/disabled state across common BloodHound export variants."""
    for key in ("enabled", "Enabled"):
        if key not in props:
            continue
        value = props.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "1", "yes", "enabled"}:
                return True
            if normalized in {"false", "0", "no", "disabled"}:
                return False

    # Some exports expose raw AD userAccountControl instead of a normalized
    # enabled property. ACCOUNTDISABLE is bit 0x0002.
    for key in ("useraccountcontrol", "userAccountControl", "UserAccountControl"):
        if key not in props:
            continue
        try:
            uac = int(str(props.get(key)).strip(), 0)
        except (TypeError, ValueError):
            continue
        return not bool(uac & 0x0002)

    return None


def import_bloodhound(path: str, registry: Registry) -> dict[str, Any]:
    counts = {
        "users": 0,
        "groups": 0,
        "memberships": 0,
        "status": 0,
        "status_properties": 0,
        "schema_versions": set(),
    }
    group_members: list[tuple[str, str, str]] = []  # group, member id/name, source

    for source_name, obj in json_objects_from_bloodhound(path):
        typ = bh_type(obj, source_name)
        records = bh_records(obj)
        source = f"bloodhound:{Path(path).name}"

        if isinstance(obj, dict):
            meta = obj.get("meta") or {}
            if isinstance(meta, dict) and meta.get("version") is not None:
                counts["schema_versions"].add(str(meta.get("version")))

        if typ == "users":
            for rec in records:
                props = rec.get("Properties") or rec.get("properties") or {}
                name = clean_bh_name(props.get("samaccountname") or props.get("name") or rec.get("Name"))
                if not name:
                    continue
                domain = props.get("domain")
                a = registry.get(name, str(domain) if domain else None)
                sid = rec.get("ObjectIdentifier") or rec.get("objectid") or props.get("objectid")
                registry.bind_sid(a, str(sid) if sid else None)
                status_keys = {
                    "enabled", "Enabled",
                    "useraccountcontrol", "userAccountControl", "UserAccountControl",
                }
                if any(key in props for key in status_keys):
                    counts["status_properties"] += 1

                enabled = bloodhound_enabled(props)
                if enabled is not None:
                    a.observe_status(enabled, source)
                    counts["status"] += 1
                a.sources.add(source)
                counts["users"] += 1

        elif typ == "groups":
            for rec in records:
                props = rec.get("Properties") or rec.get("properties") or {}
                gname = str(props.get("name") or props.get("samaccountname") or rec.get("Name") or "")
                gshort = clean_bh_name(gname)
                if not gshort:
                    continue
                counts["groups"] += 1
                members = rec.get("Members") or rec.get("members") or []
                if isinstance(members, list):
                    for member in members:
                        if not isinstance(member, dict):
                            continue
                        mid = member.get("ObjectIdentifier") or member.get("objectid") or member.get("ObjectId")
                        mname = member.get("Name") or member.get("name")
                        if mid or mname:
                            group_members.append((gshort, str(mid or mname), source))

    # Resolve after all user JSON has been seen.
    for group, ident, source in group_members:
        a = registry.by_sid(ident)
        if not a:
            # Some exports/variants may provide a name rather than SID.
            candidate = clean_bh_name(ident)
            a = registry.accounts.get(account_key(candidate))
        if not a:
            continue
        a.groups.add(group)
        label = PRIVILEGED_GROUPS.get(group.casefold())
        if label:
            a.privileges.add(label)
        if group.casefold() in TIER0_GROUPS:
            a.privileges.add("Tier 0")
        a.sources.add(source)
        counts["memberships"] += 1

    return counts


def walk_dicts(obj: Any) -> Iterable[dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from walk_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from walk_dicts(value)


def import_enum4linux(path: str, registry: Registry) -> dict[str, int]:
    """
    Tolerant enum4linux-ng JSON importer.

    enum4linux-ng has changed structures across releases/modules, so this
    intentionally discovers user/group records by semantic keys rather than
    depending on one exact nesting layout.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    source = f"enum4linux:{Path(path).name}"
    users_seen, memberships = set(), 0

    # User records: recognize common username/name + RID/SID/account-status shapes.
    for d in walk_dicts(data):
        lowered = {str(k).casefold(): v for k, v in d.items()}
        raw_name = (
            lowered.get("username")
            or lowered.get("user")
            or lowered.get("account_name")
            or lowered.get("account name")
        )
        if not isinstance(raw_name, str) or not raw_name.strip():
            continue
        a = registry.get(raw_name)
        users_seen.add(a.key)
        a.sources.add(source)

        rid = lowered.get("rid")
        if rid is not None and not a.rid:
            a.rid = str(rid)

        sid = lowered.get("sid")
        if isinstance(sid, str) and sid.startswith("S-"):
            registry.bind_sid(a, sid)

        disabled = lowered.get("account disabled")
        if isinstance(disabled, bool):
            a.observe_status(not disabled, source)
        enabled = lowered.get("enabled")
        if isinstance(enabled, bool):
            a.observe_status(enabled, source)

        flags = str(lowered.get("acb") or lowered.get("account flags") or "")
        if "disabled" in flags.casefold() or "acb_disabled" in flags.casefold():
            a.observe_status(False, source)

    # Group membership: recursively identify dictionaries whose key is a group
    # and whose value contains member-ish strings/lists/dicts.
    def collect_strings(v: Any) -> list[str]:
        out = []
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for x in v:
                out.extend(collect_strings(x))
        elif isinstance(v, dict):
            for k, x in v.items():
                if str(k).casefold() in {"member", "members", "username", "user", "name"}:
                    out.extend(collect_strings(x))
        return out

    for d in walk_dicts(data):
        for key, value in d.items():
            gshort = clean_bh_name(key)
            label = PRIVILEGED_GROUPS.get(gshort.casefold())
            if not label:
                continue
            for member in collect_strings(value):
                candidate = clean_bh_name(member)
                a = registry.accounts.get(account_key(candidate))
                if not a:
                    continue
                a.groups.add(gshort)
                a.privileges.add(label)
                if gshort.casefold() in TIER0_GROUPS:
                    a.privileges.add("Tier 0")
                a.sources.add(source)
                memberships += 1

    return {"users": len(users_seen), "memberships": memberships}


HEX_PLAINTEXT_RE = re.compile(r"^\$HEX\[([0-9a-fA-F]*)\]$")


def decode_hashcat_plaintext(value: str) -> str:
    """Decode hashcat's $HEX[...] plaintext representation when valid UTF-8.

    Preserve malformed or non-UTF-8 values verbatim rather than corrupting
    password bytes. A literal password matching $HEX[...] is ambiguous in
    hashcat output and is interpreted as encoded data.
    """
    match = HEX_PLAINTEXT_RE.fullmatch(value)
    if not match:
        return value
    hex_value = match.group(1)
    if len(hex_value) % 2:
        return value
    try:
        return bytes.fromhex(hex_value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value


def load_potfile(path: str) -> dict[str, str]:
    plains = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            h, sep, plain = line.rstrip("\r\n").partition(":")
            h = h.casefold()
            if sep and valid_hash(h):
                if plain == "" and h != NT_EMPTY_HASH:
                    continue
                plains[h] = decode_hashcat_plaintext(plain)
    return plains



def hashcat_mask(password: str) -> str:
    out = []
    for ch in password:
        if ch.islower(): out.append("?l")
        elif ch.isupper(): out.append("?u")
        elif ch.isdigit(): out.append("?d")
        else: out.append("?s")
    return "".join(out)


def charset_name(password: str) -> str:
    classes = []
    if any(c.islower() for c in password): classes.append("lower")
    if any(c.isupper() for c in password): classes.append("upper")
    if any(c.isdigit() for c in password): classes.append("digit")
    if any(not c.isalnum() for c in password): classes.append("special")
    return "+".join(classes) if classes else "other"


def password_family(password: str) -> str:
    if re.fullmatch(r"\d+", password): return "numeric"
    if re.fullmatch(r"[A-Za-z]+", password): return "alpha"
    if re.fullmatch(r"[A-Za-z]+\d+", password): return "word+digits"
    if re.fullmatch(r"[A-Za-z]+\d+[^A-Za-z0-9]+", password): return "word+digits+special"
    if re.fullmatch(r"[A-Za-z]+[^A-Za-z0-9]+\d+", password): return "word+special+digits"
    if re.fullmatch(r"\d+[A-Za-z]+", password): return "digits+word"
    return "mixed"


def username_similarity(password: str, username: str) -> bool:
    u = username.split("\\")[-1].split("@")[0].casefold()
    p = password.casefold()
    if len(u) < 3: return False
    if u in p: return True
    compact_u = re.sub(r"[^a-z0-9]", "", u)
    compact_p = re.sub(r"[^a-z0-9]", "", p)
    return len(compact_u) >= 3 and compact_u in compact_p


def cracked_password_intelligence(result: dict[str, Any], plains: dict[str, str]) -> dict[str, Any]:
    cracked_hashes = {h: plain for h, plain in plains.items()
                      if h in result["hash_map"] and h != NT_EMPTY_HASH}
    cracked_accounts = [a for h in cracked_hashes for a in result["hash_map"].get(h, [])]
    lengths, charsets, families, masks, plaintext_counts = (
        defaultdict(int), defaultdict(int), defaultdict(int), defaultdict(int), defaultdict(int)
    )
    username_derived = []

    for h, plain in cracked_hashes.items():
        accts = result["hash_map"][h]
        weight = len(accts)
        lengths[len(plain)] += weight
        charsets[charset_name(plain)] += weight
        families[password_family(plain)] += weight
        masks[hashcat_mask(plain)] += weight
        plaintext_counts[plain] += weight
        for a in accts:
            if username_similarity(plain, a.username):
                username_derived.append((a, plain))

    cracked_keys = {a.key for a in cracked_accounts}
    def rate(accounts):
        return (sum(a.key in cracked_keys for a in accounts), len(accounts))

    enabled = [a for a in result["users"] if a.enabled is True]
    privileged = [a for a in result["users"] if a.privileged]
    tier0 = [a for a in result["users"] if a.tier0]

    priority = []
    for h, accts in result["hash_map"].items():
        if h in cracked_hashes or h == NT_EMPTY_HASH: continue
        score, reasons = 0, []
        if any(a.tier0 for a in accts):
            score += 100; reasons.append("Tier 0")
        elif any(a.privileged for a in accts):
            score += 70; reasons.append("Privileged")
        elif any(is_admin_like(a.username) for a in accts):
            score += 40; reasons.append("Admin-like")
        enabled_count = sum(a.enabled is True for a in accts)
        if enabled_count:
            score += min(enabled_count * 3, 30); reasons.append(f"{enabled_count} enabled")
        if len(accts) > 1:
            score += min(len(accts) * 2, 30); reasons.append(f"reused x{len(accts)}")
        if score: priority.append((score, h, accts, reasons))
    priority.sort(key=lambda x: (-x[0], -len(x[2]), x[1]))

    return {
        "cracked_hashes": cracked_hashes,
        "lengths": dict(lengths), "charsets": dict(charsets),
        "families": dict(families), "masks": dict(masks),
        "plaintext_counts": dict(plaintext_counts),
        "username_derived": username_derived,
        "rates": {
            "users": rate(result["users"]), "enabled": rate(enabled),
            "privileged": rate(privileged), "tier0": rate(tier0),
            "unique_hashes": (len(cracked_hashes), len(result["hash_map"])),
        },
        "uncracked_priority": priority,
    }


def pct(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "n/a"


def print_password_intelligence(intel: dict[str, Any], show_hashes: bool) -> None:
    print(f"\n{BOLD}{CYAN}=== Cracked Password Intelligence ==={RESET}")

    rate_rows = (
        ("User accounts", "users"),
        ("Enabled accounts", "enabled"),
        ("Privileged accounts", "privileged"),
        ("Tier 0 accounts", "tier0"),
        ("Unique NT hashes", "unique_hashes"),
    )
    for label, key in rate_rows:
        n, total = intel["rates"][key]
        # Labels cyan, recovered count green, denominator neutral, percentage yellow.
        print(
            f"{CYAN}[i]{RESET} {CYAN}{label:<20}{RESET} "
            f"{GREEN}{n:>5}{RESET} / {total:<5} "
            f"({YELLOW}{pct(n,total)}{RESET})"
        )

    def top(counter, n=8):
        return sorted(counter.items(), key=lambda x: (-x[1], str(x[0])))[:n]

    if intel["lengths"]:
        print(f"\n{BOLD}{CYAN}Password Length (account-weighted){RESET}")
        entries = [
            f"{CYAN}{length}{RESET}:{YELLOW}{count}{RESET}"
            for length, count in top(intel["lengths"], 12)
        ]
        print("  " + "  ".join(entries))

    if intel["families"]:
        print(f"\n{BOLD}{CYAN}Common Families{RESET}")
        for name, count in top(intel["families"]):
            print(f"  {GREEN}{name:<24}{RESET} {YELLOW}{count}{RESET}")

    if intel["charsets"]:
        print(f"\n{BOLD}{CYAN}Character Sets{RESET}")
        for name, count in top(intel["charsets"]):
            print(f"  {GREEN}{name:<24}{RESET} {YELLOW}{count}{RESET}")

    if intel["masks"]:
        print(f"\n{BOLD}{CYAN}Top Hashcat Masks{RESET}")
        for mask, count in top(intel["masks"]):
            print(f"  {GREEN}{mask:<40}{RESET} {YELLOW}{count}{RESET}")

    if intel["username_derived"]:
        print(
            f"\n{BOLD}{YELLOW}[!]{RESET} "
            f"{YELLOW}{len(intel['username_derived'])}{RESET} account(s) have "
            f"{BOLD}{YELLOW}username-derived cracked passwords{RESET}"
        )

    if intel["uncracked_priority"]:
        print(f"\n{BOLD}{CYAN}=== Priority Cracking Opportunities ==={RESET}")
        gap = "  "
        print(
            f"{YELLOW}{'Score':>5}{RESET}{gap}"
            f"{CYAN}{'Hash':<40}{RESET}{gap}"
            f"{YELLOW}{'Accounts':>8}{RESET}{gap}"
            f"{CYAN}Why{RESET}"
        )
        print("-" * 100)

        for score, h, accts, reasons in intel["uncracked_priority"][:15]:
            # Make the highest-value signals pop without turning the table into a rainbow.
            if any(reason == "Tier 0" for reason in reasons):
                signal_color = RED
            elif any(reason == "Privileged" for reason in reasons):
                signal_color = YELLOW
            else:
                signal_color = GREEN

            why = ", ".join(reasons)
            print(
                f"{signal_color}{score:>5}{RESET}{gap}"
                f"{CYAN}{shown_hash(h, show_hashes):<40}{RESET}{gap}"
                f"{YELLOW}{len(accts):>8}{RESET}{gap}"
                f"{signal_color}{why}{RESET}"
            )

def hc_append_rule(text: str) -> str:
    return "".join(f"${c}" for c in text)


def hc_prepend_rule(text: str) -> str:
    return "".join(f"^{c}" for c in reversed(text))


def derive_rule_components(password: str) -> tuple[str,str,str,str]:
    m = re.match(r"^([^A-Za-z]*)([A-Za-z][A-Za-z'_-]*)(.*)$", password)
    if not m: return "", "", "", ""
    prefix, core, suffix = m.groups()
    cap = ""
    if core.islower(): cap = "l"
    elif core.isupper(): cap = "u"
    elif core[:1].isupper() and core[1:].islower(): cap = "c"
    return prefix, core, suffix, cap


def _year_neighbors(year: int) -> list[int]:
    """Conservative year extrapolation around an observed modern year."""
    current = datetime.now().year
    if 2000 <= year <= current + 2:
        return sorted({year - 1, year, year + 1})
    return [year]


def generate_adaptive_cracking(
    plains: dict[str, str],
    result: dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    """
    Build a target-adaptive cracking corpus.

    Tier 1 reproduces transformations actually observed in recovered passwords.
    Tier 2 generalizes recurring suffix/capitalization and leetspeak behavior.
    Tier 3 conservatively extrapolates modern observed years by +/- 1 year.

    Candidate words remain canonical lowercase lexical seeds. Observed casing is
    used as transformation intelligence rather than duplicated in the wordlist.
    """
    passwords = sorted({
        plain for h, plain in plains.items()
        if h in result["hash_map"] and h != NT_EMPTY_HASH and plain
    })

    words: set[str] = set()
    masks: set[str] = set()
    exact_rules: set[str] = set()
    generalized_rules: set[str] = set()
    extrapolated_rules: set[str] = set()

    cap_counts: Counter[str] = Counter()
    suffix_counts: Counter[tuple[str, str]] = Counter()
    leet_counts: Counter[tuple[str, str]] = Counter()

    leet_pairs = (
        ("a", "@"), ("a", "4"), ("e", "3"), ("i", "1"),
        ("o", "0"), ("s", "$"), ("s", "5"), ("t", "7"),
    )

    for password in passwords:
        masks.add(hashcat_mask(password))
        prefix, core, suffix, cap = derive_rule_components(password)

        if core:
            base = re.sub(r"[^A-Za-z]", "", core).lower()
            if len(base) >= 3:
                words.add(base)

            if cap:
                cap_counts[cap] += 1

            # Tier 1: faithfully reproduce the observed transformation.
            exact = (
                cap
                + (hc_prepend_rule(prefix) if prefix else "")
                + (hc_append_rule(suffix) if suffix else "")
            )
            if exact:
                exact_rules.add(exact)

            # Learn common suffix structures without treating every literal as
            # an unrelated pattern. Keep the literal material so generated
            # rules remain directly executable by Hashcat.
            if suffix:
                if re.fullmatch(r"(?:19|20)\d{2}[^\w]*", suffix):
                    year = re.match(r"((?:19|20)\d{2})(.*)", suffix)
                    if year:
                        suffix_counts[("year", year.group(2))] += 1
                elif re.fullmatch(r"\d{1,4}[^\w]*", suffix):
                    m = re.match(r"(\d+)(.*)", suffix)
                    if m:
                        suffix_counts[(f"digits:{len(m.group(1))}", m.group(2))] += 1
                elif re.fullmatch(r"[^\w]+", suffix):
                    suffix_counts[("symbol", suffix)] += 1

        observed_leet: list[str] = []
        for src_char, dst_char in leet_pairs:
            if dst_char in password:
                observed_leet.append(f"s{src_char}{dst_char}")
                leet_counts[(src_char, dst_char)] += 1

        if observed_leet:
            leet_rule = "".join(observed_leet)
            exact_rules.add(leet_rule)
            if cap:
                exact_rules.add(cap + leet_rule)

    # Tier 2: recurring behavior. A pattern must occur at least twice before
    # CredWeave promotes it into the generalized layer.
    recurring_caps = [cap for cap, count in cap_counts.items() if count >= 2]
    generalized_rules.update(recurring_caps)

    for (src_char, dst_char), count in leet_counts.items():
        if count >= 2:
            substitution = f"s{src_char}{dst_char}"
            generalized_rules.add(substitution)
            for cap in recurring_caps:
                generalized_rules.add(cap + substitution)

    # Generalize observed year suffixes by combining recurring capitalization
    # with each actually observed year/symbol pair. Tier 3 adds +/- 1 year.
    observed_year_suffixes: Counter[tuple[int, str]] = Counter()
    for password in passwords:
        _, core, suffix, cap = derive_rule_components(password)
        if not core:
            continue
        m = re.fullmatch(r"((?:19|20)\d{2})([^\w]*)", suffix)
        if not m:
            continue
        year, symbols = int(m.group(1)), m.group(2)
        observed_year_suffixes[(year, symbols)] += 1

    for (year, symbols), count in observed_year_suffixes.items():
        literal_suffix = f"{year}{symbols}"
        caps = recurring_caps or [""]
        if count >= 2:
            for cap in caps:
                generalized_rules.add(cap + hc_append_rule(literal_suffix))

        # A single observed modern year is enough to suggest adjacent years,
        # but these stay in the lowest-priority tier.
        for adjacent in _year_neighbors(year):
            if adjacent == year:
                continue
            for cap in caps:
                extrapolated_rules.add(
                    cap + hc_append_rule(f"{adjacent}{symbols}")
                )

    # Baseline transformations remain universally useful.
    baseline = {":", "c", "l", "u"}

    # Preserve tier ordering in the rule file. Deduplicate lower tiers against
    # higher-confidence rules instead of alphabetically mixing everything.
    ordered: list[str] = []
    seen: set[str] = set()
    for tier in (
        sorted(baseline),
        sorted(exact_rules),
        sorted(generalized_rules),
        sorted(extrapolated_rules),
    ):
        for rule in tier:
            if rule and rule not in seen:
                seen.add(rule)
                ordered.append(rule)

    return (
        sorted(words, key=lambda x: (x.casefold(), x)),
        ordered,
        sorted(masks),
    )

def write_adaptive_outputs(result, plains, candidates_path, rules_path, masks_path):
    words,rules,masks = generate_adaptive_cracking(plains,result)
    for path,items,label in ((candidates_path,words,"candidate word"),
                             (rules_path,rules,"Hashcat rule"),
                             (masks_path,masks,"Hashcat mask")):
        if path:
            Path(path).write_text(("\n".join(items)+"\n") if items else "",encoding="utf-8")
            print(f"{CYAN}[i]{RESET} Wrote {len(items)} target-derived {label}(s) to {path}")


def adaptive_token_sets(
    plains: dict[str, str],
    result: dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    """
    Derive conservative combinator-oriented token sets from the cracked corpus.

    left/right preserve observed prefix/core/suffix structure while combined
    contains all useful tokens. These are hypotheses for offline cracking, not
    assertions about password policy.
    """
    left: set[str] = set()
    right: set[str] = set()
    all_tokens: set[str] = set()

    passwords = {
        plain for h, plain in plains.items()
        if h in result["hash_map"] and h != NT_EMPTY_HASH and plain
    }

    for password in passwords:
        prefix, core, suffix, _ = derive_rule_components(password)
        if core:
            cleaned = re.sub(r"[^A-Za-z0-9_-]", "", core)
            base = re.sub(r"[^A-Za-z]", "", core)
            for token in (cleaned, base, core):
                if len(token) >= 3:
                    canonical = token.lower() if any(ch.isalpha() for ch in token) else token
                    all_tokens.add(canonical)
                    left.add(canonical)

        # Pull meaningful alphanumeric chunks out of the full plaintext.
        chunks = re.findall(r"[A-Za-z]{3,}|\d{2,}", password)
        for token in chunks:
            canonical = token.lower() if any(ch.isalpha() for ch in token) else token
            all_tokens.add(canonical)
            if canonical.isdigit():
                right.add(canonical)
            else:
                left.add(canonical)

        # Suffix material is especially useful on the right side of a combinator.
        suffix_chunks = re.findall(r"[A-Za-z]{3,}|\d{2,}", suffix)
        right.update(
            token.lower() if any(ch.isalpha() for ch in token) else token
            for token in suffix_chunks
        )

    # Years observed in cracked material are high-value right-hand candidates.
    for password in passwords:
        right.update(re.findall(r"(?:19|20)\d{2}", password))

    # Avoid pathological tiny sets while keeping generation target-derived.
    right.update(token for token in all_tokens if token.isdigit())
    return (
        sorted(left, key=lambda x: (x.casefold(), x)),
        sorted(right, key=lambda x: (x.casefold(), x)),
        sorted(all_tokens, key=lambda x: (x.casefold(), x)),
    )


def adaptive_attack_plan(
    result: dict[str, Any],
    plains: dict[str, str],
) -> dict[str, Any]:
    words, rules, masks = generate_adaptive_cracking(plains, result)
    left, right, tokens = adaptive_token_sets(plains, result)

    uncracked = [
        h for h in result["hash_map"]
        if h not in plains and h != NT_EMPTY_HASH
    ]

    base_candidates = len(words) * max(len(rules), 1)
    combo_candidates = len(left) * len(right)
    combo_rule_candidates = combo_candidates * max(len(rules), 1)

    return {
        "words": words,
        "rules": rules,
        "masks": masks,
        "left": left,
        "right": right,
        "tokens": tokens,
        "uncracked_hashes": len(uncracked),
        "estimates": {
            "base_rules": base_candidates,
            "combinator": combo_candidates,
            "combinator_rules": combo_rule_candidates,
        },
    }


def print_adaptive_attack_plan(plan: dict[str, Any]) -> None:
    print(f"\n{BOLD}{CYAN}=== Adaptive Attack Plan ==={RESET}")
    print(
        f"{CYAN}[i]{RESET} {GREEN}{len(plan['words'])}{RESET} source word(s), "
        f"{GREEN}{len(plan['rules'])}{RESET} rule(s), "
        f"{GREEN}{len(plan['masks'])}{RESET} observed mask(s)"
    )
    print(
        f"{CYAN}[i]{RESET} Combinator sets: "
        f"{GREEN}{len(plan['left'])}{RESET} left x "
        f"{GREEN}{len(plan['right'])}{RESET} right"
    )
    print(
        f"{CYAN}[i]{RESET} Remaining unique NT hashes: "
        f"{YELLOW}{plan['uncracked_hashes']}{RESET}"
    )

    print(f"\n{BOLD}{CYAN}Estimated Candidate Workload{RESET}")
    for label, key in (
        ("Base words + rules", "base_rules"),
        ("Combinator", "combinator"),
        ("Combinator + rules", "combinator_rules"),
    ):
        print(
            f"  {GREEN}{label:<24}{RESET} "
            f"{YELLOW}{plan['estimates'][key]:,}{RESET}"
        )

    print(f"\n{BOLD}{CYAN}Suggested Passes{RESET}")
    print(f"  {GREEN}1.{RESET} Target-derived wordlist + generated rules")
    print(f"  {GREEN}2.{RESET} Left/right combinator corpus")
    print(f"  {GREEN}3.{RESET} Combinator output + generated rules")
    print(f"  {GREEN}4.{RESET} High-frequency observed masks")


def write_attack_plan_outputs(
    result: dict[str, Any],
    plains: dict[str, str],
    directory: str | Path,
    potfile_path: str,
    hashcat_bin: str = "hashcat",
    combinator_bin: str = "combinator.bin",
) -> list[Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    plan = adaptive_attack_plan(result, plains)
    written: list[Path] = []

    files = {
        "credweave.word": plan["words"],
        "credweave.rule": plan["rules"],
        "credweave.hcmask": plan["masks"],
        "credweave.left": plan["left"],
        "credweave.right": plan["right"],
    }
    for name, values in files.items():
        path = root / name
        path.write_text(("\n".join(values) + "\n") if values else "", encoding="utf-8")
        written.append(path)

    # Generate only the remaining hashes. Full hashes are required by hashcat,
    # irrespective of the console/report masking preference.
    uncracked = sorted(
        h for h in result["hash_map"]
        if h not in plains and h != NT_EMPTY_HASH
    )
    hashes = root / "uncracked.txt"
    hashes.write_text(("\n".join(uncracked) + "\n") if uncracked else "", encoding="utf-8")
    written.append(hashes)

    # A portable helper script. It prints commands by default; --run executes.
    runner = root / "credweave-crack.sh"

    # Preserve the operator's paths as defaults while retaining environment
    # overrides. Resolve the potfile now so changing into the attack directory
    # does not break a relative --potfile path.
    potfile_abs = str(Path(potfile_path).expanduser().resolve())
    hashcat_default = str(Path(hashcat_bin).expanduser()) if "/" in hashcat_bin else hashcat_bin
    combinator_default = str(Path(combinator_bin).expanduser()) if "/" in combinator_bin else combinator_bin

    def shell_single_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    runner_text = """#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HASHCAT="${HASHCAT:-__HASHCAT__}"
COMBINATOR="${COMBINATOR:-__COMBINATOR__}"
POTFILE="${POTFILE:-__POTFILE__}"
MODE="${MODE:-1000}"
RUN=0

if [[ "${1:-}" == "--run" ]]; then
  RUN=1
fi

print_cmd() {
  printf '+ '
  printf '%q ' "$@"
  printf '\\n'
}

run_hashcat() {
  print_cmd "$@"
  if [[ "$RUN" -eq 0 ]]; then
    return 0
  fi

  "$@"
  rc=$?

  # Hashcat 0 = exhausted/success, 1 = cracked/success.
  # Anything else indicates interruption or an actual execution problem.
  if [[ "$rc" -eq 0 || "$rc" -eq 1 ]]; then
    return 0
  fi

  echo "[!] Hashcat exited with unexpected status $rc; stopping." >&2
  exit "$rc"
}

run_combinator_hashcat() {
  local use_rules="$1"
  # In straight mode, Hashcat reads candidate passwords from stdin when no
  # dictionary filename is supplied. A literal "-" is treated as a filename.
  local -a hc=("${HC_BASE[@]}" uncracked.txt)

  if [[ "$use_rules" -eq 1 ]]; then
    hc+=(-r credweave.rule)
  fi

  printf '+ %q %q %q | ' "$COMBINATOR" credweave.left credweave.right
  printf '%q ' "${hc[@]}"
  printf '\\n'

  if [[ "$RUN" -eq 0 ]]; then
    return 0
  fi

  # Capture each side of the pipeline independently. SIGPIPE from combinator
  # is acceptable when Hashcat terminates normally before consuming all input.
  set +o pipefail
  "$COMBINATOR" credweave.left credweave.right | "${hc[@]}"
  local -a statuses=("${PIPESTATUS[@]}")
  set -o pipefail

  local comb_rc="${statuses[0]}"
  local hc_rc="${statuses[1]}"

  if [[ "$hc_rc" -ne 0 && "$hc_rc" -ne 1 ]]; then
    echo "[!] Hashcat exited with unexpected status $hc_rc; stopping." >&2
    exit "$hc_rc"
  fi

  if [[ "$comb_rc" -ne 0 && "$comb_rc" -ne 141 ]]; then
    echo "[!] Combinator exited with unexpected status $comb_rc; stopping." >&2
    exit "$comb_rc"
  fi
}

echo "[*] CredWeave adaptive cracking plan"
echo "[*] Dry-run by default. Pass --run to execute."
echo "[*] Hashcat:    $HASHCAT"
echo "[*] Combinator: $COMBINATOR"
echo "[*] Potfile:    $POTFILE"
echo

HC_BASE=("$HASHCAT" -m "$MODE" --potfile-path "$POTFILE")

echo "=== PASS 1/3: Target-Derived Words + Rules ==="
run_hashcat "${HC_BASE[@]}" uncracked.txt credweave.word -r credweave.rule

if [[ -s credweave.left && -s credweave.right ]]; then
  echo
  echo "=== PASS 2/3: Combinator ==="
  run_combinator_hashcat 0

  echo
  echo "=== PASS 3/3: Combinator + Rules ==="
  run_combinator_hashcat 1
else
  echo
  echo "[!] Skipping combinator passes: credweave.left or credweave.right is empty."
fi

echo
echo "[*] Adaptive passes complete."
echo "[*] Observed masks are in credweave.hcmask."
echo "[*] Review/select masks before launching potentially large mask attacks."
"""    # Defaults are already inside double-quoted parameter expansion in the
    # generated shell script. Escape only characters significant there; do not
    # add shell quote characters, which would become part of the variable value.
    def shell_param_default(value: str) -> str:
        return (
            value.replace("\\", "\\\\")
                 .replace('"', '\\"')
                 .replace("$", "\\$")
                 .replace("`", "\\`")
        )

    runner_text = (
        runner_text
        .replace("__HASHCAT__", shell_param_default(hashcat_default))
        .replace("__COMBINATOR__", shell_param_default(combinator_default))
        .replace("__POTFILE__", shell_param_default(potfile_abs))
    )
    runner.write_text(runner_text, encoding="utf-8")
    runner.chmod(0o755)
    written.append(runner)

    plan_txt = root / "attack-plan.txt"
    plan_txt.write_text(
        "\n".join([
            "CredWeave Adaptive Attack Plan",
            f"Source words: {len(plan['words'])}",
            f"Rules: {len(plan['rules'])}",
            f"Observed masks: {len(plan['masks'])}",
            f"Left combinator candidates: {len(plan['left'])}",
            f"Right combinator candidates: {len(plan['right'])}",
            f"Remaining unique NT hashes: {plan['uncracked_hashes']}",
            "",
            "Estimated candidate workload:",
            f"Base words + rules: {plan['estimates']['base_rules']:,}",
            f"Combinator: {plan['estimates']['combinator']:,}",
            f"Combinator + rules: {plan['estimates']['combinator_rules']:,}",
            "",
            "Suggested order:",
            "1. Target-derived wordlist + generated rules",
            "2. Left/right combinator corpus",
            "3. Combinator output + generated rules",
            "4. Review high-frequency observed masks",
            "",
            "credweave-crack.sh is dry-run by default; pass --run to execute.",
        ]) + "\n",
        encoding="utf-8",
    )
    written.append(plan_txt)
    return written

def human_accounts(registry: Registry) -> list[Account]:
    return [a for a in registry.accounts.values() if a.nt_hash and not a.machine]


def machine_accounts(registry: Registry) -> list[Account]:
    return [a for a in registry.accounts.values() if a.nt_hash and a.machine]


def hash_map(accounts: Iterable[Account]) -> dict[str, list[Account]]:
    out = defaultdict(list)
    for a in accounts:
        if a.nt_hash:
            out[a.nt_hash].append(a)
    for vals in out.values():
        vals.sort(key=lambda a: a.username.casefold())
    return dict(out)


def analyze(registry: Registry) -> dict[str, Any]:
    users = human_accounts(registry)
    machines = machine_accounts(registry)
    hm = hash_map(users)

    # Empty passwords are their own condition, not credential reuse.
    reused = [
        (h, us) for h, us in hm.items()
        if len(us) > 1 and h != NT_EMPTY_HASH
    ]
    boundary = []
    identity = []
    enabled_disabled = []

    for h, us in reused:
        privileged = [a for a in us if a.privileged]
        standard = [a for a in us if not a.privileged]
        if privileged and standard:
            boundary.append((h, privileged, standard))

        by_identity = defaultdict(list)
        for a in us:
            by_identity[base_identity(a.username)].append(a)
        for ident, related in by_identity.items():
            if len(related) > 1 and any(is_admin_like(a.username) for a in related) and any(not is_admin_like(a.username) for a in related):
                identity.append((h, ident, related))

        enabled = [a for a in us if a.enabled is True]
        disabled = [a for a in us if a.enabled is False]
        if enabled and disabled:
            enabled_disabled.append((h, enabled, disabled))

    return {
        "users": users,
        "machines": machines,
        "hash_map": hm,
        "reused": sorted(reused, key=lambda x: (-len(x[1]), x[0])),
        "boundary": boundary,
        "identity": identity,
        "enabled_disabled": enabled_disabled,
        "empty": [a for a in users if a.nt_hash == NT_EMPTY_HASH],
        "lm": [a for a in users if a.lm_hash and a.lm_hash != LM_DISABLED_HASH],
        "conflicts": [a for a in registry.accounts.values() if a.status_conflict],
        "special": [a for a in users if a.rid in {"500", "502"} or a.username.casefold() == "krbtgt"],
    }


def account_json(a: Account) -> dict[str, Any]:
    return {
        "username": a.username,
        "domain": a.domain,
        "rid": a.rid,
        "sid": a.sid,
        "machine": a.machine,
        "enabled": a.enabled,
        "status_conflict": a.status_conflict,
        "status_observations": [{"value": o.value, "source": o.source} for o in a.status_observations],
        "groups": sorted(a.groups),
        "privileges": sorted(a.privileges),
        "sources": sorted(a.sources),
        "annotations": sorted(a.annotations),
    }


def print_accounts(title: str, accounts: list[Account], width: int) -> None:
    if not accounts:
        return
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}")
    for chunk in wrap_accounts(accounts, width - 4, compact=False):
        print("    " + ", ".join(display_user(a) for a in chunk))


def state_counts(accounts: list[Account]) -> tuple[int, int, int]:
    enabled = sum(a.enabled is True for a in accounts)
    disabled = sum(a.enabled is False for a in accounts)
    unknown = len(accounts) - enabled - disabled
    return enabled, disabled, unknown


def render_account_side(
    accounts: list[Account],
    width: int,
    expand: bool,
    compact: bool = True,
    summarize_threshold: int = 10,
) -> list[str]:
    """
    Render an account collection without allowing a large low-signal side of a
    relationship to consume the report. Full data remains in CSV/JSON.
    """
    if not accounts:
        return []

    if expand or len(accounts) <= summarize_threshold:
        chunks = wrap_accounts(accounts, width, compact=compact)
        return [", ".join(display_user(a, compact=compact) for a in chunk) for chunk in chunks]

    enabled = [a for a in accounts if a.enabled is True]
    unknown = [a for a in accounts if a.enabled is None]
    disabled = [a for a in accounts if a.enabled is False]

    # Show the high-signal exceptions, summarize the bulk.
    interesting = enabled + unknown
    lines = []
    if interesting:
        for chunk in wrap_accounts(interesting, width, compact=compact):
            lines.append(", ".join(display_user(a, compact=compact) for a in chunk))

    summaries = []
    if disabled:
        summaries.append(f"{len(disabled)} disabled")
    if not interesting and enabled:
        summaries.append(f"{len(enabled)} enabled")
    if not interesting and unknown:
        summaries.append(f"{len(unknown)} unknown-status")

    # If everything is one large class, just summarize it.
    if not lines:
        e, d, u = state_counts(accounts)
        parts = []
        if e:
            parts.append(f"{e} enabled")
        if d:
            parts.append(f"{d} disabled")
        if u:
            parts.append(f"{u} unknown-status")
        lines.append(f"<{len(accounts)} accounts: {', '.join(parts)}>")
    elif summaries:
        lines.append("+ " + ", ".join(summaries) + " account(s)")

    return lines


def print_relationship_accounts(
    label: str,
    accounts: list[Account],
    width: int,
    expand: bool,
    indent: str = "    ",
) -> None:
    lines = render_account_side(accounts, max(width - len(indent) - len(label) - 2, 30), expand, compact=False)
    if not lines:
        return
    print(f"{indent}{label}: {lines[0]}")
    continuation = " " * (len(indent) + len(label) + 2)
    for line in lines[1:]:
        print(f"{continuation}{line}")


def print_privilege_boundary(result: dict[str, Any], term_width: int, expand: bool) -> None:
    if not result["boundary"]:
        return

    print(f"\n{BOLD}{CYAN}=== Privilege Boundary Credential Reuse ==={RESET}")
    for h, privileged, standard in result["boundary"]:
        print(f"{BOLD}{RED}[!]{RESET} Credential shared across a privilege boundary")
        print_relationship_accounts("Privileged", privileged, term_width, expand)
        print_relationship_accounts("Other", standard, term_width, expand)

        e, d, u = state_counts(standard)
        if e or u:
            detail = []
            if e:
                detail.append(f"{e} enabled")
            if u:
                detail.append(f"{u} unknown-status")
            if d:
                detail.append(f"{d} disabled")
            print(f"    Relationship: same NT credential; {', '.join(detail)} non-privileged account(s)")


def print_identity_reuse(result: dict[str, Any]) -> None:
    if not result["identity"]:
        return
    print(f"\n{BOLD}{CYAN}=== Likely Standard / Privileged Identity Reuse ==={RESET}")
    for h, ident, accounts in result["identity"]:
        print(f"{BOLD}{RED}[!]{RESET} " + " <-> ".join(display_user(a) for a in accounts))


def print_enabled_disabled(result: dict[str, Any], term_width: int, expand: bool) -> None:
    if not result["enabled_disabled"]:
        return

    print(f"\n{BOLD}{CYAN}=== Enabled / Disabled Credential Reuse ==={RESET}")
    for h, enabled, disabled in result["enabled_disabled"]:
        if not expand and len(disabled) > 10:
            enabled_text = ", ".join(display_user(a) for a in enabled)
            print(f"{BOLD}{YELLOW}[!]{RESET} {enabled_text}")
            print(f"    shares credential material with {len(disabled)} disabled account(s)")
        else:
            print(f"{BOLD}{YELLOW}[!]{RESET} Mixed account-state credential reuse")
            print_relationship_accounts("Enabled", enabled, term_width, expand)
            print_relationship_accounts("Disabled", disabled, term_width, expand)


def print_reuse_section(
    title: str,
    rows: list[tuple[str, list[Account]]],
    term_width: int,
    users_width: int,
    show_hashes: bool,
    enabled_only: bool,
    expand: bool,
) -> None:
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}")
    gap = " " * SEPARATOR_WIDTH
    fixed = HASH_COL_WIDTH + COUNT_COL_WIDTH + 2 * SEPARATOR_WIDTH

    print(f"{CYAN}{'Hash':<{HASH_COL_WIDTH}}{gap}{YELLOW}{'Accounts Sharing':<{COUNT_COL_WIDTH}}{gap}{CYAN}Users{RESET}")
    print("-" * max(term_width, fixed + MIN_USER_COL_WIDTH))

    shown_any = False
    for h, accounts in rows:
        visible = [a for a in accounts if not enabled_only or a.enabled is not False]
        if len(visible) < 2:
            continue

        shown_any = True

        # Large mixed groups show enabled/unknown exceptions and summarize the
        # disabled bulk. --expand restores full enumeration.
        if not expand and len(visible) > 10:
            lines = render_account_side(visible, users_width, False, compact=True)
            hc = shown_hash(h, show_hashes)
            cc = str(len(visible))
            for i, line in enumerate(lines):
                print(
                    f"{CYAN}{(hc if i == 0 else ''):<{HASH_COL_WIDTH}}"
                    f"{gap}{YELLOW}{(cc if i == 0 else ''):<{COUNT_COL_WIDTH}}"
                    f"{gap}{RESET}{line}"
                )
            continue

        chunks = wrap_accounts(visible, users_width, compact=True)
        for i, chunk in enumerate(chunks):
            hc = shown_hash(h, show_hashes) if i == 0 else ""
            cc = str(len(visible)) if i == 0 else ""
            names = ", ".join(display_user(a, compact=True) for a in chunk)
            print(f"{CYAN}{hc:<{HASH_COL_WIDTH}}{gap}{YELLOW}{cc:<{COUNT_COL_WIDTH}}{gap}{RESET}{names}")

    if not shown_any:
        print(f"{GREEN}[OK]{RESET} No shared NT hashes in current display scope.")


def print_report(
    result: dict[str, Any],
    term_width: int,
    show_hashes: bool,
    enabled_only: bool,
    expand: bool,
) -> None:
    users = result["users"]
    hm = result["hash_map"]
    reused = result["reused"]
    shared_accounts = sum(len(us) for _, us in reused)
    known_enabled = sum(a.enabled is True for a in users)
    known_disabled = sum(a.enabled is False for a in users)

    actionable_reuse = [
        (h, accounts)
        for h, accounts in reused
        if any(a.enabled is not False for a in accounts)
    ]
    disabled_only_reuse = [
        (h, accounts)
        for h, accounts in reused
        if accounts and all(a.enabled is False for a in accounts)
    ]

    print(
        f"{CYAN}[i]{RESET} {len(users)} user account(s), {len(hm)} unique NT hash(es), "
        f"{len(reused)} reused credential(s) across {shared_accounts} account(s), "
        f"{len(result['empty'])} empty-password account(s) | "
        f"{known_enabled} enabled, {known_disabled} disabled, "
        f"{len(users)-known_enabled-known_disabled} unknown status | "
        f"{len(result['machines'])} machine account(s) retained but excluded from human reuse stats"
    )
    print(
        f"{CYAN}[i]{RESET} Reuse groups: {len(actionable_reuse)} actionable "
        f"(enabled/unknown present), {len(disabled_only_reuse)} disabled-only"
    )
    print(
        f"{DIM}Legend: [T0] Tier 0  [P] Privileged  [A] Admin-like name  "
        f"[D] Disabled  [!] Conflicting status{RESET}"
    )

    fixed = HASH_COL_WIDTH + COUNT_COL_WIDTH + 2 * SEPARATOR_WIDTH
    users_width = max(term_width - fixed, MIN_USER_COL_WIDTH)

    # Highest-signal relationships first.
    print_privilege_boundary(result, term_width, expand)
    print_identity_reuse(result)
    print_enabled_disabled(result, term_width, expand)

    print_reuse_section(
        "Actionable Credential Reuse",
        actionable_reuse,
        term_width,
        users_width,
        show_hashes,
        enabled_only,
        expand,
    )

    print_accounts("Empty Passwords", result["empty"], users_width)

    if result["conflicts"]:
        print(f"\n{BOLD}{CYAN}=== Account Status Conflicts ==={RESET}")
        for a in result["conflicts"]:
            observations = ", ".join(
                f"{'Enabled' if o.value else 'Disabled'} ({o.source})"
                for o in a.status_observations
            )
            print(f"{YELLOW}[!]{RESET} {a.username}: {observations}")

    if result["special"]:
        print(f"\n{BOLD}{CYAN}=== Special Accounts ==={RESET}")
        for a in result["special"]:
            if a.rid == "502" or a.username.casefold() == "krbtgt":
                print(
                    f"{RED}[!]{RESET} {display_user(a)} (krbtgt/RID 502): "
                    f"recovered NT credential material is domain-compromise material"
                )
            if a.rid == "500":
                print(
                    f"{RED}[!]{RESET} {display_user(a)} (RID 500): "
                    f"built-in Administrator credential recovered"
                )

    if disabled_only_reuse and not enabled_only:
        print_reuse_section(
            "Disabled-Only Credential Reuse",
            disabled_only_reuse,
            term_width,
            users_width,
            show_hashes,
            False,
            expand,
        )



def tier0_recovery_rows(result: dict[str, Any], plains: dict[str, str], cracked: bool) -> list[tuple[Account, str | None]]:
    rows = []
    for account in result["users"]:
        if not account.tier0 or not account.nt_hash or account.nt_hash == NT_EMPTY_HASH:
            continue
        recovered = account.nt_hash in plains
        if recovered == cracked:
            rows.append((account, plains.get(account.nt_hash)))
    return sorted(rows, key=lambda item: (item[0].enabled is not True, item[0].username.casefold()))


def print_tier0_recovery(result: dict[str, Any], plains: dict[str, str], cracked: bool, show_plaintext: bool, term_width: int) -> None:
    rows = tier0_recovery_rows(result, plains, cracked)
    title = "Cracked Tier 0 Accounts" if cracked else "Uncracked Tier 0 Accounts"
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}")
    enabled = sum(a.enabled is True for a, _ in rows)
    disabled = sum(a.enabled is False for a, _ in rows)
    unknown = len(rows) - enabled - disabled
    state = "cracked" if cracked else "remain uncracked"
    print(f"{CYAN}[i]{RESET} {BOLD}{len(rows)}{RESET} Tier 0 account(s) {state}: {GREEN}{enabled} enabled{RESET}, {YELLOW}{disabled} disabled{RESET}, {unknown} unknown/conflict")
    if not rows:
        return

    account_w = min(max(len("Account"), max(len(a.username) for a, _ in rows)), 32)
    gap = "  "
    if cracked:
        print(f"{CYAN}{'Account':<{account_w}}{gap}{'Status':<9}{gap}{'Privilege':<10}{gap}Password{RESET}")
    else:
        print(f"{CYAN}{'Account':<{account_w}}{gap}{'Status':<9}{gap}Privilege{RESET}")
    print("-" * min(max(term_width, 60), 160))

    for account, plain in rows:
        status = account_status(account)
        status_color = GREEN if status == "Enabled" else YELLOW if status == "Disabled" else CYAN
        line = f"{RED}{account.username:<{account_w}}{RESET}{gap}{status_color}{status:<9}{RESET}{gap}{RED}{'Tier 0':<10}{RESET}"
        if cracked:
            shown = plain if show_plaintext else "********"
            line += f"{gap}{GREEN}{shown or ''}{RESET}"
        print(line)


def write_uncracked_tier0_hashes(result: dict[str, Any], plains: dict[str, str], path: str | Path) -> int:
    hashes = sorted({
        account.nt_hash for account, _ in tier0_recovery_rows(result, plains, False)
        if account.nt_hash and account.nt_hash != NT_EMPTY_HASH
    })
    Path(path).write_text(("\n".join(hashes) + "\n") if hashes else "", encoding="utf-8")
    return len(hashes)


AFFECTED_RESOURCE_FINDINGS = (
    "implied-trust",
    "privileged-reuse",
    "password-reuse",
    "empty-passwords",
    "lm-hashes",
    "all",
)


def account_status(a: Account) -> str:
    if a.status_conflict:
        return "Conflict"
    if a.enabled is True:
        return "Enabled"
    if a.enabled is False:
        return "Disabled"
    return "Unknown"


def privilege_label(a: Account) -> str:
    if a.tier0:
        return "Tier 0"
    if a.privileged:
        return "Privileged"
    if is_admin_like(a.username):
        return "Admin-like"
    return "Standard"


def affected_resource_rows(result: dict[str, Any], finding: str) -> list[dict[str, str]]:
    """
    Build normalized, report-safe affected-resource rows.

    One relationship is emitted per row so large findings remain sortable and
    paste cleanly into appendix tables. Hashes and plaintext credentials are
    intentionally excluded.
    """
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(
        finding_name: str,
        resource: Account,
        related: Account | None,
        relationship: str,
        detail: str = "",
    ) -> None:
        key = (
            finding_name,
            resource.key,
            related.key if related else "",
            relationship,
        )
        if key in seen:
            return
        seen.add(key)
        rows.append({
            "Finding": finding_name,
            "Affected Resource": resource.username,
            "Related Resource": related.username if related else "",
            "Relationship": relationship,
            "Affected Status": account_status(resource),
            "Related Status": account_status(related) if related else "",
            "Affected Privilege": privilege_label(resource),
            "Related Privilege": privilege_label(related) if related else "",
            "Detail": detail,
        })

    if finding in {"implied-trust", "all"}:
        # Privilege-boundary sharing is the core implied-trust condition.
        for _, privileged, standard in result["boundary"]:
            for p_account in privileged:
                for s_account in standard:
                    add(
                        "Implied Trust Relationship Exploitation",
                        p_account,
                        s_account,
                        "Shared Credential Across Privilege Boundary",
                        "Same NT credential material recovered for both accounts",
                    )

        # Explicit standard/admin identity pairs are particularly reportable.
        for _, _, accounts in result["identity"]:
            privileged = [a for a in accounts if a.privileged or is_admin_like(a.username)]
            standard = [a for a in accounts if a not in privileged]
            for p_account in privileged:
                for s_account in standard:
                    add(
                        "Implied Trust Relationship Exploitation",
                        p_account,
                        s_account,
                        "Likely Standard / Privileged Identity Credential Reuse",
                        "Related account naming and identical NT credential material",
                    )

    if finding in {"privileged-reuse", "all"}:
        for _, privileged, standard in result["boundary"]:
            for p_account in privileged:
                for s_account in standard:
                    add(
                        "Privileged Credential Reuse",
                        p_account,
                        s_account,
                        "Shared Credential Across Privilege Boundary",
                    )

    if finding in {"password-reuse", "all"}:
        for _, accounts in result["reused"]:
            # Emit one row per account within a reuse group instead of an N^2
            # cross-product. The group ID is stable within this export only.
            group_name = f"Credential Reuse Group ({len(accounts)} accounts)"
            for account in accounts:
                add(
                    "Password Reuse",
                    account,
                    None,
                    group_name,
                    "Credential shared with: " + ", ".join(
                        other.username for other in accounts if other.key != account.key
                    ),
                )

    if finding in {"empty-passwords", "all"}:
        for account in result["empty"]:
            add(
                "Empty Password",
                account,
                None,
                "Empty Password",
                "NT hash corresponds to the known empty-password value",
            )

    if finding in {"lm-hashes", "all"}:
        for account in result["lm"]:
            add(
                "LM Hashes Present",
                account,
                None,
                "LM Hash Stored",
                "Legacy LM credential material recovered",
            )

    rows.sort(
        key=lambda r: (
            r["Finding"].casefold(),
            r["Affected Resource"].casefold(),
            r["Related Resource"].casefold(),
            r["Relationship"].casefold(),
        )
    )
    return rows


AFFECTED_RESOURCE_COLUMNS = [
    "Finding",
    "Affected Resource",
    "Related Resource",
    "Relationship",
    "Affected Status",
    "Related Status",
    "Affected Privilege",
    "Related Privilege",
    "Detail",
]


def write_affected_resources(
    path: str | Path,
    rows: list[dict[str, str]],
    fmt: str,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt in {"csv", "tsv"}:
        delimiter = "," if fmt == "csv" else "\t"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=AFFECTED_RESOURCE_COLUMNS,
                delimiter=delimiter,
            )
            writer.writeheader()
            writer.writerows(rows)
        return

    if fmt == "markdown":
        def md(value: str) -> str:
            return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")

        lines = [
            "| " + " | ".join(AFFECTED_RESOURCE_COLUMNS) + " |",
            "| " + " | ".join("---" for _ in AFFECTED_RESOURCE_COLUMNS) + " |",
        ]
        for row in rows:
            lines.append(
                "| " + " | ".join(md(row.get(col, "")) for col in AFFECTED_RESOURCE_COLUMNS) + " |"
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    raise ValueError(f"Unsupported affected-resources format: {fmt}")


def write_report_dir(
    directory: str | Path,
    result: dict[str, Any],
    finding: str,
    plains: dict[str, str],
    show_hashes: bool,
) -> list[Path]:
    """
    Write a compact reporting bundle. Credential plaintexts are not exported.
    """
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    affected = affected_resource_rows(result, finding)
    affected_path = root / "affected-resources.csv"
    write_affected_resources(affected_path, affected, "csv")
    written.append(affected_path)

    reuse_path = root / "credential-reuse.csv"
    with reuse_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Hash", "Accounts Sharing", "Users", "Enabled", "Disabled", "Privileged"])
        for h, accts in result["reused"]:
            w.writerow([
                shown_hash(h, show_hashes),
                len(accts),
                ", ".join(a.username for a in accts),
                ", ".join(a.username for a in accts if a.enabled is True),
                ", ".join(a.username for a in accts if a.enabled is False),
                ", ".join(a.username for a in accts if a.privileged),
            ])
    written.append(reuse_path)

    privileged_path = root / "privileged-reuse.csv"
    privileged_rows = affected_resource_rows(result, "privileged-reuse")
    write_affected_resources(privileged_path, privileged_rows, "csv")
    written.append(privileged_path)

    empty_path = root / "empty-passwords.csv"
    write_affected_resources(empty_path, affected_resource_rows(result, "empty-passwords"), "csv")
    written.append(empty_path)

    lm_path = root / "lm-hashes.csv"
    write_affected_resources(lm_path, affected_resource_rows(result, "lm-hashes"), "csv")
    written.append(lm_path)

    summary_path = root / "summary.txt"
    enabled = sum(a.enabled is True for a in result["users"])
    disabled = sum(a.enabled is False for a in result["users"])
    unknown = len(result["users"]) - enabled - disabled
    summary_path.write_text(
        "\n".join([
            "CredWeave Reporting Summary",
            f"User accounts: {len(result['users'])}",
            f"Machine accounts: {len(result['machines'])}",
            f"Unique NT hashes: {len(result['hash_map'])}",
            f"Reused credentials: {len(result['reused'])}",
            f"Empty-password accounts: {len(result['empty'])}",
            f"LM-hash accounts: {len(result['lm'])}",
            f"Privilege-boundary reuse groups: {len(result['boundary'])}",
            f"Likely standard/privileged identity reuse pairs: {len(result['identity'])}",
            f"Enabled accounts: {enabled}",
            f"Disabled accounts: {disabled}",
            f"Unknown-status accounts: {unknown}",
            f"Potfile-matched hashes: {sum(1 for h in result['hash_map'] if h in plains)}",
        ]) + "\n",
        encoding="utf-8",
    )
    written.append(summary_path)

    analysis_path = root / "analysis.json"
    payload = {
        "tool": {"name": "CredWeave", "version": VERSION},
        "summary": {
            "user_accounts": len(result["users"]),
            "machine_accounts": len(result["machines"]),
            "unique_nt_hashes": len(result["hash_map"]),
            "reused_nt_hashes": len(result["reused"]),
            "empty_password_accounts": len(result["empty"]),
            "lm_hash_accounts": len(result["lm"]),
            "privilege_boundary_reuse_groups": len(result["boundary"]),
            "identity_reuse_relationships": len(result["identity"]),
        },
        "accounts": [
            account_json(a)
            for a in sorted(result["users"] + result["machines"], key=lambda x: x.username.casefold())
        ],
        "credential_reuse": [
            {
                "hash": shown_hash(h, show_hashes),
                "accounts": [a.username for a in accts],
            }
            for h, accts in result["reused"]
        ],
        "affected_resources": affected,
    }
    analysis_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    written.append(analysis_path)

    return written

def compare_dump(old_path: str, current: Registry, strict: bool) -> dict[str, list[str]]:
    old = Registry()
    parse_dump(old_path, old, strict)
    olda = {a.key: a for a in human_accounts(old)}
    newa = {a.key: a for a in human_accounts(current)}
    return {
        "added": sorted(newa[k].username for k in newa.keys() - olda.keys()),
        "removed": sorted(olda[k].username for k in olda.keys() - newa.keys()),
        "changed": sorted(newa[k].username for k in newa.keys() & olda.keys() if newa[k].nt_hash != olda[k].nt_hash),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="credweave",
        description="Credential Relationship Analysis for Active Directory",
    )
    p.add_argument("dump", help="user:rid:lmhash:nthash credential dump")
    enrich = p.add_argument_group("enrichment")
    enrich.add_argument("--bloodhound", action="append", default=[], metavar="PATH", help="BloodHound collector ZIP, directory, or JSON; repeatable")
    enrich.add_argument("--enum4linux", action="append", default=[], metavar="JSON", help="enum4linux-ng JSON; repeatable")
    enrich.add_argument("-a", "--admins-file", action="append", default=[], metavar="FILE", help="explicit privileged accounts; repeatable")

    intel = p.add_argument_group("credential intelligence")
    intel.add_argument("--potfile", metavar="FILE", help="hashcat potfile")
    intel.add_argument("--crack-out", metavar="FILE", help="write unique uncracked NT hashes")
    intel.add_argument("--lm-crack-out", metavar="FILE", help="write unique LM hashes")
    intel.add_argument("-l", "--lm", action="store_true", help="report accounts storing LM hashes")
    intel.add_argument("--generate-candidates", metavar="FILE", help="write target-derived source words from cracked credentials")
    intel.add_argument("--generate-rules", metavar="FILE", help="write target-derived Hashcat rules inferred from cracked credentials")
    intel.add_argument("--generate-masks", metavar="FILE", help="write observed Hashcat masks from cracked credentials")
    intel.add_argument("--no-password-stats", action="store_true", help="suppress cracked-password statistics normally shown with --potfile")
    intel.add_argument("--adaptive-plan", action="store_true", help="show target-derived adaptive cracking plan")
    intel.add_argument("--attack-dir", metavar="DIR", help="write adaptive cracking workspace, including combinator sets and dry-run helper")
    intel.add_argument("--hashcat-bin", metavar="PATH", default="hashcat", help="hashcat executable for generated attack runner (default: hashcat from PATH)")
    intel.add_argument("--combinator-bin", metavar="PATH", default="combinator.bin", help="hashcat-utils combinator executable for generated attack runner (default: combinator.bin from PATH)")
    intel.add_argument("--cracked-t0", action="store_true", help="show Tier 0 accounts whose NT hashes are present in the potfile")
    intel.add_argument("--uncracked-t0", action="store_true", help="show Tier 0 accounts whose NT hashes are not present in the potfile")
    intel.add_argument("--show-plaintext", action="store_true", help="show plaintext passwords in cracked credential output (masked by default)")
    intel.add_argument("--crack-out-t0", metavar="FILE", help="write unique uncracked Tier 0 NT hashes")

    analysis = p.add_argument_group("analysis")
    analysis.add_argument("--diff", metavar="OLDDUMP", help="compare with older credential dump")
    analysis.add_argument("--enabled-only", action="store_true", help="hide disabled accounts from general reuse table only; relationship analysis still considers them")
    analysis.add_argument("--strict", action="store_true", help="abort on malformed dump records")
    analysis.add_argument("--expand", action="store_true", help="fully enumerate large reuse groups instead of summarizing them")

    output = p.add_argument_group("output")
    output.add_argument("-o", "--output", metavar="CSV", help="write reuse CSV")
    output.add_argument("--json", metavar="FILE", help="write full JSON analysis")
    output.add_argument("--affected-resources", metavar="FILE", help="write report-ready affected-resource table")
    output.add_argument(
        "--affected-resources-format",
        choices=("csv", "tsv", "markdown"),
        default="csv",
        help="affected-resource output format (default: csv)",
    )
    output.add_argument(
        "--finding",
        choices=AFFECTED_RESOURCE_FINDINGS,
        default="implied-trust",
        help="finding scope for affected-resource/report output (default: implied-trust)",
    )
    output.add_argument("--report-dir", metavar="DIR", help="write a reporting bundle to DIR")
    output.add_argument("--show-hashes", action="store_true", help="show/export complete hashes")
    output.add_argument("-w", "--width", type=int, metavar="N", help="force console width")
    output.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    registry = Registry()

    try:
        users, machines, skipped = parse_dump(args.dump, registry, args.strict)

        for path in args.admins_file:
            load_admins_file(path, registry)

        for path in args.bloodhound:
            counts = import_bloodhound(path, registry)
            versions = ",".join(sorted(counts["schema_versions"])) or "unknown"
            print(
                f"{CYAN}[i]{RESET} BloodHound {Path(path).name}: "
                f"{counts['users']} user record(s), {counts['groups']} group record(s), "
                f"{counts['memberships']} resolved membership(s), "
                f"{counts['status']} status observation(s) | JSON schema v{versions}"
            )
            if counts["users"] and counts["status_properties"] == 0:
                print(
                    f"{BOLD}{RED}[!] BloodHound user data contains no enabled/disabled "
                    f"account-state properties (enabled/userAccountControl). Accounts without "
                    f"dump-derived status will remain Unknown.{RESET}"
                )
                print(
                    f"{CYAN}[i]{RESET} For secretsdump.py collections, include --user-status "
                    f"to embed account status in the hash dump."
                )
            elif counts["status_properties"] and counts["status"] == 0:
                print(
                    f"{YELLOW}[!]{RESET} BloodHound account-state properties were present but "
                    f"could not be interpreted; affected accounts may remain Unknown."
                )

        for path in args.enum4linux:
            counts = import_enum4linux(path, registry)
            print(f"{CYAN}[i]{RESET} enum4linux-ng {Path(path).name}: {counts['users']} user record(s), {counts['memberships']} privileged membership(s) resolved")

        plains = load_potfile(args.potfile) if args.potfile else {}
        result = analyze(registry)
        password_intel = cracked_password_intelligence(result, plains) if plains else None

        if args.show_plaintext and not args.potfile:
            print(f"{RED}Error: --show-plaintext requires --potfile.{RESET}")
            return 1
        if (args.cracked_t0 or args.uncracked_t0 or args.crack_out_t0) and not args.potfile:
            print(f"{RED}Error: Tier 0 recovery options require --potfile.{RESET}")
            return 1
        if args.crack_out_t0:
            count = write_uncracked_tier0_hashes(result, plains, args.crack_out_t0)
            print(f"{CYAN}[i]{RESET} Wrote {count} unique uncracked Tier 0 NT hash(es) to {args.crack_out_t0}")

        if args.generate_candidates or args.generate_rules or args.generate_masks:
            if not plains:
                print(f"{RED}Error: adaptive cracking output requires --potfile.{RESET}")
                return 1
            write_adaptive_outputs(result, plains, args.generate_candidates, args.generate_rules, args.generate_masks)

        if args.adaptive_plan or args.attack_dir:
            if not plains:
                print(f"{RED}Error: adaptive attack planning requires --potfile.{RESET}")
                return 1
            plan = adaptive_attack_plan(result, plains)
            print_adaptive_attack_plan(plan)
            if args.attack_dir:
                written = write_attack_plan_outputs(
                    result,
                    plains,
                    args.attack_dir,
                    args.potfile,
                    args.hashcat_bin,
                    args.combinator_bin,
                )
                print(
                    f"{CYAN}[i]{RESET} Adaptive cracking workspace written to "
                    f"{args.attack_dir} ({len(written)} file(s))"
                )

        if args.crack_out:
            hashes = sorted(h for h in result["hash_map"] if h != NT_EMPTY_HASH and h not in plains)
            Path(args.crack_out).write_text(("\n".join(hashes) + "\n") if hashes else "", encoding="utf-8")
            print(f"{CYAN}[i]{RESET} Wrote {len(hashes)} NT hash(es) to {args.crack_out}")

        if args.lm_crack_out:
            hashes = sorted({a.lm_hash for a in result["users"] if a.lm_hash and a.lm_hash != LM_DISABLED_HASH})
            Path(args.lm_crack_out).write_text(("\n".join(hashes) + "\n") if hashes else "", encoding="utf-8")
            print(f"{CYAN}[i]{RESET} Wrote {len(hashes)} LM hash(es) to {args.lm_crack_out}")

        if args.output:
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Hash", "Accounts Sharing", "Users", "Enabled", "Disabled", "Privileged"])
                for h, accts in result["reused"]:
                    w.writerow([
                        shown_hash(h, args.show_hashes),
                        len(accts),
                        ", ".join(a.username for a in accts),
                        ", ".join(a.username for a in accts if a.enabled is True),
                        ", ".join(a.username for a in accts if a.enabled is False),
                        ", ".join(a.username for a in accts if a.privileged),
                    ])
            print(f"{CYAN}[i]{RESET} CSV written to {args.output}")

        if args.affected_resources:
            rows = affected_resource_rows(result, args.finding)
            write_affected_resources(
                args.affected_resources,
                rows,
                args.affected_resources_format,
            )
            print(
                f"{CYAN}[i]{RESET} Affected resources written to "
                f"{args.affected_resources} ({len(rows)} row(s), finding={args.finding})"
            )

        if args.report_dir:
            written = write_report_dir(
                args.report_dir,
                result,
                args.finding,
                plains,
                args.show_hashes,
            )
            print(
                f"{CYAN}[i]{RESET} Reporting bundle written to {args.report_dir} "
                f"({len(written)} file(s), finding={args.finding})"
            )

        diff = compare_dump(args.diff, registry, args.strict) if args.diff else None

        if args.json:
            payload = {
                "tool": {"name": "CredWeave", "version": VERSION},
                "summary": {
                    "user_accounts": len(result["users"]),
                    "machine_accounts": len(result["machines"]),
                    "unique_nt_hashes": len(result["hash_map"]),
                    "reused_nt_hashes": len(result["reused"]),
                    "empty_password_accounts": len(result["empty"]),
                    "malformed_dump_lines_skipped": skipped,
                },
                "accounts": [account_json(a) for a in sorted(registry.accounts.values(), key=lambda x: x.username.casefold())],
                "credential_reuse": [
                    {"hash": shown_hash(h, args.show_hashes), "accounts": [a.username for a in accts]}
                    for h, accts in result["reused"]
                ],
                "privilege_boundary_reuse": [
                    {"hash": shown_hash(h, args.show_hashes), "privileged": [a.username for a in p], "standard": [a.username for a in s]}
                    for h, p, s in result["boundary"]
                ],
                "enabled_disabled_reuse": [
                    {"hash": shown_hash(h, args.show_hashes), "enabled": [a.username for a in e], "disabled": [a.username for a in d]}
                    for h, e, d in result["enabled_disabled"]
                ],
                "diff": diff,
            }
            Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"{CYAN}[i]{RESET} JSON written to {args.json}")

        term_width = args.width if args.width and args.width > 0 else get_terminal_width()
        print_report(result, term_width, args.show_hashes, args.enabled_only, args.expand)

        if args.cracked_t0:
            print_tier0_recovery(result, plains, True, args.show_plaintext, term_width)
        if args.uncracked_t0:
            print_tier0_recovery(result, plains, False, False, term_width)

        if args.lm:
            print_accounts("LM Hashes Present", result["lm"], max(term_width - 4, 40))

        if password_intel and not args.no_password_stats:
            print_password_intelligence(password_intel, args.show_hashes)

        if plains:
            cracked = [(h, plains[h], accts) for h, accts in result["hash_map"].items() if h in plains]
            print(f"\n{BOLD}{CYAN}=== Cracked Credentials ==={RESET}")
            print(f"{CYAN}[i]{RESET} {len(cracked)} unique NT hash(es) present in potfile")

            # Keep plaintexts readable in their own column and wrap account
            # labels cleanly beneath the Users column. Large account sets use
            # the same signal-compression rules as credential reuse unless
            # --expand is requested.
            password_width = (
                min(
                    max(
                        len("Password"),
                        max((len(plain) for _, plain, _ in cracked), default=8),
                    ),
                    32,
                )
                if args.show_plaintext
                else len("Password")
            )
            cracked_count_width = max(
                len("Accounts"),
                len(str(max((len(accts) for _, _, accts in cracked), default=0))),
            )
            cracked_gap = " " * SEPARATOR_WIDTH
            cracked_fixed = password_width + cracked_count_width + 2 * SEPARATOR_WIDTH
            cracked_users_width = max(term_width - cracked_fixed, MIN_USER_COL_WIDTH)

            print(
                f"{CYAN}{'Password':<{password_width}}"
                f"{cracked_gap}{YELLOW}{'Accounts':>{cracked_count_width}}"
                f"{cracked_gap}{CYAN}Users{RESET}"
            )
            print("-" * max(term_width, cracked_fixed + MIN_USER_COL_WIDTH))

            for h, plain, accts in sorted(
                cracked,
                key=(
                    (lambda x: (-len(x[2]), x[1].casefold()))
                    if args.show_plaintext
                    else (lambda x: (-len(x[2]), x[0]))
                ),
            ):
                # Do not let an unusually long plaintext destroy alignment.
                # Plaintexts are sensitive reporting material. Keep them masked
                # by default and reveal only when explicitly requested.
                password_display = plain if args.show_plaintext else "********"
                if len(password_display) > password_width:
                    password_display = password_display[: max(password_width - 1, 1)] + "…"

                if not args.expand and len(accts) > 10:
                    lines = render_account_side(
                        accts,
                        cracked_users_width,
                        False,
                        compact=True,
                    )
                else:
                    chunks = wrap_accounts(
                        accts,
                        cracked_users_width,
                        compact=True,
                    )
                    lines = [
                        ", ".join(display_user(a, compact=True) for a in chunk)
                        for chunk in chunks
                    ]

                if not lines:
                    lines = [""]

                for i, line in enumerate(lines):
                    pw = password_display if i == 0 else ""
                    count = str(len(accts)) if i == 0 else ""
                    print(
                        f"{GREEN}{pw:<{password_width}}{RESET}"
                        f"{cracked_gap}{YELLOW}{count:>{cracked_count_width}}{RESET}"
                        f"{cracked_gap}{line}"
                    )

        if diff is not None:
            print(f"\n{BOLD}{CYAN}=== Diff vs Previous Dump ==={RESET}")
            for key, marker in (("added", f"{GREEN}[+]{RESET}"), ("removed", f"{RED}[-]{RESET}"), ("changed", f"{YELLOW}[~]{RESET}")):
                if diff[key]:
                    print(f"{marker} {key.title()}: {', '.join(diff[key])}")
            if not any(diff.values()):
                print(f"{GREEN}[OK]{RESET} No account/password changes detected.")

        return 0

    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"{RED}Error: {exc}{RESET}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
