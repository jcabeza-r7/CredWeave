# Unified BloodHound Graph Update

Accepts BloodHound UI graph exports containing User/Group -> Computer `AdminTo`, User -> Group `MemberOf`, and Group -> Group `MemberOf` edges. A single consolidated graph JSON or multiple separate exports are supported via repeated `--bloodhound` flags. Collector ZIPs are still supported for credential account enrichment.

The parser normalizes graph-local node identifiers using BloodHound object IDs (typically SIDs) or domain-qualified names; graph-local numeric node IDs are not joined across exports. Recursive group traversal uses cycle protection, shortest membership paths, and deduplicated target sets. These counts represent graph-observed relationships, not validated logon ability.

New CLI options:

    --privilege-debug USER@DOMAIN
    --privilege-debug-limit 30

Graph ingestion reports raw counts of direct user AdminTo, group AdminTo, user MemberOf, and group MemberOf relationships. The debug option prints direct and inherited granting paths for up to N computers. User-only and group-only export compatibility is preserved.

Baseline validation (before nested collector membership changes): 30 automated tests; graph-only smoke test using the four user-provided exports found 183 user AdminTo, 498 group AdminTo, 4838 user memberships, and 324 group memberships. 100 graph users have effective reach, including 55 with inherited reach but no direct AdminTo. These graph-only figures are not a complete account-registry validation.

Caveats: Multiple distinct shortest paths to the same granting group are collapsed to one deterministic path. Exports with missing nodes or edges cannot be inferred; no completeness guarantees. CSV columns are unchanged. Do not distribute actual client exports or credential material in source archives.

## Nested collector membership fix (1.6.3)

BloodHound CE-compatible collector ZIPs describe each Group's Members by
`ObjectIdentifier`, including other Group objects. CredWeave now retains those
edges across imported ZIPs and calculates transitive account memberships via
shortest-path BFS with cycle protection. `T0_ACCOUNT` is set when a supported
Tier 0 group is reachable, even through nested groups. Evidence is available in
`--privilege-debug ACCOUNT@DOMAIN` as a membership path and source ZIP name.
This is a name-based local classifier using `TIER0_GROUPS`; it **does not** claim
exact parity with the configured BloodHound CE Tier Zero zone rules.

The graph merger now retains positive Tier Zero information from repeated
node records. Collector-derived inherited groups are domain-qualified when
matched against exported graph nodes. Collector ZIPs alone still do not
establish explicit `AdminTo` edges.

The original user data and collection archives are never bundled in the
release archive; regression fixtures are synthetic.
