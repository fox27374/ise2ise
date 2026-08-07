# Decisions

Why ise2ise is shaped the way it is. Recorded 2026-08-06/07 from the
requirements interview, so that work can resume without re-deriving any of it.

`README.md` describes what the tool does. This file describes what was decided,
what was rejected, and what is still unproven.

---

## The constraints that shaped everything

**Target is always a freshly installed standalone**, built manually by the
operator, containing only ISE's factory defaults.

This one fact removed a large amount of design:

- No update or overwrite path. Import is create-only; duplicates are skipped and
  counted. The tool can never damage a running deployment.
- No node mapping table. The target has exactly one node, so every source node
  hostname collapses onto it. The source may still be standalone or distributed.
- Deployment build, licensing and node roles are out of scope entirely.

**Both ends are ISE 3.x.** Both APIs exist on every supported version, so there
are no dead fallback branches for 2.x. Version independence is achieved by
*probing capability and skipping what is absent*, never by parsing a version
number and branching on it.

---

## Language and distribution

**Go, one static binary per OS.** Weighed against a single-file Python script:
Python is one identical file everywhere but needs a runtime that macOS 12.3+ no
longer ships and Windows never had, and enterprise-locked laptops often block
installing one. Go moves that cost to build time and ships something that just
runs. The trade is that "one file" becomes one file per OS.

Rejected: a pure HTML/JS page with no server. The browser cannot reach ISE —
CORS, the self-signed certificate, and Basic auth to port 9060 all block it.

**Prebuilt binaries are committed** to `dist/` so a recipient needs no toolchain.

**Stdlib only.** `go.mod` has no requirements and should stay that way.
AES-GCM, PBKDF2, CSV, HTTP and `embed` are all in the standard library as of
Go 1.24. If something seems to need a dependency, check the stdlib again first.

---

## Security decisions

**Binds `127.0.0.1` only, with no flag to change it.** The UI is
unauthenticated and holds ISE admin credentials in memory; exposing it on a
routable interface would be handing those out. `-port` moves the port, never the
interface.

**TLS verification off by default**, `-verify-tls` to enable, and the UI says so
while it is off. ISE ships a self-signed certificate, so verification-on by
default means refusing to talk to a stock deployment until the operator feeds it
a CA. Wrong default for day one; correct as an option.

**Credentials are never persisted.** Retyped every session. This is a tool run a
handful of times per migration; persisted ISE admin credentials on a laptop is a
worse problem than retyping a password.

**The bundle is always encrypted.** It carries certificate private keys and, once
device secrets are merged, RADIUS/SNMP/enable passwords. An unencrypted file of
that content is the kind of thing that lives on a share drive forever.
AES-256-GCM, PBKDF2-HMAC-SHA256 at 600 000 iterations. No plaintext mode.

---

## Network devices go by CSV, not by API

The most consequential finding of the interview.

ISE **masks shared secrets on API reads** — `radiusSharedSecret` comes back as
`"******"` (enhancement CSCwn09816, 3.1+). There is no API, CLI or GUI way to
read an existing secret back in plaintext. Cisco's position is that they are
write-once credentials that belong in a vault.

Cisco's documentation states the masking covers the CSV export too. **It does
not.** The operator tested 3.2 through 3.5 and the export CSV contains every
secret in plaintext; this was confirmed against a real 37-device export, which
had zero masked values across the RADIUS shared secret, SNMP RO community, SNMP
auth and privacy passwords, SGA device password, and EXEC/enable passwords.

So the CSV is the only route that carries a device's credentials. Which makes
the interesting problem not migration but **translation**: the column set differs
between releases, so an older export is rejected by a newer deployment.

The design consequence is that **the target's own template CSV is the schema**.
Nothing is hardcoded to a release; a future ISE 3.6 works without a code change.
Columns are matched by label, with the release's type annotation stripped.

Rejected: parsing the CSV and POSTing devices through the API. It would require
hand-mapping ~55 columns to ERS JSON and re-guessing the mapping every release,
to save one manual click. Kept on the roadmap because the operator wants the
whole migration behind one button eventually, but the CSV→CSV path stays as the
route that cannot silently drop a column.

Guards that exist because of how this fails:

- A source column with no home in the target is **reported as data loss**. Silent
  dropping is the failure mode the tool exists to prevent.
- A masked secret (`******`) **refuses the row** rather than importing the
  literal string. A device that exists but rejects every RADIUS request is harder
  to debug than a device that is not there.
- PAC issue/expiry/issuer columns are runtime state and are never written.

---

## Endpoints: static assignments only

A new deployment re-profiles endpoints by itself as soon as traffic flows.
Copying every endpoint moves data the target regenerates anyway, at the cost of
one HTTPS round trip per MAC through ERS.

What does *not* regenerate is what a human decided: static group assignment (the
MAB allowlist, printers, badge readers) and static profile assignment. Those are
the payload. The operator additionally **selects which endpoint identity
groups** to export from, which bounds the volume further.

---

## Certificates

Three stores, and they behave nothing alike:

| Store | Decision |
|---|---|
| **Trusted certificates** (CA/root/intermediate) | Migrate fully. Portable by design. |
| **System certificates** (node identity, has private key) | Operator selects which to carry. Only a wildcard or multi-SAN certificate makes sense — a per-node identity certificate's CN is a source FQDN that will never exist again. |
| **ISE internal CA** | Out of scope. Cannot be moved; Cisco's own procedure regenerates it on a new deployment, and endpoint certificates signed by the old root stop validating. Architectural, not an API gap. |

**The admin role defaults to off** when importing a system certificate. Taking
over the admin certificate on a box that is still being built is a good way to
lock yourself out of the GUI mid-migration.

**Export path depends on version.** API export of a certificate *with its private
key* is 3.3+. For a 3.2 source the operator exports the ZIP from the GUI and
drops it in; the import path (3.1+) is identical either way. One "certificate
password" field covers the API export, the GUI ZIPs and the import.

---

## Policy

Scope is **policy elements + policy sets + rules** — the condition library,
dACLs, authorization profiles, SGTs, SGACLs, the egress matrix, identity source
sequences, and the policy sets themselves with their authentication and
authorization rules.

### The reason this is hard

Rules point at other objects three different ways, and only one survives a move:

| Reference | Stored as | Survives? |
|---|---|---|
| Authorization profile, dACL | name | yes, if imported first |
| Allowed protocols / service | name | yes, if it exists on the target |
| Library condition | `ConditionReference` + **UUID** | **no** |
| Identity source sequence / store | `identitySourceId` **UUID** | **no** |
| Security Group (SGT) | name + UUID | partly |

So the import is two-pass: create the referenced objects, capture the **new**
UUIDs ISE hands back, then rewrite every reference by matching on **name** before
posting the rules. The endpoint `groupId`/`profileId` remap already implemented
is the same pattern at small scale — reuse it.

A condition whose `conditionType` is `ConditionReference` keeps its `id` during
export cleaning; every other object's deployment-local `id` is stripped.

### The pre-flight gate

Import resolves the entire reference graph against the target and **writes
nothing** until the operator confirms. Objects that fail pre-flight are skipped,
never attempted. Rationale: a half-imported policy set is worse than none, and a
rule whose condition resolves to nothing is worse still — it looks imported and
matches no traffic.

The pre-flight is re-run server-side at confirm time rather than trusting the
browser's copy.

### Factory defaults get updated, not skipped

A fresh ISE ships objects the source also has by name: `PermitAccess`,
`DenyAccess`, `Profiled`, `Unknown`, `RegisteredDevices`, `All Locations`,
`All Device Types`, and the **`Default` policy set**.

Create-only would skip all of them. That is fine when they are untouched and
wrong when they are not — and `Default` is the one people customise most, since
it holds the catch-all authentication rule and the fallback authorization rules.
Skipped silently, the import reports success while the target keeps its factory
version, and it is wrong in exactly the place that decides what happens to
traffic no other rule matched.

So: a hardcoded allowlist of factory object names is **updated** rather than
skipped. Safe specifically because the target is a fresh install, where those
objects are by definition factory-fresh.

This is **not yet implemented** — the endpoint slice had no factory objects worth
updating, so building the mechanism early would have been speculative. It lands
with the policy slice, which is where it matters.

---

## Active Directory

AD is used in most authentication rules, and **both deployments join the same
domain** — so group SIDs are identical and references resolve once the groups are
loaded into the target's join point.

Split by what is safely automatable:

| Step | Who |
|---|---|
| Read source join point config | tool |
| Create the join point on the target | tool |
| **Join the domain** | **operator, in the GUI** |
| Load referenced groups (`PUT /ers/config/activedirectory/{id}/addGroups`) | tool |
| Rewrite rule references | tool |

The domain join is deliberately manual. Passing domain administrator credentials
through a migration tool to save a 60-second GUI action is a bad trade.

If a future migration crosses to a *different* domain, every AD group condition
is dead on arrival — different SIDs — and the tool can only report them.

---

## Explicitly out of scope

Confirmed manual: ISE internal CA · posture (conditions, requirements, policies)
· profiler policies and custom profiles · guest/sponsor/BYOD portals and their
customisation · admin users, RBAC and admin groups · logging targets, syslog,
alarms, repositories · licensing, node roles, deployment build · PAC
provisioning state (re-provisioned on first authentication) · **TACACS device
admin policy** (a parallel policy tree under `/api/v1/policy/device-admin/*`;
network access only for now).

---

## Deferred decisions

Small things settled provisionally, worth revisiting:

- **Endpoint identity group nesting is not carried.** `parentId` is stripped and
  a bundle note is emitted. Carrying it needs a third name↔UUID remap. Groups
  currently land flat at top level; custom groups often hang under `Profiled`.
- **Empty report sections serialise as `null`, not `[]`**, because the `Report`
  slices are nil. The UI guards for it. Cosmetic.
- **Network device CSV → API import** — on the roadmap, deliberately behind the
  CSV→CSV path.
- **Bulk endpoint creation** (`/api/v1/endpoint/bulk`) — not needed at the
  volumes the static-only filter produces. Revisit if an export ever exceeds a
  few thousand.

---

## Unverified against real hardware

**No ISE has ever answered this code.** Every field name, path and payload shape
came from Cisco's documentation. The lab (`ntslab.loc`) was offline when slices 1
and 2 were built.

Slice 1 (CSV translation) *is* verified — against a real 37-device export from a
production deployment, translated into a synthetic newer-release template.

Slice 2 (API core) is verified only against a hand-written `httptest` fake ISE
that returns what the documentation says ISE returns. That proves the paging,
the stub→detail fetch, both OpenAPI list shapes, the error propagation, the
bundle crypto and the remaps — and proves nothing about whether ISE actually
speaks that way.

Known-uncertain shapes, in rough order of risk:

1. `/api/v1/endpoint` — list shape, paging parameters, and which fields carry
   `staticGroupAssignment` / `staticProfileAssignment` / `groupId` / `profileId`.
2. `/ers/config/profilerprofile` — used for the profile-name remap.
3. `/ers/config/node` — node list shape for the probe.
4. System certificate export body and the 3.3 export endpoint (not yet built).
5. Egress matrix cell shape (not yet built).
6. Condition library payloads (not yet built).

The code reports what it actually received when a shape does not match, rather
than panicking or returning empty. Read those messages literally.

### Lab checklist, when the lab is back

Do this **before** building more slices — the policy, TrustSec and certificate
work all sits on top of this client, and an hour here is worth more than another
slice on unverified shapes.

1. Enable ERS and OpenAPI on the lab; confirm the probe reports version, nodes,
   and both APIs on.
2. Probe with a deliberately wrong password — confirm it says bad credentials,
   not "API off".
3. Probe with OpenAPI disabled — confirm it distinguishes that from a bad
   password.
4. Export endpoint identity groups; compare the count against the GUI.
5. Export static endpoints from one group; confirm the static-only filter keeps
   what the GUI shows as statically assigned and drops the profiled ones.
6. Confirm an endpoint with a static *profile* assignment round-trips its profile
   name.
7. Import into a throwaway standalone; confirm the pre-flight blocks an endpoint
   whose profiler profile is missing, and that nothing is written before confirm.
8. Confirm a created endpoint points at the **target's** group UUID.
9. Re-run the same import; confirm everything is skipped as already existing and
   nothing is duplicated.
10. Try a bundle with the wrong passphrase; confirm the error is legible.

Send back whatever it gets wrong — the error text is designed to be quotable.

---

## Roadmap

Ordered by dependency, not by size.

1. ~~Network device CSV translation~~ — done, verified against real data.
2. ~~API core: client, probe, encrypted bundle, endpoint groups + static
   endpoints~~ — done, fake-ISE verified only.
3. **Lab verification of slice 2.** Blocking; see the checklist above.
4. **Certificates** — trusted store, then system certificates with the
   3.2 GUI-ZIP fallback. Self-contained, independent of policy, good next slice
   while policy questions settle.
5. **Policy elements** — network device groups, condition library, dACLs,
   authorization profiles, identity source sequences. Introduces the factory
   allowlist update mechanism.
6. **TrustSec** — SGTs, then SGACLs, then the egress matrix (needs both).
7. **Policy sets and rules** — the two-pass UUID remap. Most dependent on lab
   iteration; deliberately last.
8. **AD join point** config export, creation, and `addGroups`.
9. **Network device CSV → API import.**
