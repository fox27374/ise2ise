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

### The trusted store is its own slice

Interviewed 2026-08-07 and built as slice 3, ahead of system certificates. The
two stores share a menu in the ISE GUI and nothing else: the trusted store has no
private keys, no password, no node identity and no lockout risk, so it carries
one unverified API shape instead of four. System certificates wait for the lab.

**ERS cannot create a trusted certificate.** `/ers/config/trustedcertificate`
answers GET, PUT and DELETE — there is no POST. The only create path is OpenAPI
`POST /api/v1/certs/trusted-certificate/import`. A target whose OpenAPI is not
answering therefore blocks the whole family, as **one** pre-flight item rather
than one per certificate.

**The detail read carries no certificate.** Both APIs return metadata — subject,
issuer, serial, expiry, trust flags — and the bytes come from a separate
`GET /api/v1/certs/trusted-certificate/{id}/export`. Cisco documents it as a file
download without saying what the file is, and the GUI's answer changes with the
selection (one certificate downloads `.pem`, several download `.zip`).

So the body is **sniffed, not assumed**: `-----BEGIN` is PEM, `0x30` is DER,
`PK\x03\x04` is a ZIP that gets walked with `archive/zip` and each entry sniffed
again. Everything normalises to PEM in the bundle. `encoding/pem`, `crypto/x509`
and `archive/zip` are all stdlib, so covering all three cost about twenty lines
and removed the possibility of being wrong about which one ISE picked. Bytes that
match none of the three are reported with their leading hex and Content-Type, and
that certificate is skipped.

**A chain is split into its members.** An export file holding several
certificates yields several trusted certificates, because a missing issuer on the
target is a silent validation failure later. Only the certificate matching the
listing metadata keeps its source friendly name; the rest are named from their
subject CN, suffixed with the first 8 hex of their fingerprint when the CN is
empty or the name already exists. ISE requires the name unique. Fingerprint
dedupe absorbs the duplicates this produces when the issuer also has its own
entry in the source store.

**Two exclusions, computed and never offered:** an `internalCA` certificate (the
internal CA is out of scope, and its root on the target would be trust the target
should not have) and a self-signed certificate whose CN is one of the source node
hostnames (a per-node default server certificate, meaningless on the target).
Everything else appears in a picker, ticked by default. Cisco's factory roots
ride along and land as "already exists" — free, and cheaper than maintaining a
list of what a given release ships.

**Dedupe is by SHA-256 fingerprint, not by name.** The same root sits in two
stores under two friendly names often enough to matter, and this is the first
family whose identity is really its content. The source-side fingerprint is
computed locally over the DER rather than read from ISE, so only the target side
depends on ISE exposing one. When the target exposes no usable fingerprint the
family falls back to name matching and says so once, rather than stopping: a
metadata field name is a poor reason to halt a migration, and ISE's own rejection
of a duplicate certificate still catches the content case at write time.

**Trust flags travel verbatim, all four**, `trustForCertificateBasedAdminAuth`
included. This deliberately differs from the system certificate rule above: that
one changes how the box authenticates administrators *to itself*, while a trusted
CA flag only widens what the box will accept. Discarding a decision the source
operator made is the failure mode the tool exists to prevent.

**Expired certificates are blocked in pre-flight**, with the expiry date in the
reason, never attempted. `crypto/x509` answers this locally, so it costs nothing,
and expired trust on a fresh deployment is dead weight.

**CRL settings need a second write.** The OpenAPI import payload accepts only the
name, description, data and the trust/allow flags; CRL download, distribution
URL, update period and failure behaviour are set by a PUT afterwards. The PUT is
made, and **a failed PUT still counts the certificate as created** — deleting a
good certificate because a secondary setting would not stick is worse than a
certificate with default revocation settings, and the tool issues no DELETE
against a target under any circumstances. The failure and the settings to enter
by hand go into the report.

The OCSP service reference is dropped with a note naming the service. OCSP
service objects are out of scope, so the name resolves to nothing on the target.

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
alarms, repositories · **OCSP service configurations** (a trusted certificate's
reference to one is dropped with a note) · licensing, node roles, deployment
build · PAC
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
came from Cisco's documentation. The lab (`ntslab.loc`) was offline when slices 1,
2 and 3 were built.

Slice 1 (CSV translation) *is* verified — against a real 37-device export from a
production deployment, translated into a synthetic newer-release template.

Slice 2 (API core) is verified only against a hand-written `httptest` fake ISE
that returns what the documentation says ISE returns. That proves the paging,
the stub→detail fetch, both OpenAPI list shapes, the error propagation, the
bundle crypto and the remaps — and proves nothing about whether ISE actually
speaks that way.

Slice 3 (trusted certificates) sits in the same position, with one difference:
the sniffing means the export body only has to be *one of* PEM, DER or ZIP for
the slice to work, rather than the single shape the code guessed. Its test
certificates are generated in-process with `crypto/x509`, so no certificate file
ever lands in the repository.

Known-uncertain shapes, in rough order of risk:

1. `/api/v1/endpoint` — list shape, paging parameters, and which fields carry
   `staticGroupAssignment` / `staticProfileAssignment` / `groupId` / `profileId`.
2. `/ers/config/profilerprofile` — used for the profile-name remap.
3. `/ers/config/node` — node list shape for the probe.
4. `GET /api/v1/certs/trusted-certificate/{id}/export` — whether the body is PEM,
   DER or ZIP. Sniffed rather than assumed, so all three work; what is unproven
   is that it is one of the three at all.
5. The target's trusted-certificate fingerprint field (`sha256Fingerprint`) and
   its formatting. Absent means a silent fall back to name matching.
6. Whether the trusted-certificate read-side field names match the import-side
   ones (`trustForIseAuth` and friends), and whether the CRL PUT accepts the
   field set the source object hands over.
7. System certificate export body and the 3.3 export endpoint (not yet built).
8. Egress matrix cell shape (not yet built).
9. Condition library payloads (not yet built).

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

Trusted certificates, same session:

11. Export one trusted certificate and **say which shape came back** — PEM, DER
    or ZIP, and whether the ZIP held a chain. This is the single most useful
    thing the lab can answer for this slice.
12. Confirm the picker excludes the internal CA certificates and each node's
    self-signed default server certificate, and nothing else.
13. Compare the picker's list against Administration → System → Certificates →
    Trusted Certificates in the GUI.
14. Confirm the target's certificate list exposes a fingerprint; if pre-flight
    reports the name-matching fallback, send the note back verbatim.
15. Import into the throwaway standalone; confirm the four trust flags arrive as
    the source had them, and that an expired certificate was blocked and never
    attempted.
16. Confirm the CRL settings PUT is accepted, and what ISE says if it is not.
17. Re-run the same import; confirm every certificate is skipped, none
    duplicated, and that a certificate renamed on the target is still recognised
    by fingerprint.
18. With OpenAPI disabled on the target, confirm pre-flight blocks the family
    once with a legible reason rather than per certificate.

Send back whatever it gets wrong — the error text is designed to be quotable.

---

## Roadmap

Ordered by dependency, not by size.

1. ~~Network device CSV translation~~ — done, verified against real data.
2. ~~API core: client, probe, encrypted bundle, endpoint groups + static
   endpoints~~ — done, fake-ISE verified only.
3. ~~Trusted certificates~~ — built 2026-08-07, fake-ISE verified only. Taken out
   of order because it is self-contained and needed no lab answers that policy
   work also needs.
4. **Lab verification of slices 2 and 3.** Blocking; see the checklist above.
5. **System certificates** — operator-selected, the 3.3 export-with-private-key
   API and the 3.2 GUI-ZIP fallback, admin role off. Held back deliberately: four
   unverified shapes and a private key, none of it testable without the lab.
6. **Policy elements** — network device groups, condition library, dACLs,
   authorization profiles, identity source sequences. Introduces the factory
   allowlist update mechanism.
7. **TrustSec** — SGTs, then SGACLs, then the egress matrix (needs both).
8. **Policy sets and rules** — the two-pass UUID remap. Most dependent on lab
   iteration; deliberately last.
9. **AD join point** config export, creation, and `addGroups`.
10. **Network device CSV → API import.**
