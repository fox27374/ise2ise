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

**Prebuilt binaries ship as release assets**, so a recipient still needs no
toolchain. They were originally committed to `dist/`, which was the right call
while the repository was private and hand-carried and the wrong one the moment it
had a remote: four ~10 MB blobs per rebuild, replaced on every slice, is a
history that grows faster than the source it documents. A tag now triggers a
workflow that re-runs the checks, cross-compiles and attaches the binaries plus
`SHA256SUMS`. The blobs already in the history stay there — rewriting it is a
bigger cost than the space it reclaims.

**Release binaries are reproducible**, from v0.5.0. Until then `SHA256SUMS`
proved only that a download matched what CI happened to produce; nobody could
rebuild a tag and check the bytes. That is enough while the binaries are
hand-carried by the person who built them, and not enough the moment someone
else runs one against their own ISE deployment on the strength of that file.

Three inputs decided the bytes and all three were varying:

- The absolute source path was baked in — seven occurrences of the builder's
  home directory in the binary. `-trimpath`.
- A native macOS build links the host SDK (`CGO_ENABLED=1`) while the runner
  cross-compiles macOS from Linux with cgo off, so the same commit produced
  different binaries depending on where `make` ran. `CGO_ENABLED=0` everywhere,
  which costs nothing here and is implied by stdlib-only anyway.
- `go-version` was pinned to the minor, leaving the patch to whatever was
  newest that day. Pinned to the patch in the workflow.

Confirmed rather than assumed: v0.5.0 built on macOS matches all four binaries
the Ubuntu runner cross-compiled, byte for byte, and the README's verification
recipe was run from a fresh clone of the public repository.

What this buys is narrow and worth being precise about. It removes the build
pipeline from the set of things a recipient has to trust — the binary can be
shown to come from this source. It says nothing about whether the source
deserves trust, and it does not defend against a compromised toolchain. The
standing cost is that a Go patch bump is now a deliberate commit rather than
something that happens by itself, which is the right trade for a tool that holds
ISE admin credentials.

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

### Verified against ISE 3.4.0.608 on 2026-08-07

The lab came back and answered all of this. What the documentation said and what
ISE does differ enough that the first implementation read **zero** of the 33
certificates on the box and reported success.

| Assumption | Reality on 3.4 |
|---|---|
| ERS `/ers/config/trustedcertificate` | **404.** The resource does not exist. OpenAPI is the only route. |
| Objects have `name` | The field is **`friendlyName`**. |
| List returns stubs, detail per object | The list returns **whole objects**; no second call needed. |
| Export at `/{id}/export` | **`/export/{id}`**, id last. |
| Export body shape unknown | **Bare PEM**, `application/octet-stream`, one certificate, filename from the friendly name. |
| Four `trustFor*` booleans on read | A single comma-separated string, `trustedFor`: `Infrastructure` = ISE auth, `Endpoints` = client auth, `Cisco Services`, `AdminAuth`. Writes still take the four booleans. |
| `data` is base64 | **Plain-text PEM.** |
| Booleans and numbers | Reads give `"on"`/`"off"` and stringified integers; writes want real booleans and integers. |
| Dates | Java `Date.toString()`: `Thu Jul 17 01:59:59 CEST 2036`. |
| A `selfSigned` field exists | It does not. Use `issuedTo == issuedBy`. |
| CRL settings via ERS PUT | OpenAPI `PUT /api/v1/certs/trusted-certificate/{id}`. |

Three behaviours no documentation mentions, each found by hitting it:

- **A comma in `description` is refused** with HTTP 400 `Security Check Failed`,
  and the check runs before the duplicate check. `name` accepts commas. The
  import retries once without the description rather than failing the
  certificate, and reports what could not be set.
- **`automaticCRLUpdate`, `enableServerIdentityCheck`,
  `authenticateBeforeCRLReceived` and `ignoreCRLExpiration` may only be true
  when `downloadCRL` is true** — otherwise the whole PUT is rejected. A factory
  certificate commonly has exactly that combination, so the dependent flags are
  forced false rather than losing every other setting to a 400.
- **The PUT replaces rather than patches.** A trust flag left out of the body
  comes back false and the certificate ends up `trustedFor: "Unknown"` — trusted
  for nothing, on a certificate the import had just set correctly. The flags are
  sent again with the CRL settings.

A duplicate is **HTTP 409**, "Certificates are having same subject, same serial
number and they are binary equal. Hence skipping the replace" — wording that
matched none of the existing duplicate detection.

Also confirmed: ISE names a node by its short hostname in `/ers/config/node`
(`ibk-sda-ise1`) but issues its default server certificate to the FQDN
(`ibk-sda-ise1.ntslab.loc`), so an exact comparison never matches and the
per-node certificates were being offered for export.

The whole chain now runs against the box: picker (33 listed, 12 internal CA and
2 node certificates excluded, 19 offered), export, encrypted bundle, pre-flight
(duplicates recognised by fingerprint), and a confirmed import that created a
certificate with its trust flags intact.

### Two things ERS demands that nothing documented

Found on the same box while testing the endpoint import, and both are why that
import had never once succeeded against real hardware.

**ERS writes need a CSRF nonce.** With the CSRF check enabled — it is, by
default, under Administration → System → Settings → API Settings — every ERS
create is refused with an HTML body reading `CSRF nonce validation failed`. The
handshake is a GET carrying `X-CSRF-TOKEN: fetch`, which answers **415** while
returning `X-CSRF-Token` plus `JSESSIONIDSSO`/`APPSESSIONID` cookies; the token
and the cookies must both travel with the write.

The check is per deployment: the second lab box has it **disabled**, so the
box-to-box import run on 2026-08-09 never exercised the handshake. That
behaviour stays proven on the source box only.

The client does the handshake itself rather than asking the operator to turn the
check off. Weakening a security setting on a production source deployment to run
a migration tool is the wrong trade, and the fetch header is harmless on a
deployment where the check is disabled. The nonce is held in memory for the life
of one client, never persisted, and a stale one is refetched once before the
write is retried.

OpenAPI writes are **not** covered by the check, which is why the trusted
certificate import worked throughout and this stayed hidden until an endpoint
had to be created.

**ERS refuses the OpenAPI's own endpoint fields.** Found on 2026-08-07 against
the second lab box, where six of nine static endpoints failed the create with
HTTP 400 `Resource Initialization Failed due to JSON invalidity` and the other
three landed. The correlation was exact: every failure carried a non-null
`ipAddress`, every success had none. `/api/v1/endpoint` returns `ipAddress`,
`vendor`, `productId`, `serialNumber`, `deviceType`, the revision and protocol
fields and the whole `asset*` set; `/ers/config/endpoint` knows none of them and
rejects the entire object, naming every property in the payload rather than the
offending one.

The null strip below hid this completely — those fields are null on an endpoint
ISE has never learned an address for, which is most of them in a quiet lab. A
DHCP-learned address is not null. All of it is runtime state the target relearns,
so the fields are dropped at endpoint create rather than on export, which covers
bundles written before this was known.

**ERS refuses JSON nulls on create**: "Resource Initialization Failed due to JSON
invalidity: please if properties names are correct: ipAddress->...". An endpoint
read from the OpenAPI arrives with a dozen null fields (`ipAddress`, `vendor`,
`mdmAttributes`, the whole `asset*` set), and the export carried them into the
create. Nulls are stripped at `ersCreate`, so every family is covered and so is
any bundle written before the fix. A null means "unset", so dropping it loses
nothing.

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

### The system certificate store, read off the box before it was built

Slice 5, interviewed 2026-08-10. Every shape below was read from the source
deployment's own OpenAPI document and its real objects **before** any code was
written, because the trusted store was built from Cisco's documentation and the
first implementation read zero of the 33 certificates on the box.

The specification is served at `GET /api/v3/api-docs?group=Certificates`.
There is no `/api/swagger.json` — that path answers 404, and
`/api/swagger-resources` lists the 26 groups a 3.4 deployment publishes.

| Path | What it is |
|---|---|
| `GET /api/v1/certs/system-certificate/{hostName}` | The store, **per node**, paged (`page`, `size`, `sort`, `sortBy`, `filter`, `filterType`) |
| `POST /api/v1/certs/system-certificate/export` | Body `{id, hostName, export, password}`; answers a ZIP |
| `POST /api/v1/certs/system-certificate/import` | Body `SystemCert`; **no node field at all** |
| `GET /api/v1/deployment/node` | `hostname`, `fqdn`, `ipAddress`, `roles`, `nodeStatus` |

**The import has no node parameter.** Cisco's own note on the endpoint: "To
import a certificate on a secondary node, execute this RESTApi directly on a
secondary node by specifying the server name of the secondary node in the URL."
A certificate lands on whichever node's URL received the POST, so covering a
deployment means one client per node, dialled at that node's own address with
the credentials already given. `/api/v1/deployment/node` supplies the addresses
and the personas, and only an Admin-persona node serves this API — the target's
`ISE-179` is `SecondaryAdmin`, so it qualifies.

This is the first family that cares about node collapse, and the answer is that
ISE does not collapse anything: the operator picks the target nodes and the
certificate is written to each one separately.

**The export password is constrained where the bundle passphrase is not:**
alphanumeric, minimum 8, maximum 100. The passphrase rule is 12 characters of
anything, so it cannot be handed to ISE verbatim. The certificate password is
therefore **derived** from the bundle passphrase — base32 of a SHA-256 over a
fixed label and the passphrase, truncated — which is alphanumeric by
construction, in range by construction, and identical on both sides because both
sides start from the same passphrase the operator already types. No extra field,
nothing stored, and no rule imposed on what a passphrase may contain.

**What the export actually returns**, confirmed by running it: an
`application/octet-stream` ZIP, `Content-Disposition: attachment; filename=…`,
holding `<sanitised-name>.pem` (the certificate) and, with
`CERTIFICATE_WITH_PRIVATE_KEY`, `<sanitised-name>.pvk` — a PKCS#8
`-----BEGIN ENCRYPTED PRIVATE KEY-----` block. `CERTIFICATE` alone needs no
password and yields the `.pem` only.

**The private key is never opened.** The `.pvk` text travels into the bundle as
an opaque blob and goes back to ISE as `privateKeyData` with the derived
password. The tool holds no plaintext key at any point, and the key is wrapped
twice on disk: by ISE's password and by the bundle's own AES-GCM.

The list carries `id`, `friendlyName`, `issuedTo`, `issuedBy`, `validFrom`,
`expirationDate`, `usedBy`, `keySize`, `groupTag`, `portalsUsingTheTag`,
`selfSigned`, `serialNumberDecimalFormat`, `signatureAlgorithm` and
`sha256Fingerprint`. Two differences from the trusted store: `selfSigned` really
exists here, and dates are the same Java `Date.toString()`.

**It carries no SANs and no certificate**, which is why the picker fetches
`export: CERTIFICATE` per certificate — no password, no private key, about 2 KB
each — and parses subject, SANs, key size and validity locally. A wildcard or
multi-SAN default-tick guessed from `issuedTo` would be a guess; parsed from the
certificate it is a fact.

**Roles read back as one string and write as booleans**, the same read/write
split the trusted store's `trustedFor` has. Observed on the source: `Admin, EAP
Authentication, RADIUS DTLS`, `Portal`, `pxGrid`, `SAML`, `ISE Messaging
Service`, `Not in use`. The write side is `admin`, `eap`, `radius` (RADSec and
RADIUS DTLS), `tacacs`, `pxgrid`, `ims` (the messaging service), `saml`,
`portal`. The mapping is a table, and an unrecognised token is reported rather
than dropped.

`SystemCert` demands seven booleans on every create:
`allowExtendedValidity`, `allowOutOfDateCert`,
`allowPortalTagTransferForSameSubject`, `allowReplacementOfCertificates`,
`allowReplacementOfPortalGroupTag`, `allowRoleTransferForSameSubject`,
`allowSHA1Certificates`. **The three that would overwrite something are always
false**: replacement of certificates, replacement of the portal group tag, and
role transfer for a matching subject. Create-only is not a preference here — a
node may be serving the certificate that would be replaced.

**Roles travel verbatim except admin**, which is forced off unless the operator
ticks one run-level box, warned that it restarts the node's application and
replaces the certificate the GUI is served with. The rule from the original
interview stands; what is new is that the operator can overrule it deliberately.

**A held portal group tag drops the portal role rather than moving the tag.**
Pre-flight reads the target's own store, sees which tags are taken and by what,
and says up front that the certificate will be created without `portal` and
without `portalGroupTag`. The source box shows why this matters: its self-signed
portal certificate holds `Default Portal Certificate Group` with twelve portals
on it, and moving that tag would take every one of them with it.

**Per node, a matching SHA-256 is a skip and a taken name is blocked.** Nothing
is renamed and nothing is replaced. The skip names what the target calls the
certificate, as the trusted store does.

**A missing issuer blocks the certificate**, with the issuer DN in the reason
and trusted certificates created in the same run counted as present — the
`willExist` rule the endpoint groups already use. ISE refuses a system
certificate whose chain it cannot build, and a blocked item explains that better
than a 400 does.

**The picker hard-excludes only expired certificates.** Everything else is
listed with a reason and stays selectable: the lab already produced one filter
that was correct by its rule and wrong in effect, so judgement belongs to the
operator. Ticked by default: a wildcard CN or SAN, or more than one DNS SAN.
Listed unticked with the reason: single-name certificates, self-signed ones, and
anything signed by this deployment's internal CA — six of the source's nine
certificates are exactly that, ISE Messaging Service and Certificate Services
artifacts the target regenerates for itself.

**A node that stops answering mid-import is reported and skipped, never
retried.** A role change restarts the application on that node, so a failed
write is expected rather than exceptional; retrying it could create a second
copy of a certificate the first write already landed, and this tool issues no
DELETE.

**The 3.2 fallback is built, not deferred.** The API export is 3.3+, so a 3.2
source is covered by the operator exporting the ZIP from the GUI and attaching
it. Those keys keep the password set in the GUI, which cannot be re-wrapped
without opening the key, so the bundle records `keySource: api | zip` and a
second password field appears — at export when a ZIP is attached, at import only
when the bundle actually holds a ZIP-sourced key. An attached ZIP has no roles
and no friendly name, so its name defaults to the certificate's CN and is
editable, and its roles are ticked by hand.

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

Every field name, path and payload shape originally came from Cisco's
documentation, because the lab (`ntslab.loc`) was offline while slices 1, 2 and 3
were built. It answered on 2026-08-07; the probe, the endpoint reads and the
entire trusted certificate path have now been exercised against a real
standalone (3.4.0.608, node `ibk-sda-ise1`), including the endpoint import: a
group and a statically assigned endpoint were created on the box, the endpoint
following the target's own group UUID, and a re-run created nothing.

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

1. `/ers/config/profilerprofile` — used for the profile-name remap.
2. Egress matrix cell shape (not yet built).
4. Condition library payloads (not yet built).

Verified on 3.4 and no longer guesses: `/api/v1/endpoint` (bare JSON array, with
`mac`, `groupId`, `profileId`, `staticGroupAssignment` and
`staticProfileAssignment` all as assumed), `/ers/config/node`, the whole
trusted certificate surface described above, and — read off the box on
2026-08-10, ahead of the code — the system certificate list, export and import
schemas, the export ZIP's `.pem`/`.pvk` entries, and `/api/v1/deployment/node`.

What system certificates still cannot claim is a **write**: no certificate has
been imported onto a target node yet, so the role mapping, the portal tag
behaviour and the restart-mid-import path are proven only as far as the
specification and the source's own objects go.

The code reports what it actually received when a shape does not match, rather
than panicking or returning empty. Read those messages literally.

### The first real migration, source to target

A second deployment answered on 2026-08-07, which made the first end-to-end run
between two real boxes possible: 3.4.0.608 at `172.24.89.178`, **two nodes**
(`ISE-178`, `ISE-179`), ERS and OpenAPI both on. `ntslab.loc`'s standalone was
the source.

It is neither fresh nor standalone, so it contradicts the assumption at the top
of this file in both directions — and nothing broke, because create-only means
the target's own state decides what happens: 52 of 72 objects were already there
and were skipped by name. What the two-node target does *not* yet exercise is the
node-collapse assumption, since neither endpoints nor trusted certificates carry
a node reference. System certificates will be the first family that cares.

The run: 44 endpoint identity groups, 9 statically assigned endpoints and 19
trusted certificates exported into a 69 KB encrypted bundle, pre-flight reporting
20 create / 52 skip / 0 blocked, and after the endpoint fix above a confirmed
import creating all of them and two further re-runs creating nothing.

One thing the operator caught that the code did not: a self-signed certificate
for `ibk-sda-ise2.ntslab.loc` sat in the source's trust store and was offered for
export. The per-node exclusion only drops a self-signed certificate whose CN
matches a node of *this* deployment, and `ise2` is not a node of the standalone —
so a dead node certificate from some other box passed the filter. Correct by the
rule as written, wrong in effect. Widening the rule to "any self-signed
certificate whose CN is an FQDN" would also drop legitimate self-signed roots, so
the picker, not the filter, is the place this gets decided; it is worth flagging
such a certificate in the UI rather than silently offering it.

### Lab checklist, when the lab is back

Do this **before** building more slices — the policy, TrustSec and certificate
work all sits on top of this client, and an hour here is worth more than another
slice on unverified shapes.

1. ~~Enable ERS and OpenAPI; confirm the probe reports version, nodes, both
   APIs~~ — done. 3.4.0.608, node `ibk-sda-ise1`, both on.
2. ~~Probe with a deliberately wrong password~~ — done. Both APIs report 401 with
   the either/or wording, no false "API off".
3. Probe with OpenAPI disabled — confirm it distinguishes that from a bad
   password. **Still open, and harder to reach than expected.** ISE 3.4's API
   Settings page offers no OpenAPI switch at all: under API Service Settings
   there is only ERS, for the primary administration node and for the others.
   An ERS-only admin account does not stand in for it either — an account in the
   **ERS Admin group and nothing else** was granted OpenAPI reads on trusted
   certificates, endpoints and the policy tree on 2026-08-09, so the role does
   not gate OpenAPI on this release. Whatever makes OpenAPI unusable in the field
   is the service being unreachable, not RBAC. Fake-verified only, and the fake
   is the honest place for it until a box turns up where the gateway can be
   stopped.
4. ~~Export endpoint identity groups~~ — done, 44 returned. Still worth comparing
   the count against the GUI.
5. ~~Export static endpoints from one group~~ — done. 171 endpoints read from the
   OpenAPI, 1 static in the selected group, 170 outside it.
6. Confirm an endpoint with a static *profile* assignment round-trips its profile
   name. **Still open**: the lab's static endpoints are all group-assigned.
7. Import; confirm the pre-flight blocks an endpoint whose profiler profile is
   missing, and that nothing is written before confirm. **Half done**: nothing is
   written before confirm (verified), the blocked case is fake-verified only.
8. ~~Confirm a created endpoint points at the **target's** group UUID~~ — done.
   The group was recreated with a new UUID and the endpoint followed it.
9. ~~Re-run the same import~~ — done. Nothing created, nothing duplicated,
   nothing failed.
10. ~~Try a bundle with the wrong passphrase; confirm the error is legible~~ —
    done. Both a wrong passphrase and a truncated bundle answer `wrong
    passphrase, or the bundle is corrupt or was tampered with`, before any
    connection to the target is made.

Trusted certificates — items 11, 12, 14, 15 and 16 were done on 2026-08-07 and
their answers are in "Verified against ISE 3.4.0.608" above. What is left:

11. Compare the picker's 19 offered certificates against Administration → System
    → Certificates → Trusted Certificates in the GUI.
12. Confirm an **expired** certificate is blocked and never attempted. The lab
    store has none, so this remains fake-verified only.
13. ~~Re-run an import of certificates the target already has and confirm every
    one is skipped, none duplicated — including one **renamed on the target**~~ —
    done. 17 of 19 source certificates were recognised as already present on a
    target that had never seen this bundle, and two full re-runs created nothing.
    The renamed case was then forced by hand: `ROOTCA NTSLAB`, imported by the
    tool, was renamed to `ROOTCA NTSLAB 2` in the target's GUI, and pre-flight
    still reported 0 create / 71 skip. Only the SHA-256 fingerprint could have
    matched it, which is what the fingerprint path exists for.

    A content match under a different name now says so — `already exists on the
    target as "ROOTCA NTSLAB 2" (same certificate, different name)` — while a
    name match keeps the plain wording. A skip the operator cannot account for is
    the one worth reading twice: the target already trusts that CA under a name
    nobody here chose.
14. With OpenAPI disabled on the target, confirm pre-flight blocks the family
    once with a legible reason rather than per certificate. **Blocked on the same
    thing as item 3** — 3.4 offers no way to turn OpenAPI off, and the ERS Admin
    role does not withhold it. Fake-verified only.
15. Import a certificate whose description contains a comma and confirm the
    retry lands it without the description and reports what was dropped. The lab
    cannot hold such a description, so this too is fake-verified only.

Send back whatever it gets wrong — the error text is designed to be quotable.

---

## The group picker decides what exists, not just what is read

Reversed on 2026-08-09, at the operator's request. Until then, ticking the
endpoint identity group family carried **all** groups regardless of the picker,
and the picker only bounded which groups' endpoints were read. The reasoning was
that a group is cheap and an endpoint's group must exist on the target.

That is true and it misses the point: a deployment that has been alive for years
accumulates groups nobody uses any more, and a migration is the one moment they
can be dropped without anyone arguing about it. The tool cannot tell which are
dead — the operator can. So the picker is now the single scope: a ticked group is
created on the target and its static endpoints travel; an unticked one is
neither created nor read.

All groups are still *read* from the source, because the list is also the
`groupId → name` table that turns an endpoint's group into something portable.
Only the selected ones enter the bundle, and one note names the rest, so the
import side can tell a decision from an omission.

Selecting nothing is refused rather than exported, in the browser and again in
the handler before the client connects. The old behaviour — a note saying no
endpoints were exported — is the wrong answer now that the same emptiness would
also mean no groups.

**Built-ins are ISE's own claim, not a list of ours.** The ERS detail object
carries `systemDefined`, so `Profiled`, `Unknown`, `Blocked List` and the rest
sort last under a divider without anyone maintaining a per-release name list.
This is the same rule the trusted store follows for Cisco's factory roots. The
flag is only on the detail object, so the picker reads all 44 group objects — the
export makes that identical read anyway.

### Which groups a policy still points at

The operator's question — *which of these are actually dead?* — is answerable
from the box, so the picker answers it rather than relying on memory.

A rule that matches on an endpoint identity group stores it like this, verified
on 3.4:

```
dictionaryName: IdentityGroup
attributeName:  Name
attributeValue: Endpoint Identity Groups:Production:Siemens
```

**By name, not by UUID** — which is why such a reference survives a migration at
all, and why it can be counted without resolving anything. The value carries the
group's nesting path and the group is the last segment; endpoint identity group
names are unique in ISE, which the import's own duplicate check already relies
on, so the leaf identifies it.

Eight documents are read: the policy sets of both trees, each set's
authentication and authorization rules, and each tree's shared condition library.
The lab's source answers 200 on all eight and yields 7 references across 5 policy
sets. Each is walked generically rather than by modelling the rule schema —
conditions nest to arbitrary depth, the shapes are needed for nothing else here,
and a generic walk cannot miss one by getting the structure wrong.

**Device admin policy is scanned and never migrated.** TACACS policy is out of
scope and stays out of scope; the badge answers "is anything on this box using
this group", and a group used only by device admin rules is in use. Reporting it
as unused would be the tool encouraging exactly the deletion this feature exists
to prevent.

**A scan that fails costs the badge, never the migration.** The groups are
returned regardless, with one sentence saying what could not be read. This
matters more than it looks: a refused scan and a deployment whose policy
references no groups both produce zeros, and presenting the first as the second
would talk an operator into dropping a group a rule depends on.

The badge is advisory in the other direction too. A referenced group can still be
left behind deliberately — the tool reports, it does not veto. The consequence is
recorded rather than prevented: once the policy slice lands, a rule whose group
was left behind fails pre-flight, correctly, and that is the trade this feature
buys.

---

## Roadmap

Ordered by dependency, not by size.

1. ~~Network device CSV translation~~ — done, verified against real data.
2. ~~API core: client, probe, encrypted bundle, endpoint groups + static
   endpoints~~ — done, fake-ISE verified only.
3. ~~Trusted certificates~~ — built and then corrected against real 3.4 on
   2026-08-07. Export, pre-flight and a confirmed import all exercised against
   the lab.
4. **Finish lab verification**: the handful of checklist items the lab's own
   contents cannot exercise — a static *profile* assignment, an expired
   certificate, a comma in a description, OpenAPI switched off. Everything
   structural is now proven on hardware.
5. **System certificates** — operator-selected, the 3.3 export-with-private-key
   API and the 3.2 GUI-ZIP fallback, admin role off. Interviewed and its API
   surface read off the source box on 2026-08-10, before any code; see the
   section above. In build.
6. **Policy elements** — network device groups, condition library, dACLs,
   authorization profiles, identity source sequences. Introduces the factory
   allowlist update mechanism.
7. **TrustSec** — SGTs, then SGACLs, then the egress matrix (needs both).
8. **Policy sets and rules** — the two-pass UUID remap. Most dependent on lab
   iteration; deliberately last.
9. **AD join point** config export, creation, and `addGroups`.
10. **Network device CSV → API import.**
