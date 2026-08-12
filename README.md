# ise2ise

Migrates Cisco ISE configuration between two independent deployments.

Three tools, all in one local binary with a browser UI on `127.0.0.1`:

- **Export** — read objects from the source deployment over the ISE APIs and
  write an encrypted transfer bundle.
- **Import** — decrypt a bundle on the other side, resolve every cross-reference
  against the target, show a pre-flight report, and only then create what is
  missing.
- **Network device CSV** — translate a network device export into the target
  release's column layout. The API masks device secrets, so the CSV is the only
  route that carries them.

## Why the CSV tool exists

ISE's GUI export of network devices contains the RADIUS and TACACS shared
secrets, the SNMP auth/privacy passwords, the TrustSec (SGA) device passwords
and the EXEC/enable passwords **in plaintext**. The REST API masks all of them,
so the CSV is the only route that carries a device's credentials to a new
deployment.

The problem: the CSV column set changes between ISE releases (3.2 through 3.5
are all confirmed to differ), so a CSV exported from an older deployment is
rejected by a newer one. `ise2ise` rewrites the source export into the target's
own column layout, using a template the operator downloads from the target ISE.

It keys off the column *label* only — everything after the label is the ISE
release's own type annotation (`Name:String(32):Required`,
`SNMP:Polling Interval:Integer:600-86400 seconds`), and the target's template is
the authoritative schema. Nothing in the tool is hardcoded to a release.

What it does beyond reordering columns:

- **Reports data loss.** Any source column with no home in the target layout is
  listed as a warning; that is the whole point of running the tool instead of
  eyeballing the file.
- **Refuses masked secrets.** A row whose shared secret reads `******` would
  import that literal string and silently break RADIUS for the device, so the
  row is not written and is named in the report.
- **Drops read-only columns.** The TrustSec PAC issue/expiry/issuer columns are
  runtime state; ISE re-provisions the PAC when the device authenticates.
- **Rewrites node hostnames.** Optionally replaces the source deployment's node
  hostname in `SNMP:Originating Policy Services Node` and
  `SGA:CoA Coa Source Host` with the target node's.

## CSV workflow

1. Source ISE: `Administration → Network Resources → Network Devices → Export`.
2. Target ISE: `Administration → Network Resources → Network Devices → Import`,
   click **Generate a Template**, download it.
3. Run `ise2ise`; the browser opens on `http://127.0.0.1:8777/`.
4. Upload both files, optionally enter the target node's hostname, translate.
5. Review the report — especially the data-loss and refused-row warnings.
6. Download `network-devices-translated.csv` and import it on the target ISE.

Handle both CSVs as credential material and delete them when you are done.
`.gitignore` excludes `*.csv` for that reason.

## API migration

### Enabling the APIs

Both ISE APIs are off out of the box. On **each** deployment:
`Administration → System → Settings → API Settings` → enable **ERS** (port
9060) and **OpenAPI** (port 443), and use an account with the **ERS Admin**
role (plus **API Admin** for OpenAPI). Leave the **CSRF check** however you like
— the tool performs ISE's nonce handshake, so it works either way. ise2ise probes both and tells you which
one answered; when only ERS is available everything still works, just slower,
because ERS needs one GET per object.

Nothing decides behaviour from the ISE version — capability is probed, and
whatever is missing is skipped and reported. Both ends are expected to be
ISE 3.x. The source may be standalone or distributed; the target is *expected*
to be a **freshly installed standalone**, because import is **create-only**: an
object that already exists is skipped and counted, never overwritten, and the
tool issues no DELETE under any circumstances.

That expectation is a design assumption, not a requirement the tool enforces.
A migration has been run into a two-node target that was not fresh, and the
create-only rule is what made it uneventful: everything already present was
skipped by name. System certificates are the one family that cares which node it
is writing to, and they ask: you pick the target nodes, and each one is written
separately.

### Export

Connect to the source, look at the probe result (version, nodes, which APIs are
on), pick the object families and then what to take from them — the endpoint
identity groups to migrate, the trusted certificates to carry — give a
passphrase, run. Progress streams live. The result is a single encrypted file.

**The group selection is the scope for both endpoint families.** A group you
tick is created on the target and its static endpoints travel; a group you leave
unticked is neither created nor read. That is how a deployment sheds the groups
it stopped using years ago — the tool cannot tell which those are, you can. One
note in the bundle names everything left behind, so the import side can tell a
decision from an omission. Selecting no groups at all is refused rather than
quietly producing an empty bundle.

Two things in the picker help you choose:

- **ISE's own built-in groups sort last**, under a divider. That comes from the
  `systemDefined` flag ISE puts on each group, not from a list in this tool, so a
  future release's new groups land in the right place without a code change.
- **A group a policy rule points at is badged** with how many rules use it, and a
  `used by policy` link ticks exactly those. Both policy trees are read, network
  access and TACACS device admin, because a group used only by device admin rules
  is still in use — device admin policy itself is never migrated. The badge is
  advisory: you can still leave a referenced group behind on purpose. If the scan
  cannot read the policy tree it says so rather than showing zeros, because a
  refused scan and a deployment that references no groups look identical
  otherwise.

Endpoints are filtered to the ones with a **static** group or profile
assignment. Everything else is profiler output that the new deployment
regenerates by itself, so carrying it is pointless churn. Endpoints are read
from the OpenAPI when it is available (whole objects in one call) and from ERS
otherwise.

### The bundle

AES-256-GCM, key from PBKDF2-HMAC-SHA256 with 600 000 iterations and a random
16-byte salt; the file header (magic, format version, salt, nonce) is
authenticated as GCM additional data. There is no unencrypted mode and no
recovery: lose the passphrase and the bundle is gone.

**Credentials are never in the bundle.** They are held in memory for the
duration of a request and nowhere else — not on disk, not in a log, not in a
session.

### Import and the pre-flight gate

Import writes nothing until you confirm. It decrypts the bundle, resolves every
cross-reference against the target, and reports three lists: what will be
created, what already exists and will be skipped, and what **cannot** be
resolved. Unresolvable objects are never attempted — a dangling reference is
worse than a missing object. Only after the confirm button does anything get
written, and the pre-flight is re-run server-side at that moment in case the
target moved.

Cross-references travel **by name**, never by UUID: on export an endpoint's
`groupId` and `profileId` are resolved to the group and profiler-profile names;
on import those names are resolved against the target's own UUIDs. A profiler
profile that does not exist on the target blocks that endpoint at pre-flight.

### What travels today

| Family | Notes |
|---|---|
| Endpoint identity groups | The ones you select, and only those. Group nesting is not carried and is reported. |
| Static endpoints | Only in the groups you select, only static assignments, identified by MAC. |
| Trusted certificates | The ones you select. Internal CA and per-node self-signed certificates are excluded for you. See below. |
| System certificates | The ones you select, with their private keys, onto the target nodes you select. See below. |
| Policy elements | Network device groups, dACLs, authorization profiles, identity source sequences and conditions, all of them. See below. |
| Policy sets and rules | The sets with their authentication and authorization rules. They arrive **disabled**. See below. |
| Identity sources | Certificate authentication profiles are created; REST identity stores are reported for you to build by hand. See below. |
| Active Directory join points | The join point and its whole configuration. **You join the domain**; the tool loads the groups on the next run. See below. |

### Trusted certificates

Pick them from a list, the same way you pick endpoint identity groups. Two kinds
are excluded automatically, unticked and labelled with the reason:

- **ISE internal CA certificates.** The internal CA cannot be moved — Cisco's own
  procedure regenerates it on a new deployment — and its root on the target would
  be trust the target should not have.
- **Per-node self-signed server certificates.** Their CN is a source node
  hostname that will never exist again.

Cisco's factory roots are not filtered out; they are already on the target, so
they land in the pre-flight report as "already exists" and cost nothing.

What to expect:

- **Duplicates are matched by SHA-256 fingerprint**, not by name, so a
  certificate the target already holds under a different friendly name is still
  recognised and skipped — and the report names the target's own name for it,
  since a skip you cannot account for is the one worth reading twice. If the
  target does not report fingerprints, the tool falls back to name matching and
  says so once in the report.
- **Expired certificates are blocked** at pre-flight with the expiry date, and
  never attempted.
- **All four trust purposes travel as they were on the source**, including
  certificate-based admin authentication. Check them on the target if that one is
  in use.
- **A certificate chain is split** into its members. Members that had no friendly
  name of their own on the source are named from their subject CN.
- **CRL settings are restored** after the certificate is created. If that second
  step fails the certificate still stays — the report names the settings to enter
  by hand. An OCSP service selection is never carried, because OCSP service
  configurations are out of scope; the report names the service.
- **A description containing a comma cannot be set.** ISE refuses the import
  outright ("Security Check Failed"), so the certificate is imported without its
  description and the report tells you what to paste back in.
- **Importing needs OpenAPI on the target.** It is the only create path ISE
  offers for this family — the ERS resource does not exist. With OpenAPI off, the
  whole family is blocked with one line in the report rather than one line per
  certificate.

This path has been run against a real ISE 3.4 deployment: 33 certificates listed,
14 excluded, export and encrypted bundle, pre-flight recognising duplicates by
fingerprint, and a confirmed import creating a certificate with its trust
purposes intact.

### System certificates

These are the ones with a private key: the certificate a node presents for EAP,
RADIUS, portals, pxGrid or the admin GUI. Only a **wildcard or multi-SAN**
certificate really makes sense to move — a per-node identity certificate names a
source FQDN that will never exist on the target — so those are the ones the
picker ticks for you. Everything else is listed unticked with the reason, and
stays selectable, because the judgement is yours. Expired certificates are the
only ones you cannot tick.

The private key never lies open. ISE encrypts it on export, the encrypted block
goes into the bundle untouched, and it goes back to ISE the same way; the tool
does not open it at any point. The password ISE uses is derived from your bundle
passphrase, so there is nothing extra to type or to remember, and no password is
stored anywhere.

**Choose which target nodes get the certificate.** ISE's import API has no node
field at all — a certificate lands on whichever node received the request — so
the pre-flight lists the target's Admin-persona nodes, ticked, and the import
writes to each one you leave ticked. Nodes that serve no admin API are shown
disabled. The report has one line per certificate per node, so what you confirm
is what gets written.

What to expect:

- **The admin role is off unless you ask for it.** One checkbox on the import
  step turns it on. It restarts the application on that node and replaces the
  certificate the GUI is served with, so if your browser does not trust the new
  chain you lose the UI until it does. Every other role travels as it was.
- **A held portal group tag is not taken.** If a certificate on the target
  already holds the tag, yours is created without the portal role rather than
  moving the tag — which would take every portal on it away from a certificate
  the node is serving. The pre-flight says so before you confirm, and names the
  holder.
- **Nothing is ever replaced or renamed.** A certificate already on the node with
  the same SHA-256 is skipped; a *different* certificate already using the same
  name blocks that one, and is reported.
- **The issuing CA has to be on the target**, or the certificate is blocked with
  the issuer named. A CA travelling in the same bundle counts, so exporting the
  trusted certificate family alongside usually resolves it in one run.
- **A node that stops answering is reported, not retried.** A role change can
  restart the node's application; the run moves on to the next node and tells you
  to re-run once it answers. Re-running is safe — what landed is skipped.
- **From an ISE 3.2 source**, where the export API does not exist, export the ZIP
  from the ISE GUI and attach it in the export step. The tool reads the
  certificate out of it so you can name it and tick its roles. That key keeps the
  password you set in the GUI, so you are asked for it once on export and once on
  import; certificates taken through the API are not affected.

This path has been run between two real ISE 3.4 deployments: a multi-SAN
certificate exported with its private key, its issuing CA carried in the same
bundle, both created on a two-node target with EAP and RADIUS DTLS on each node,
the portal role dropped because the tag was held there, and a re-run creating
nothing. What has still never been exercised is taking the **admin** role, the
3.2 GUI-ZIP path, and a node restarting mid-import.

### Policy elements

One checkbox carries five families: network device groups, dACLs, authorization
profiles, identity source sequences and conditions. There is no per-object
picker — unlike certificates, nothing here is dangerous or pointless to carry,
and what the target already has is skipped.

- **Nothing is ever overwritten, including ISE's own objects.** A name the target
  already has is skipped. But the pre-flight compares the two copies and, when
  they differ, names the fields: `already exists on the target and DIFFERS from
  the source in dacl; not changed`. That is how a customised `PERMIT_ALL_IPV4_TRAFFIC`
  or a reordered `All_User_ID_Stores` shows up instead of quietly staying at the
  target's version.
- **Device groups pull in their parents.** ISE stores the hierarchy in the name
  (`Device Type#All Device Types#Router`), so a group you carry creates any
  missing ancestor, each listed in the report with the child that required it.
- **A missing reference blocks, except a portal.** An identity source sequence
  naming a store the target lacks, or an authorization profile reading from a
  dictionary it lacks, is blocked with the missing thing named — both usually
  mean "join the domain on the target first, then re-run". A profile whose web
  redirection names a portal the target lacks is **created without the redirect**
  and the report says so; portals are not migrated by this tool.
- **What the import created is marked.** Every object the tool creates gets
  `[ise2ise 2026-08-10]` appended to its description, so the ISE list views show
  at a glance what came from a migration. ISE has no enabled/disabled state on
  any of these object types — only policy sets and rules have one — so the
  description is the only place to put it. The marker is ignored when comparing
  content, so a re-run still reports "already exists, identical", and marking
  never stacks.
- **Two of ISE 3.4's own reads can fail, and you will see it.** Listing
  authorization profiles can answer HTTP 500 with a conversion exception on
  `cisco-av-pair` — one profile ISE cannot serialise takes the whole listing
  with it, and which ones differ per deployment — so the tool reads them one at
  a time instead. A profile
  holding a web redirection can fail that read too — ISE cannot deserialise its
  own object — and such a profile is **not exported**: it is named in the report,
  with ISE's error, for you to recreate by hand. On the lab source that is one
  profile out of 27.

Conditions travel from the network-access tree only, all three kinds (library,
time, network). Device admin policy is never migrated, so its conditions are not
either.

This slice has **not been run against real hardware**. Every read shape was taken
off a real 3.4 deployment before it was written, but no policy element has been
created on a real target yet.

### Policy sets and rules

Ticking this also ticks policy elements, and locks it: nearly every rule names an
authorization profile or an identity source sequence, so a sets-only bundle is
one whose rules cannot resolve.

**Everything imported arrives disabled.** A migration cannot change how the
target treats traffic until you enable it deliberately — and it means the sets
that came from the migration are exactly the ones switched off. One checkbox on
the import step carries the source's own state instead, for a live cutover.

- **Rank is appended, never reused.** Imported sets land after everything the
  target already has, in their source order, and always above the target's
  `Default`. Rules do the same inside their set. Your existing evaluation order
  is not rearranged.
- **`Default` is the one set whose rules are merged.** It exists on every
  deployment and cannot be created, so the set is skipped and its rules are added
  beside the target's own — a rule name the target already has is left alone.
- **Any other name clash is imported beside it** as `Guest (imported)`, then
  `(imported 2)`. The target's set is never touched or merged into. Imported sets
  carry the same `[ise2ise …]` description marker as policy elements, which is
  how a re-run recognises its own work and writes nothing.
- **A reference the target cannot resolve blocks the whole set**, nothing from it
  written, with a note naming what is missing. A set that landed without one of
  its rules would still match the traffic and then treat it differently than the
  source did. In practice this means SGTs (TrustSec is not migrated yet),
  certificate authentication profiles, and AD join points — join the domain on
  the target and re-run.

Per-set exceptions, global exceptions and MFA rules are not carried; a bundle
whose source had them gets a note per set.

### Active Directory join points

This is the one family that needs you in the middle of it, and it takes two
import runs with a manual step between them:

1. **First import** creates the join point on the target with its whole
   configuration, **not joined**. The report says so.
2. **You join the domain** in `Administration → Identity Management → External
   Identity Sources → Active Directory`, with your own domain credentials.
3. **Second import** loads the join point's AD groups, and everything that was
   blocked on the AD dictionary or those groups now goes through.

The domain join is deliberately not automated. ISE does expose an API for it, but
joining creates a computer object in Active Directory and fails per node in ways
ISE reports afterwards — that is a domain administrator's action, and keeping it
manual means **no AD credentials ever reach this tool**. There is no code path
that can call it.

- **The whole configuration travels**: domain, description, the allowed-domain
  list, the AD scope, the AD attributes and every advanced setting — machine
  authentication, aging time, the rewrite rules, the not-in-AD and unreachable
  domain behaviours, failed-authentication protection. Nothing is trimmed to make
  a create succeed; if ISE refuses it, the report carries its words.
- **All the join point's groups travel**, with their SIDs. That list is already
  an administrator's selection — ISE holds only the groups someone added from the
  directory — and both deployments joining the same domain means the SIDs match
  and policy references resolve.
- **A domain already joined under a different name blocks**, naming both. Adding
  a second join point for the same domain is a configuration change, not a
  migration, so the tool leaves the decision to you.
- **A join point created in the run counts as an identity source** immediately,
  so identity source sequences and rules that name it can land in the same pass.
  Its dictionary and its groups do not — those exist only after the join, which
  is why the second run matters.
- **If you created the join point yourself, its AD attributes are reported, not
  copied.** You have to create a join point before you can join a domain, so in
  practice yours already exists and the tool skips it. ISE offers no way to add
  an attribute to an existing join point — a `PUT` answers 405 and there is no
  attribute operation — so the report names each attribute the source has and
  yours does not, for you to add under the join point's **Attributes** tab. This
  matters: an authorization profile that reads one is refused by ISE with an
  empty HTTP 500 until the attribute is there. Advanced settings that differ are
  reported the same way and never changed.

Ticking policy sets ticks this family too, since rules name the join point as
their identity source.

### Identity sources

Certificate authentication profiles are migrated normally. **REST identity stores
are not created** — they are reported, with everything you need to build one.

That is not a shortcut. ISE will accept a REST identity store over its API and
produce something unusable: the device attributes and device query settings
cannot be written by any API, and a store missing them does not even show those
tabs in the GUI, so it cannot be completed or saved there either. The only
remaining action on such a store is to delete it. The report therefore names the
provider, `rootUrl`, username suffix, client id and tenant id, and you create it
under `Administration → Identity Management → External Identity Sources → REST
(ROPC)`.

Because nothing is written, **the application secret is not carried** in the
bundle at all — take it from your own records when you build the store. The
client id and tenant id do travel; neither is a credential on its own.

## Running

Prebuilt binaries are attached to each release —
[github.com/fox27374/ise2ise/releases](https://github.com/fox27374/ise2ise/releases):

```
ise2ise-darwin-arm64
ise2ise-darwin-amd64
ise2ise-windows-amd64.exe
ise2ise-linux-amd64
```

`SHA256SUMS` is attached alongside them. On macOS and Linux, `chmod +x` the file
you downloaded.

### Verifying a download

Releases from **v0.5.0** are reproducible: building the tag yourself produces the
published bytes, so you can establish that a binary came from this source instead
of trusting the pipeline that built it. `-trimpath` keeps the builder's directory
out of the binary, `CGO_ENABLED=0` stops a native macOS build from linking the
host SDK when a cross build does not, and the Go patch version is pinned in the
release workflow. Those three are the whole difference between a checksum that
says "this is what CI produced" and one anybody can check.

```
git checkout v0.5.0
make dist
cd dist
curl -sLO https://github.com/fox27374/ise2ise/releases/download/v0.5.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

Four `OK` lines means the release matches this source. This was confirmed for
v0.5.0 on macOS against binaries the Ubuntu runner cross-compiled — all four
targets byte-identical.

v0.4.0 and earlier were built before those flags and will **not** match; for
those, `SHA256SUMS` only tells you a download arrived intact.

Or from source (Go 1.24+, stdlib only, no third-party modules):

```
go run .
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `8777` | Port to listen on. |
| `-open` | `true` | Open the UI in the system browser on startup. |
| `-verify-tls` | `false` | Verify the ISE TLS certificate. Off by default because ISE ships a self-signed one; the UI says so out loud while it is off. |

The server binds `127.0.0.1` only — there is deliberately no way to bind a
routable interface. The UI is unauthenticated and handles credential-bearing
files. Uploads and results are never written to disk; the browser downloads the
translated CSV and the encrypted bundle from in-memory blobs.

## Building

```
make build   # ./ise2ise for the host platform
make test    # gofmt -l . && go vet ./... && go test ./...
make dist    # all four cross-compiled binaries into dist/ (git-ignored)
```

Releasing is a tag. The workflow in `.github/workflows/release.yml` re-runs the
checks, cross-compiles, and attaches the four binaries and their checksums:

```
git tag v0.3.0 && git push origin v0.3.0
```

## Not yet implemented

Everything below is a later slice. None of it exists in the binary today, not
even as a stub:

- Full TrustSec: SGTs, SGACLs, egress matrix
- Network device CSV → API import

The probe, both endpoint families and the whole trusted certificate path have
been exercised between two real ISE 3.4 deployments, import included: groups,
statically assigned endpoints and trusted certificates exported from one box and
created on another, with re-runs creating nothing. Everything still to be built
comes from Cisco's documentation rather than a live box. When a response does not
have the expected shape, the tool reports what it actually received instead of
failing silently; please read those messages literally when you hit one in a lab.
