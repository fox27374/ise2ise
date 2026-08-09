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
skipped by name. Nothing today carries a node reference, so the single-node
assumption has not been exercised yet — system certificates will be the first
family that cares.

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

System certificates — the ones with a private key — are a later slice.

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

- Network device groups
- Condition library
- dACLs
- Authorization profiles
- Identity source sequences
- Full TrustSec: SGTs, SGACLs, egress matrix
- Policy sets and rules, with UUID remapping
- AD join point configuration and `addGroups`
- System certificates (the ones with a private key)
- Network device CSV → API import

The probe, both endpoint families and the whole trusted certificate path have
been exercised between two real ISE 3.4 deployments, import included: groups,
statically assigned endpoints and trusted certificates exported from one box and
created on another, with re-runs creating nothing. Everything still to be built
comes from Cisco's documentation rather than a live box. When a response does not
have the expected shape, the tool reports what it actually received instead of
failing silently; please read those messages literally when you hit one in a lab.
