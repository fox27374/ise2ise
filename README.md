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
role (plus **API Admin** for OpenAPI). ise2ise probes both and tells you which
one answered; when only ERS is available everything still works, just slower,
because ERS needs one GET per object.

Nothing decides behaviour from the ISE version — capability is probed, and
whatever is missing is skipped and reported. Both ends are expected to be
ISE 3.x. The source may be standalone or distributed; the target is expected to
be a **freshly installed standalone**, so import is **create-only**: an object
that already exists is skipped and counted, never overwritten.

### Export

Connect to the source, look at the probe result (version, nodes, which APIs are
on), pick the object families and — for endpoints — the endpoint identity
groups to export from, give a passphrase, run. Progress streams live. The
result is a single encrypted file.

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
| Endpoint identity groups | All groups, so an endpoint's group exists on the target. Group nesting is not carried and is reported. |
| Static endpoints | Only in the groups you select, only static assignments, identified by MAC. |

## Running

Prebuilt binaries are in `dist/`:

```
dist/ise2ise-darwin-arm64
dist/ise2ise-darwin-amd64
dist/ise2ise-windows-amd64.exe
dist/ise2ise-linux-amd64
```

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
make dist    # all four cross-compiled binaries into dist/
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
- Trusted certificates
- System certificates
- Network device CSV → API import

The API field names come from Cisco's documentation, not from a live box. When
a response does not have the expected shape, the tool reports what it actually
received instead of failing silently — please read those messages literally
when you hit one in a lab.
