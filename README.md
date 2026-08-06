# ise2ise

Migrates Cisco ISE configuration between two independent deployments.

Today it does exactly one thing: it translates a **network device CSV export**
from a source ISE into the column layout of a target ISE, so the export actually
imports on the other side.

## Why this exists

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

## Workflow

1. Source ISE: `Administration → Network Resources → Network Devices → Export`.
2. Target ISE: `Administration → Network Resources → Network Devices → Import`,
   click **Generate a Template**, download it.
3. Run `ise2ise`; the browser opens on `http://127.0.0.1:8777/`.
4. Upload both files, optionally enter the target node's hostname, translate.
5. Review the report — especially the data-loss and refused-row warnings.
6. Download `network-devices-translated.csv` and import it on the target ISE.

Handle both CSVs as credential material and delete them when you are done.
`.gitignore` excludes `*.csv` for that reason.

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

The server binds `127.0.0.1` only — there is deliberately no way to bind a
routable interface. The UI is unauthenticated and handles credential-bearing
files. Uploads and results are never written to disk; the browser downloads the
translated CSV from an in-memory blob.

## Building

```
make build   # ./ise2ise for the host platform
make test    # gofmt -l . && go vet ./... && go test ./...
make dist    # all four cross-compiled binaries into dist/
```

## Not yet implemented

Everything below is a later slice. None of it exists in the binary today, not
even as a stub:

- API export/import of endpoints (static assignments in selected groups)
- Endpoint identity groups
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
- Encrypted transfer bundle
- Network device CSV → API import
