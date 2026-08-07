# ise2ise

Migrates Cisco ISE configuration between two independent deployments. Go, local
web UI, one static binary per OS.

**Read `DECISIONS.md` before changing anything.** It records why the tool is
shaped the way it is, what was deliberately rejected, what is still unverified
against real hardware, and the roadmap in dependency order. `README.md` is the
operator-facing guide.

## Hard constraints

- **Stdlib only.** `go.mod` has no requirements and stays that way. AES-GCM,
  PBKDF2, CSV, HTTP and `embed` are all standard library in Go 1.24.
- **Binds `127.0.0.1` only.** No flag may reach a routable interface. The UI is
  unauthenticated and holds ISE admin credentials in memory.
- **Credentials never persist** — not to disk, not into the bundle, not to a log,
  not into a server-side session.
- **The transfer bundle is always encrypted.** No plaintext mode.
- **Import is create-only** and writes nothing until the operator confirms a
  pre-flight report. Unresolvable references are skipped, never attempted.
- **Never branch on an ISE version number.** Probe capability, skip what is
  absent, report it.
- **Cross-references travel by name, never by UUID.** Resolve to a name on
  export, resolve against the target's own UUIDs on import.
- **No third-party test framework.** Plain `go test`, `httptest` for the fake
  ISE.

## Conventions

Report what ISE actually returned when a response does not match the expected
shape — no panics, no silent empties. The operator's lab is the only place these
shapes get proven, so the error text is the product.

Never commit `*.csv`. Real ISE network device exports contain plaintext RADIUS,
TACACS, SNMP, TrustSec and enable credentials.

## Verify before claiming done

```
gofmt -l .        # silent
go vet ./...      # clean
go test ./...     # passes, including earlier slices
go list -m all    # no third-party modules
make dist         # all four binaries
```

Editor and LSP diagnostics are not authoritative here — they have produced false
compile errors on this repo more than once. The toolchain is the truth.
