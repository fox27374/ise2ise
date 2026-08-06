package main

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// Header shapes below are the real ones from a 3.x network device export.
// Values are synthetic on purpose: a real export is a plaintext credential dump.

func TestColumnLabel(t *testing.T) {
	cases := map[string]string{
		"Name:String(32):Required":                                   "Name",
		"Description:String(256)":                                    "Description",
		"IP Address:Subnets(a.b.c.d/m#....):Required":                "IP Address",
		"Network Device Groups:String(100)(Type#Root Name#Name|...)": "Network Device Groups",
		// Protocol is part of the label, not the type.
		"Authentication:Protocol:String(6)":                "Authentication:Protocol",
		"Authentication:Shared Secret:String(128)":         "Authentication:Shared Secret",
		"PasswordEncrypted:Boolean(true|false)":            "PasswordEncrypted",
		"SNMP:Version:Enumeration(1|2c|3)":                 "SNMP:Version",
		"SNMP:RO Community:String(32)":                     "SNMP:RO Community",
		"SNMP:Polling Interval:Integer:600-86400 seconds":  "SNMP:Polling Interval",
		"SNMP:Originating Policy Services Node:String(32)": "SNMP:Originating Policy Services Node",
		"SGA:Device Password:String(256)":                  "SGA:Device Password",
		"SGA:PAC issue date:Date":                          "SGA:PAC issue date",
		"SGA:PAC issued by:String":                         "SGA:PAC issued by",
		"SGA:CoA Coa Source Host:String":                   "SGA:CoA Coa Source Host",
		"Deployment:Enable Mode Password:String(32)":       "Deployment:Enable Mode Password",
		"TACACS:Shared Secret:String(128)":                 "TACACS:Shared Secret",
		"TacacsSANValues:String(JSON String)":              "TacacsSANValues",
		// Note the space between the type and its constraint list.
		"TACACS TLS:Connect Mode Options:String (OFF|ON_DRAFT_COMPLIANT)": "TACACS TLS:Connect Mode Options",
		"coaPort:Integer(128)": "coaPort",
		// BOM on the very first header must not stick to the label.
		"\ufeffName:String(32):Required": "Name",
	}
	for header, want := range cases {
		if got := columnLabel(header); got != want {
			t.Errorf("columnLabel(%q) = %q, want %q", header, got, want)
		}
	}
}

// --- shared fixtures ---------------------------------------------------------

const (
	hName    = "Name:String(32):Required"
	hDesc    = "Description:String(256)"
	hIP      = "IP Address:Subnets(a.b.c.d/m#....):Required"
	hNDG     = "Network Device Groups:String(100)(Type#Root Name#Name|...)"
	hProto   = "Authentication:Protocol:String(6)"
	hSecret  = "Authentication:Shared Secret:String(128)"
	hPwdEnc  = "PasswordEncrypted:Boolean(true|false)"
	hSNMPVer = "SNMP:Version:Enumeration(1|2c|3)"
	hSNMPRO  = "SNMP:RO Community:String(32)"
	hSNMPNod = "SNMP:Originating Policy Services Node:String(32)"
	hSGAPwd  = "SGA:Device Password:String(256)"
	hPACDate = "SGA:PAC issue date:Date"
	hPACBy   = "SGA:PAC issued by:String"
	hCoAHost = "SGA:CoA Coa Source Host:String"
	hEnable  = "Deployment:Enable Mode Password:String(32)"
	hCoAPort = "coaPort:Integer(128)"
)

func csvBytes(rows ...[]string) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.WriteAll(rows); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// translate runs Translate and returns the parsed output rows plus the report.
func translate(t *testing.T, src, tmpl []byte, node string) ([][]string, *Report) {
	t.Helper()
	out, rep, err := Translate(src, tmpl, node)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, out)
	}
	return rows, rep
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want || strings.HasPrefix(v, want) {
			return true
		}
	}
	return false
}

func col(t *testing.T, rows [][]string, label string) int {
	t.Helper()
	for i, h := range rows[0] {
		if columnLabel(h) == label {
			return i
		}
	}
	t.Fatalf("output has no column %q (header: %v)", label, rows[0])
	return -1
}

// --- tests -------------------------------------------------------------------

// The target template reorders columns, adds one the source never had, and
// omits one the source did have. The omission is the data-loss signal.
func TestTranslateReordersAndReportsGaps(t *testing.T) {
	src := csvBytes(
		[]string{hName, hIP, hSecret, hCoAPort},
		[]string{"sw1", "172.24.88.161/32", "s3cr3t", "1700"},
	)
	// Different order, "Description" is new in the target, "coaPort" is gone.
	tmpl := csvBytes([]string{hIP, hDesc, hSecret, hName})

	rows, rep := translate(t, src, tmpl, "")
	if len(rows) != 2 {
		t.Fatalf("want header + 1 row, got %d rows", len(rows))
	}
	want := []string{"172.24.88.161/32", "", "s3cr3t", "sw1"}
	for i, w := range want {
		if rows[1][i] != w {
			t.Errorf("column %d (%s) = %q, want %q", i, rows[0][i], rows[1][i], w)
		}
	}
	if !has(rep.EmptyTarget, "Description") {
		t.Errorf("EmptyTarget = %v, want Description", rep.EmptyTarget)
	}
	if !has(rep.UnmappedSrc, "coaPort") {
		t.Errorf("UnmappedSrc = %v, want coaPort (data loss must be reported)", rep.UnmappedSrc)
	}
	if !has(rep.Mapped, "IP Address") || !has(rep.Mapped, "Name") {
		t.Errorf("Mapped = %v, want IP Address and Name", rep.Mapped)
	}
	if rep.SourceRows != 1 || rep.WrittenRows != 1 {
		t.Errorf("SourceRows=%d WrittenRows=%d, want 1/1", rep.SourceRows, rep.WrittenRows)
	}
}

// PAC state is re-provisioned by ISE; carrying it over is meaningless, so those
// columns must be reported dropped and written blank.
func TestPACColumnsDropped(t *testing.T) {
	src := csvBytes(
		[]string{hName, hPACDate, hPACBy},
		[]string{"sw1", "2024-01-02", "ise-old.lab.loc"},
	)
	tmpl := csvBytes([]string{hName, hPACDate, hPACBy})

	rows, rep := translate(t, src, tmpl, "")
	if !has(rep.DroppedRO, "SGA:PAC issue date") || !has(rep.DroppedRO, "SGA:PAC issued by") {
		t.Errorf("DroppedRO = %v, want both PAC columns", rep.DroppedRO)
	}
	if rows[1][1] != "" || rows[1][2] != "" {
		t.Errorf("PAC values were written: %q", rows[1])
	}
	// Dropped read-only columns are not data loss, so they must not be flagged.
	if len(rep.UnmappedSrc) != 0 {
		t.Errorf("UnmappedSrc = %v, want empty", rep.UnmappedSrc)
	}
}

func TestTargetNodeRewrite(t *testing.T) {
	src := csvBytes(
		[]string{hName, hSNMPNod, hCoAHost, hDesc},
		[]string{"sw1", "ibk-sda-ise1.ntslab.loc", "ibk-sda-ise1.ntslab.loc", "core"},
		[]string{"sw2", "", "", "edge"}, // empty cells must stay empty
	)
	tmpl := csvBytes([]string{hName, hSNMPNod, hCoAHost, hDesc})

	rows, rep := translate(t, src, tmpl, "new-ise.example.net")
	if rows[1][1] != "new-ise.example.net" || rows[1][2] != "new-ise.example.net" {
		t.Errorf("node columns not rewritten: %q", rows[1])
	}
	if rows[1][3] != "core" {
		t.Errorf("non-node column was rewritten: %q", rows[1])
	}
	if rows[2][1] != "" || rows[2][2] != "" {
		t.Errorf("empty node cells were filled in: %q", rows[2])
	}
	if !has(rep.NodeRewrites, "SNMP:Originating Policy Services Node") || !has(rep.NodeRewrites, "SGA:CoA Coa Source Host") {
		t.Errorf("NodeRewrites = %v, want both node columns", rep.NodeRewrites)
	}

	// Without a target node nothing is touched.
	rows, rep = translate(t, src, tmpl, "")
	if rows[1][1] != "ibk-sda-ise1.ntslab.loc" {
		t.Errorf("node rewritten without a target node: %q", rows[1])
	}
	if len(rep.NodeRewrites) != 0 {
		t.Errorf("NodeRewrites = %v, want empty", rep.NodeRewrites)
	}
}

// A masked secret would import as the literal string "******" and break RADIUS
// for that device, so the row must be refused loudly instead.
func TestMaskedSecretRefused(t *testing.T) {
	src := csvBytes(
		[]string{hName, hSecret, hPwdEnc, hSNMPRO, hSGAPwd, hEnable},
		[]string{"sw1", "s3cr3t", "true", "public", "sga-pw", "enable-pw"},
		[]string{"sw2", "******", "true", "public", "sga-pw", "enable-pw"},
	)
	tmpl := csvBytes([]string{hName, hSecret, hPwdEnc, hSNMPRO, hSGAPwd, hEnable})

	rows, rep := translate(t, src, tmpl, "")
	if len(rows) != 2 {
		t.Fatalf("want header + 1 written row, got %d rows: %v", len(rows), rows)
	}
	if rows[1][0] != "sw1" {
		t.Errorf("wrong row survived: %q", rows[1])
	}
	if rep.SourceRows != 2 || rep.WrittenRows != 1 {
		t.Errorf("SourceRows=%d WrittenRows=%d, want 2/1", rep.SourceRows, rep.WrittenRows)
	}
	if !has(rep.Refused, "sw2") {
		t.Errorf("Refused = %v, want sw2 named", rep.Refused)
	}
	if len(rep.Refused) != 1 {
		t.Errorf("Refused = %v, want exactly one entry", rep.Refused)
	}
	// PasswordEncrypted is a boolean flag, not a credential.
	if rows[1][2] != "true" {
		t.Errorf("PasswordEncrypted = %q, want true", rows[1][2])
	}
}

func TestBOMAndRaggedRows(t *testing.T) {
	src := append([]byte("\ufeff"), csvBytes(
		[]string{hName, hIP, hNDG, hDesc},
		[]string{"sw1", "172.24.88.161/32"}, // ragged: trailing columns omitted
		[]string{"sw2", "10.0.0.1/32", "Location#All Locations|Device Type#All Device Types", "edge"},
	)...)
	tmpl := append([]byte("\ufeff"), csvBytes([]string{hName, hDesc, hNDG, hIP})...)

	rows, rep := translate(t, src, tmpl, "")
	if rep.SourceRows != 2 || rep.WrittenRows != 2 {
		t.Fatalf("SourceRows=%d WrittenRows=%d, want 2/2 (report: %+v)", rep.SourceRows, rep.WrittenRows, rep)
	}
	if len(rep.UnmappedSrc) != 0 || len(rep.EmptyTarget) != 0 {
		t.Errorf("BOM leaked into a label: UnmappedSrc=%v EmptyTarget=%v", rep.UnmappedSrc, rep.EmptyTarget)
	}
	name := col(t, rows, "Name")
	if rows[1][name] != "sw1" {
		t.Errorf("BOM stuck to the first value: %q", rows[1][name])
	}
	ndg := col(t, rows, "Network Device Groups")
	if rows[1][ndg] != "" {
		t.Errorf("ragged row invented a value: %q", rows[1][ndg])
	}
	if rows[2][ndg] != "Location#All Locations|Device Type#All Device Types" {
		t.Errorf("device groups mangled: %q", rows[2][ndg])
	}
}

// Same release on both sides: everything round-trips except the read-only columns.
func TestRoundTripIdenticalSchema(t *testing.T) {
	header := []string{hName, hDesc, hIP, hNDG, hProto, hSecret, hPwdEnc, hSNMPVer, hSNMPRO, hSNMPNod, hSGAPwd, hPACDate, hPACBy, hCoAHost, hEnable, hCoAPort}
	row1 := []string{"sw1", "core switch", "172.24.88.161/32", "Location#All Locations|Device Type#All Device Types|IPSEC#Is IPSEC Device", "RADIUS", "s3cr3t", "false", "2c", "public", "ise1.lab.loc", "sga-pw", "2024-01-02", "ise1.lab.loc", "ise1.lab.loc", "enable-pw", "1700"}
	row2 := []string{"sw2", "", "10.0.0.1/32", "Location#All Locations", "TACACS_PLUS", "an0ther", "false", "3", "", "", "", "", "", "", "", ""}
	schema := csvBytes(header)
	src := csvBytes(header, row1, row2)

	rows, rep := translate(t, src, schema, "")
	if len(rep.UnmappedSrc) != 0 || len(rep.EmptyTarget) != 0 {
		t.Errorf("identical schemas should map cleanly: UnmappedSrc=%v EmptyTarget=%v", rep.UnmappedSrc, rep.EmptyTarget)
	}
	if len(rows) != 3 {
		t.Fatalf("want header + 2 rows, got %d", len(rows))
	}
	ro := map[int]bool{}
	for i, h := range header {
		if readOnlyLabels[labelKey(columnLabel(h))] {
			ro[i] = true
		}
	}
	if len(ro) != 2 {
		t.Fatalf("fixture should contain 2 read-only columns, found %d", len(ro))
	}
	for r, want := range [][]string{row1, row2} {
		for i := range header {
			got := rows[r+1][i]
			if ro[i] {
				if got != "" {
					t.Errorf("row %d column %q: read-only value carried over: %q", r+1, header[i], got)
				}
				continue
			}
			if got != want[i] {
				t.Errorf("row %d column %q = %q, want %q", r+1, header[i], got, want[i])
			}
		}
	}
}
