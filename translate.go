package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// Cisco ISE network device export headers look like "<Label>:<Type>(<constraints>)",
// and the label itself may contain colons:
//
//	Name:String(32):Required
//	Authentication:Shared Secret:String(128)
//	SNMP:Polling Interval:Integer:600-86400 seconds
//
// The column set and the header text both change between ISE releases, so the
// translation keys off the label only and takes the target's own exported
// template as the authoritative schema. Nothing here is version-specific.

// typeTokens start the segment that ends the label. "Protocol" is deliberately
// absent: "Authentication:Protocol:String(6)" has Protocol inside the label.
var typeTokens = []string{"String", "Boolean", "Integer", "Enumeration", "Subnets", "Date"}

// columnLabel strips the trailing type annotation from an ISE CSV header.
func columnLabel(header string) string {
	parts := strings.Split(strings.TrimPrefix(header, "\ufeff"), ":")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		for _, t := range typeTokens {
			if strings.HasPrefix(p, t) {
				return strings.Join(parts[:i], ":")
			}
		}
	}
	return header
}

// labelKey normalises a label for matching across releases: case and internal
// whitespace vary, the meaning does not.
func labelKey(label string) string {
	return strings.Join(strings.Fields(strings.ToLower(label)), " ")
}

// aliases maps a source label key to the target label key it became in a later
// release. Empty until a real rename is observed in an actual export pair --
// guessing renames is how a parser silently writes data into the wrong column.
var aliases = map[string]string{}

// readOnlyLabels are populated by ISE at runtime and rejected or ignored on
// import. PAC state is re-provisioned when a device authenticates.
var readOnlyLabels = map[string]bool{
	"sga:pac issue date":      true,
	"sga:pac expiration date": true,
	"sga:pac issued by":       true,
}

// nodeLabels hold a source-deployment node hostname. The target is always a
// standalone, so every source node name collapses onto its single node.
var nodeLabels = map[string]bool{
	"snmp:originating policy services node": true,
	"sga:coa coa source host":               true,
}

// secretLabel reports whether a column carries a credential. Used to refuse
// masked values rather than import "******" as a literal secret.
func secretLabel(key string) bool {
	if key == "passwordencrypted" { // a boolean flag, not a credential
		return false
	}
	for _, s := range []string{"secret", "password", "community", "encryptionkey", "authenticationkey"} {
		if strings.Contains(key, s) {
			return true
		}
	}
	return false
}

func isMasked(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && strings.Trim(v, "*") == ""
}

type Report struct {
	SourceRows   int      `json:"sourceRows"`
	WrittenRows  int      `json:"writtenRows"`
	Mapped       []string `json:"mapped"`       // target column <- source column
	DroppedRO    []string `json:"droppedRO"`    // read-only, intentionally not carried
	UnmappedSrc  []string `json:"unmappedSrc"`  // in source, no home in target: DATA LOSS
	EmptyTarget  []string `json:"emptyTarget"`  // in target, absent from source: left blank
	NodeRewrites []string `json:"nodeRewrites"` // columns rewritten to the target node
	Refused      []string `json:"refused"`      // rows not written, with reason
}

func parseCSV(b []byte) ([][]string, error) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1 // ISE emits ragged rows when trailing columns are empty
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	return rows, nil
}

// Translate rewrites a network device export from one ISE release into the
// column layout of another, using the target's own template as the schema.
// targetNode, when set, replaces every source node hostname.
func Translate(sourceCSV, templateCSV []byte, targetNode string) ([]byte, *Report, error) {
	src, err := parseCSV(sourceCSV)
	if err != nil {
		return nil, nil, fmt.Errorf("source CSV: %w", err)
	}
	tmpl, err := parseCSV(templateCSV)
	if err != nil {
		return nil, nil, fmt.Errorf("target template CSV: %w", err)
	}

	srcHeader, tgtHeader := src[0], tmpl[0]
	srcHeader[0] = strings.TrimPrefix(srcHeader[0], "\ufeff")
	tgtHeader[0] = strings.TrimPrefix(tgtHeader[0], "\ufeff")

	rep := &Report{}

	// source label key -> column index
	srcIdx := map[string]int{}
	for i, h := range srcHeader {
		srcIdx[labelKey(columnLabel(h))] = i
	}

	// target column -> source column index, or -1
	pick := make([]int, len(tgtHeader))
	used := map[int]bool{}
	for i, h := range tgtHeader {
		label := columnLabel(h)
		key := labelKey(label)
		pick[i] = -1
		if readOnlyLabels[key] {
			rep.DroppedRO = append(rep.DroppedRO, label)
			continue
		}
		j, ok := srcIdx[key]
		if !ok {
			if a, has := aliases[key]; has {
				j, ok = srcIdx[a]
			}
		}
		if !ok {
			rep.EmptyTarget = append(rep.EmptyTarget, label)
			continue
		}
		pick[i] = j
		used[j] = true
		rep.Mapped = append(rep.Mapped, label)
		if nodeLabels[key] && targetNode != "" {
			rep.NodeRewrites = append(rep.NodeRewrites, label)
		}
	}

	// Source columns with nowhere to go are silent data loss unless reported.
	for i, h := range srcHeader {
		label := columnLabel(h)
		if used[i] || readOnlyLabels[labelKey(label)] {
			continue
		}
		rep.UnmappedSrc = append(rep.UnmappedSrc, label)
	}

	nameCol, ok := srcIdx[labelKey("Name")]
	if !ok {
		return nil, nil, fmt.Errorf("source CSV has no Name column; is this an ISE network device export?")
	}

	out := &bytes.Buffer{}
	w := csv.NewWriter(out)
	if err := w.Write(tgtHeader); err != nil {
		return nil, nil, err
	}

	for _, row := range src[1:] {
		if !hasContent(row) {
			continue
		}
		rep.SourceRows++
		name := at(row, nameCol)
		if strings.TrimSpace(name) == "" {
			rep.Refused = append(rep.Refused, "(row with no Name): skipped")
			continue
		}

		rec := make([]string, len(tgtHeader))
		masked := ""
		for i, j := range pick {
			if j < 0 {
				continue
			}
			v := at(row, j)
			key := labelKey(columnLabel(srcHeader[j]))
			if secretLabel(key) && isMasked(v) {
				masked = columnLabel(srcHeader[j])
				break
			}
			if nodeLabels[key] && targetNode != "" && strings.TrimSpace(v) != "" {
				v = targetNode
			}
			rec[i] = v
		}
		if masked != "" {
			rep.Refused = append(rep.Refused, fmt.Sprintf("%s: %q is masked in the source export, not a usable secret", name, masked))
			continue
		}
		if err := w.Write(rec); err != nil {
			return nil, nil, err
		}
		rep.WrittenRows++
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, nil, err
	}
	return out.Bytes(), rep, nil
}

func at(row []string, i int) string {
	if i >= 0 && i < len(row) {
		return row[i]
	}
	return ""
}

func hasContent(row []string) bool {
	for _, v := range row {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
