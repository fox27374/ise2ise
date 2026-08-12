package main

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// TrustSec: security groups, the SGACLs the matrix cells name, and the cells
// themselves. One family, three kinds, ordered so that an object is always
// created before whatever points at it.
//
// Every cross-reference ISE stores here is a UUID - a cell's source SGT, its
// destination SGT and each of its SGACLs - so all three are rewritten to names
// on export and resolved against the target's own UUIDs on import.
const (
	kindSGT        = "sgt"
	kindSGACL      = "sgacl"
	kindEgressCell = "egressCell"

	// The ANY security group is what the default egress cell points at. It is
	// not in what /ers/config/sgt lists, but a GET by id returns it.
	sgtANY = "ANY"
)

// trustSecKinds is the order everything is read, reported and written in: an
// SGT exists before an SGACL, and both exist before the cell that names them.
var trustSecKinds = []string{kindSGT, kindSGACL, kindEgressCell}

func kindRank(kind string) int {
	if i := slices.Index(trustSecKinds, kind); i >= 0 {
		return i
	}
	return len(trustSecKinds)
}

// ExportTrustSec fills the bundle with SGTs, SGACLs and egress matrix cells.
func ExportTrustSec(c *Client, b *Bundle, families []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyTrustSec) {
		return nil
	}

	out := make([]map[string]any, 0, 128)

	log("Listing security groups…")
	sgtStubs, err := c.ersList(pathSGT)
	if err != nil {
		return fmt.Errorf("listing security groups: %w", err)
	}
	log("Found %d security groups; reading them…", len(sgtStubs))
	sgts, err := c.ersGetAll(pathSGT, rootSGT, sgtStubs)
	if err != nil {
		return fmt.Errorf("reading security groups: %w", err)
	}
	sgtName := nameResolver(c, pathSGT, rootSGT, sgts)
	for _, sgt := range sgts {
		sgt["kind"] = kindSGT
		out = append(out, portableTrustSec(sgt))
	}
	log("Captured %d security groups.", len(sgts))

	log("Listing SGACLs…")
	sgaclStubs, err := c.ersList(pathSGACL)
	if err != nil {
		return fmt.Errorf("listing SGACLs: %w", err)
	}
	log("Found %d SGACLs; reading them…", len(sgaclStubs))
	sgacls, err := c.ersGetAll(pathSGACL, rootSGACL, sgaclStubs)
	if err != nil {
		return fmt.Errorf("reading SGACLs: %w", err)
	}
	sgaclName := nameResolver(c, pathSGACL, rootSGACL, sgacls)
	for _, sgacl := range sgacls {
		sgacl["kind"] = kindSGACL
		out = append(out, portableTrustSec(sgacl))
	}
	log("Captured %d SGACLs.", len(sgacls))

	log("Listing egress matrix cells…")
	cellStubs, err := c.ersList(pathEgressCell)
	if err != nil {
		return fmt.Errorf("listing egress matrix cells: %w", err)
	}
	log("Found %d egress matrix cells; reading them…", len(cellStubs))
	cells, err := c.ersGetAll(pathEgressCell, rootEgressCell, cellStubs)
	if err != nil {
		return fmt.Errorf("reading egress matrix cells: %w", err)
	}
	for _, cell := range cells {
		cell["kind"] = kindEgressCell
		label := str(cell, "name")

		// The three UUID references become names. An id that resolves to
		// nothing is kept as it stands: the cell then blocks at pre-flight
		// naming something the operator can search for, rather than being
		// written with a reference that means nothing on the target.
		for _, f := range []struct{ id, name string }{
			{"sourceSgtId", "sourceSgtName"},
			{"destinationSgtId", "destinationSgtName"},
		} {
			id := str(cell, f.id)
			if id == "" {
				continue
			}
			resolved, ok := sgtName(id)
			if !ok {
				b.Note("Egress cell %q names a security group ISE would not return (%s); the cell is carried with the id in place of the name and will be blocked on import.", label, id)
			}
			cell[f.name] = resolved
			delete(cell, f.id)
		}

		if ids, ok := cell["sgacls"].([]any); ok {
			names := make([]string, 0, len(ids))
			for _, raw := range ids {
				id, _ := raw.(string)
				if id == "" {
					continue
				}
				resolved, ok := sgaclName(id)
				if !ok {
					b.Note("Egress cell %q names an SGACL ISE would not return (%s); the cell is carried with the id in place of the name and will be blocked on import.", label, id)
				}
				names = append(names, resolved)
			}
			delete(cell, "sgacls")
			if len(names) > 0 {
				cell["sgaclNames"] = names
			}
		}

		out = append(out, portableTrustSec(cell))
	}
	log("Captured %d egress matrix cells.", len(cells))

	sort.Slice(out, func(i, j int) bool {
		ki, kj := kindRank(str(out[i], "kind")), kindRank(str(out[j], "kind"))
		if ki != kj {
			return ki < kj
		}
		return strings.ToLower(str(out[i], "name")) < strings.ToLower(str(out[j], "name"))
	})

	if len(out) > 0 {
		b.Note("TrustSec objects are created on the target but not pushed to network devices: deploy the matrix from the target's own TrustSec pages once the import is confirmed.")
	}

	b.Objects[familyTrustSec] = out
	return nil
}

// portableTrustSec strips what belongs to the deployment the object was read
// from. generationId is ISE's own change counter and matrixId names the local
// egress matrix; neither means anything on the target.
func portableTrustSec(obj map[string]any) map[string]any {
	delete(obj, "generationId")
	delete(obj, "matrixId")
	return stripLocal(obj)
}

// nameResolver returns a lookup from UUID to name over objects already read,
// falling back to a GET by id for the ones ISE hides from its own list - the
// ANY security group being the one this tool has met. A failed lookup returns
// the id and false, so the caller can say which reference it could not follow.
func nameResolver(c *Client, path, rootKey string, known []map[string]any) func(string) (string, bool) {
	byID := map[string]string{}
	for _, obj := range known {
		byID[str(obj, "id")] = str(obj, "name")
	}
	return func(id string) (string, bool) {
		if name, ok := byID[id]; ok {
			return name, true
		}
		obj, err := c.ersGetByID(path, id, rootKey)
		if err != nil || str(obj, "name") == "" {
			byID[id] = id
			return id, false
		}
		byID[id] = str(obj, "name")
		return byID[id], true
	}
}

// preflightTrustSec resolves every TrustSec object against the target and
// reports what would happen. It runs before the policy families so that an SGT
// this run creates counts as one a policy set may name.
func preflightTrustSec(c *Client, b *Bundle, r *PreflightReport) {
	items := b.Objects[familyTrustSec]
	if len(items) == 0 {
		return
	}

	targetSGTs := map[string]map[string]any{}   // name -> object
	targetSGACLs := map[string]map[string]any{} // name -> object
	holderOfValue := map[float64]string{}       // tag value -> the name holding it

	sgtStubs, _ := c.ersList(pathSGT)
	targetSGTList, _ := c.ersGetAll(pathSGT, rootSGT, sgtStubs)
	for _, sgt := range targetSGTList {
		targetSGTs[str(sgt, "name")] = sgt
		if v, ok := sgt["value"].(float64); ok {
			holderOfValue[v] = str(sgt, "name")
		}
	}

	sgaclStubs, _ := c.ersList(pathSGACL)
	targetSGACLList, _ := c.ersGetAll(pathSGACL, rootSGACL, sgaclStubs)
	for _, sgacl := range targetSGACLList {
		targetSGACLs[str(sgacl, "name")] = sgacl
	}

	// The target's cells, keyed by the SGT pair they govern - which is what
	// identifies a cell, not the name ISE derives from it.
	targetSGTName := nameResolver(c, pathSGT, rootSGT, targetSGTList)
	targetSGACLName := nameResolver(c, pathSGACL, rootSGACL, targetSGACLList)
	targetCells := map[string]map[string]any{}
	cellStubs, _ := c.ersList(pathEgressCell)
	targetCellList, _ := c.ersGetAll(pathEgressCell, rootEgressCell, cellStubs)
	for _, cell := range targetCellList {
		src, _ := targetSGTName(str(cell, "sourceSgtId"))
		dst, _ := targetSGTName(str(cell, "destinationSgtId"))
		targetCells[cellKey(src, dst)] = cell
	}

	// What will exist once this run has finished, which is what a later object
	// in the same bundle is allowed to point at.
	willExistSGTs := map[string]bool{}
	for name := range targetSGTs {
		willExistSGTs[name] = true
	}
	willExistSGACLs := map[string]bool{}
	for name := range targetSGACLs {
		willExistSGACLs[name] = true
	}

	// Kind order, not bundle order: an SGT has to be decided before the cell
	// that names it can be told whether its reference resolves.
	for _, kind := range trustSecKinds {
		for _, item := range items {
			if str(item, "kind") != kind {
				continue
			}
			name := str(item, "name")
			it := PreflightItem{Family: familyTrustSec, Name: name, obj: maps.Clone(item)}

			switch kind {
			case kindSGT:
				// A tag value is what a switch puts on the wire. If the target
				// has given it to something else, this SGT cannot be created
				// and nothing else can be substituted for it.
				if v, ok := item["value"].(float64); ok {
					if holder, taken := holderOfValue[v]; taken && holder != name {
						it.Action = actionSkip
						it.Reason = fmt.Sprintf("value %d is already held on the target by security group %q; the tag is not changed, so this one is left out", int(v), holder)
						break
					}
				}
				if target, exists := targetSGTs[name]; exists {
					it.Action, it.Reason = actionSkip, existsReason(item, target)
					willExistSGTs[name] = true
					break
				}
				it.Action = actionCreate
				willExistSGTs[name] = true

			case kindSGACL:
				if target, exists := targetSGACLs[name]; exists {
					it.Action, it.Reason = actionSkip, existsReason(item, target)
					willExistSGACLs[name] = true
					break
				}
				it.Action = actionCreate
				willExistSGACLs[name] = true

			case kindEgressCell:
				src := str(item, "sourceSgtName")
				dst := str(item, "destinationSgtName")

				// The default cell exists on every deployment and decides what
				// happens to every pair with no cell of its own. It is reported
				// and never written.
				if src == sgtANY && dst == sgtANY {
					it.Action = actionSkip
					it.Reason = defaultCellReason(item, targetCells[cellKey(sgtANY, sgtANY)], targetSGACLName)
					break
				}

				if reason := cellBlocked(item, src, dst, willExistSGTs, willExistSGACLs); reason != "" {
					it.Action, it.Reason = actionSkip, reason
					break
				}

				// A cell holding both a catch-all default rule and an SGACL is
				// two rules in one cell, and ISE refuses it unless "Multiple
				// SGACLs per cell" is on in the target's TrustSec global
				// settings - a setting no API on 3.4 will report, so this is
				// said up front and the create is still attempted. Refused on
				// the lab, 2026-08-12, with "Only one Catch All Rule SGACL can
				// exsits [None,Permit IP,Deny IP!".
				if defaultRuleOf(item) != "NONE" && len(nameList(item, "sgaclNames")) > 0 {
					r.Notes = append(r.Notes, fmt.Sprintf("Egress cell %q carries the catch-all rule %s as well as %s. ISE refuses that unless \"Multiple SGACLs per cell\" is enabled in the target's TrustSec global settings, which no API reports; the cell is attempted and its refusal, if it comes, is reported with what ISE said.", name, defaultRuleOf(item), joinOr(nameList(item, "sgaclNames"), "no SGACL")))
				}

				if target, exists := targetCells[cellKey(src, dst)]; exists {
					it.Action = actionSkip
					it.Reason = "the target already has a cell for this pair"
					if diff := cellDrift(item, target, targetSGACLName); diff != "" {
						it.Reason += "; " + diff + " — not changed, edit it on the target if the source's version is the one you want"
					}
					break
				}
				it.Action = actionCreate
			}

			r.add(it)
		}
	}
}

func cellKey(src, dst string) string { return src + "\x00" + dst }

// cellBlocked returns why a cell cannot be written, or "" if it can. A cell is
// blocked whole: written with one SGACL missing it would permit or deny traffic
// the source never meant it to.
func cellBlocked(cell map[string]any, src, dst string, sgts, sgacls map[string]bool) string {
	if src == "" || dst == "" {
		return "the cell does not name both a source and a destination security group"
	}
	if !sgts[src] {
		return fmt.Sprintf("source security group %q does not exist on the target and this bundle does not create one", src)
	}
	if !sgts[dst] {
		return fmt.Sprintf("destination security group %q does not exist on the target and this bundle does not create one", dst)
	}
	for _, name := range nameList(cell, "sgaclNames") {
		if !sgacls[name] {
			return fmt.Sprintf("SGACL %q does not exist on the target and this bundle does not create one; the cell is left out whole rather than written with the rest", name)
		}
	}
	return ""
}

// existsReason explains a skip for an object the target already has, naming the
// fields the two copies disagree in. Nothing is written either way.
func existsReason(mine, theirs map[string]any) string {
	if fields := driftFields(withoutZeroes(mine), withoutZeroes(comparableTarget(theirs))); len(fields) > 0 {
		return fmt.Sprintf("already exists on the target and differs in %s — not changed, edit it on the target if the source's version is the one you want", strings.Join(fields, ", "))
	}
	return "already exists on the target, identical"
}

// withoutZeroes drops the properties whose value carries no information, so a
// build that answers with a field and a build that leaves it out are not read
// as two deployments disagreeing.
//
// Measured on the lab, 2026-08-12: the source returns validateAclContent:false
// on every SGACL and the target, a patch behind it, returns no such property at
// all. Nothing about the two ACLs differs. A field that is present on one side
// and set on the other is still reported - only the empty against absent case
// is silenced, and no version number is consulted to decide it.
func withoutZeroes(obj map[string]any) map[string]any {
	if obj == nil {
		return nil
	}
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		switch t := v.(type) {
		case nil:
		case bool:
			if t {
				out[k] = v
			}
		case string:
			if t != "" {
				out[k] = v
			}
		case []any:
			if len(t) > 0 {
				out[k] = v
			}
		default:
			out[k] = v
		}
	}
	return out
}

// comparableTarget strips from a target object what was already stripped from
// the bundle's copy, so the two are compared on their content alone.
func comparableTarget(obj map[string]any) map[string]any {
	if obj == nil {
		return nil
	}
	return portableTrustSec(maps.Clone(obj))
}

// defaultCellReason reports how the source's default egress rule differs from
// the target's. The ANY-ANY cell is the TrustSec catch-all, so it is described
// and left alone rather than overwritten by an import.
func defaultCellReason(mine, theirs map[string]any, sgaclName func(string) (string, bool)) string {
	source := fmt.Sprintf("%s with %s", defaultRuleOf(mine), joinOr(nameList(mine, "sgaclNames"), "no SGACL"))
	if theirs == nil {
		return fmt.Sprintf("the default egress cell is never written; the source's is %s and the target's could not be read", source)
	}

	var theirSGACLs []string
	if ids, ok := theirs["sgacls"].([]any); ok {
		for _, raw := range ids {
			if id, _ := raw.(string); id != "" {
				name, _ := sgaclName(id)
				theirSGACLs = append(theirSGACLs, name)
			}
		}
	}
	target := fmt.Sprintf("%s with %s", defaultRuleOf(theirs), joinOr(theirSGACLs, "no SGACL"))

	if source == target {
		return fmt.Sprintf("the default egress cell is never written; both sides are %s", source)
	}
	return fmt.Sprintf("the default egress cell is never written: the source's is %s, the target's is %s — change it on the target's TrustSec matrix if the source's is the one you want", source, target)
}

func defaultRuleOf(cell map[string]any) string {
	if rule := str(cell, "defaultRule"); rule != "" {
		return rule
	}
	return "NONE"
}

// cellDrift describes how an existing cell differs from the bundle's, or "".
func cellDrift(mine, theirs map[string]any, sgaclName func(string) (string, bool)) string {
	var diffs []string
	if defaultRuleOf(mine) != defaultRuleOf(theirs) {
		diffs = append(diffs, fmt.Sprintf("the source's default rule is %s, the target's is %s", defaultRuleOf(mine), defaultRuleOf(theirs)))
	}
	if a, b := str(mine, "matrixCellStatus"), str(theirs, "matrixCellStatus"); a != b && a != "" {
		diffs = append(diffs, fmt.Sprintf("the source's status is %s, the target's is %s", a, b))
	}
	var theirNames []string
	if ids, ok := theirs["sgacls"].([]any); ok {
		for _, raw := range ids {
			if id, _ := raw.(string); id != "" {
				name, _ := sgaclName(id)
				theirNames = append(theirNames, name)
			}
		}
	}
	mineNames := nameList(mine, "sgaclNames")
	if !slices.Equal(mineNames, theirNames) {
		diffs = append(diffs, fmt.Sprintf("the source's SGACLs are %s, the target's are %s", joinOr(mineNames, "none"), joinOr(theirNames, "none")))
	}
	return strings.Join(diffs, ", ")
}

// applyTrustSec creates the objects pre-flight cleared, in kind order.
func applyTrustSec(c *Client, r *PreflightReport, res *ImportResult, log func(string, ...any)) error {
	created := 0
	for _, it := range r.Items {
		if it.Family == familyTrustSec && it.Action == actionCreate {
			created++
		}
	}
	if created > 0 {
		log("Creating %d TrustSec objects…", created)
	}

	// A cell needs the target's UUIDs for the SGTs and SGACLs this run has just
	// created, and ISE hands none of them back on a create. The collections are
	// re-read once, when the first cell is reached and everything it can name
	// already exists.
	var sgtIDs, sgaclIDs map[string]string
	readIDs := func() error {
		if sgtIDs != nil {
			return nil
		}
		var err error
		if sgtIDs, err = stubsByName(c, pathSGT); err != nil {
			return fmt.Errorf("reading the target's security groups: %w", err)
		}
		if sgaclIDs, err = stubsByName(c, pathSGACL); err != nil {
			return fmt.Errorf("reading the target's SGACLs: %w", err)
		}
		return nil
	}

	for _, it := range r.Items {
		if it.Family != familyTrustSec {
			continue
		}
		if it.Action == actionSkip {
			res.Skipped++
			continue
		}
		if it.Action != actionCreate {
			res.Blocked++
			continue
		}
		kind := str(it.obj, "kind")
		obj := maps.Clone(it.obj)
		delete(obj, "kind")

		var path, root string
		switch kind {
		case kindSGT:
			path, root = pathSGT, rootSGT
		case kindSGACL:
			path, root = pathSGACL, rootSGACL
		case kindEgressCell:
			path, root = pathEgressCell, rootEgressCell
			if err := readIDs(); err != nil {
				return err
			}
			if reason := resolveCellRefs(obj, sgtIDs, sgaclIDs); reason != "" {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("egress cell %q: %s", it.Name, reason))
				log("FAILED egress cell %q: %s", it.Name, reason)
				continue
			}
		default:
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("TrustSec object %q: unknown kind %q", it.Name, kind))
			continue
		}

		if err := c.ersCreate(path, root, obj); err != nil {
			if isDuplicate(err) {
				res.Skipped++
				log("%s %q already exists; skipped.", kind, it.Name)
				continue
			}
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s %q: %v", kind, it.Name, err))
			log("FAILED %s %q: %v", kind, it.Name, err)
			continue
		}
		res.Created++
		log("Created %s %q.", kind, it.Name)
	}
	return nil
}

// resolveCellRefs turns the cell's carried names back into the target's own
// UUIDs. Any name that does not resolve fails the whole cell: a cell posted
// without one of its SGACLs is a rule that permits or denies the wrong traffic.
func resolveCellRefs(cell map[string]any, sgtIDs, sgaclIDs map[string]string) string {
	src := str(cell, "sourceSgtName")
	dst := str(cell, "destinationSgtName")
	delete(cell, "sourceSgtName")
	delete(cell, "destinationSgtName")

	srcID, ok := sgtIDs[src]
	if !ok {
		return fmt.Sprintf("the target has no security group %q", src)
	}
	dstID, ok := sgtIDs[dst]
	if !ok {
		return fmt.Sprintf("the target has no security group %q", dst)
	}
	cell["sourceSgtId"] = srcID
	cell["destinationSgtId"] = dstID

	names := nameList(cell, "sgaclNames")
	delete(cell, "sgaclNames")
	ids := make([]any, 0, len(names))
	for _, name := range names {
		id, ok := sgaclIDs[name]
		if !ok {
			return fmt.Sprintf("the target has no SGACL %q", name)
		}
		ids = append(ids, id)
	}
	if len(ids) > 0 {
		cell["sgacls"] = ids
	}
	return ""
}

// sgtNamesAfterThisRun names every security group the target will have once
// this run is done: its own, plus the ones pre-flight cleared for creation.
// Policy sets name security groups, and a rule may name one this bundle brings.
func sgtNamesAfterThisRun(c *Client, r *PreflightReport) map[string]bool {
	names := map[string]bool{}
	stubs, _ := c.ersList(pathSGT)
	for _, s := range stubs {
		names[s.Name] = true
	}
	for _, it := range r.Items {
		if it.Family == familyTrustSec && it.Action == actionCreate && str(it.obj, "kind") == kindSGT {
			names[it.Name] = true
		}
	}
	return names
}

// nameList reads a list of names that survived a JSON round trip as []any or
// arrived straight from the exporter as []string.
func nameList(obj map[string]any, key string) []string {
	switch v := obj[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, raw := range v {
			if s, _ := raw.(string); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func joinOr(names []string, empty string) string {
	if len(names) == 0 {
		return empty
	}
	return strings.Join(quoteAll(names), ", ")
}
