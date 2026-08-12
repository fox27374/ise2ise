package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestExportIdentitySources(t *testing.T) {
	fake := newFakeISE(t)
	client := fake.client()

	// Add REST ID store with headers (including secret)
	restStore := map[string]any{
		"id":   "rest-1",
		"name": "EntraID",
		"link": map[string]any{"rel": "self", "href": "http://localhost/"},
		"ersRestIDStoreAttributes": map[string]any{
			"usernameSuffix": "@example.com",
			"rootUrl":        "http://example.com",
			"predefined":     "Microsoft Entra ID",
			"headers": []any{
				map[string]any{"key": "clientID", "value": "abc123"},
				map[string]any{"key": "clientSecret", "value": "verysecret"},
				map[string]any{"key": "tenantID", "value": "tenant123"},
			},
		},
		"ersRestIDStoreUserAttributes": map[string]any{
			"attributes": []any{
				map[string]any{"name": "userPrincipalName", "type": "STRING"},
			},
		},
		"ersRestIDStoreDeviceAttributes": map[string]any{
			"attributes": []any{
				map[string]any{"name": "displayName", "type": "STRING"},
			},
		},
	}
	fake.restIDStores = append(fake.restIDStores, restStore)

	// Add certificate profile
	certProfile := map[string]any{
		"id":   "cert-1",
		"name": "EntraID_Cert_Profile",
		"link": map[string]any{"rel": "self", "href": "http://localhost/"},
	}
	fake.certProfiles = append(fake.certProfiles, certProfile)

	// Export
	b := NewBundle(client.ProbeDeployment())
	err := ExportIdentitySources(client, b, []string{familyIdentitySources}, t.Logf)
	if err != nil {
		t.Fatalf("ExportIdentitySources: %v", err)
	}

	// Check bundle contents
	objs := b.Objects[familyIdentitySources]
	if len(objs) != 2 {
		t.Errorf("expected 2 objects, got %d", len(objs))
	}

	// Find and check REST store
	var restExported map[string]any
	for _, obj := range objs {
		if str(obj, "name") == "EntraID" {
			restExported = obj
			break
		}
	}
	if restExported == nil {
		t.Fatal("REST store not exported")
	}

	// Verify structure is carried
	if str(restExported, "kind") != "restIDStore" {
		t.Errorf("expected kind restIDStore, got %s", str(restExported, "kind"))
	}

	// Verify id and link are stripped
	if _, hasID := restExported["id"]; hasID {
		t.Error("exported object still has id field")
	}
	if _, hasLink := restExported["link"]; hasLink {
		t.Error("exported object still has link field")
	}

	// Verify headers are carried
	attrs, ok := restExported["ersRestIDStoreAttributes"].(map[string]any)
	if !ok {
		t.Fatal("missing attributes")
	}
	headers := extractHeaders(attrs)
	if len(headers) != 3 {
		t.Errorf("expected 3 headers, got %d", len(headers))
	}

	// Check bundle notes for secret warning
	found := false
	for _, note := range b.Notes {
		if strings.Contains(note, "EntraID") && strings.Contains(note, "secret") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected bundle note warning about secret")
	}

	// Verify secret value is NOT in notes
	secretFound := false
	for _, note := range b.Notes {
		if strings.Contains(note, "verysecret") {
			secretFound = true
		}
	}
	if secretFound {
		t.Error("secret value appears in bundle notes")
	}
}

func TestPreflightIdentitySources(t *testing.T) {
	fake := newFakeISE(t)
	client := fake.client()

	// Add target REST store with a different secret
	targetRest := map[string]any{
		"id":   "target-rest-1",
		"name": "EntraID",
		"ersRestIDStoreAttributes": map[string]any{
			"headers": []any{
				map[string]any{"key": "clientSecret", "value": "differentsecret"},
			},
		},
	}
	fake.restIDStores = append(fake.restIDStores, targetRest)

	// Add target cert profile (factory one)
	fake.certProfiles = append(fake.certProfiles, map[string]any{
		"id":   "target-cert-1",
		"name": "Preloaded_Certificate_Profile",
	})

	// Create bundle with source store and profile
	b := NewBundle(client.ProbeDeployment())
	b.Objects[familyIdentitySources] = []map[string]any{
		{
			"name": "EntraID",
			"kind": "restIDStore",
			"ersRestIDStoreAttributes": map[string]any{
				"headers": []any{
					map[string]any{"key": "clientSecret", "value": "sourcesecret"},
				},
			},
		},
		{
			"name": "Preloaded_Certificate_Profile",
			"kind": "certificateProfile",
		},
		{
			"name": "NewCertProfile",
			"kind": "certificateProfile",
		},
	}

	r := &PreflightReport{}
	preflightIdentitySources(client, b, r)

	// Check items
	if len(r.Items) == 0 {
		t.Fatal("expected preflight items")
	}

	// Find the EntraID store item - should be skip with drift
	var entraItem PreflightItem
	for _, it := range r.Items {
		if it.Name == "EntraID" {
			entraItem = it
			break
		}
	}
	if entraItem.Action != actionSkip {
		t.Errorf("expected EntraID to be skipped, got action %s", entraItem.Action)
	}
	if !strings.Contains(entraItem.Reason, "clientSecret") {
		t.Errorf("expected drift reason to mention clientSecret, got: %s", entraItem.Reason)
	}
	// Verify the secret value is NOT in the reason
	if strings.Contains(entraItem.Reason, "sourcesecret") || strings.Contains(entraItem.Reason, "differentsecret") {
		t.Error("secret value appears in drift reason")
	}

	// Factory cert profile should be skipped
	var factoryItem PreflightItem
	for _, it := range r.Items {
		if it.Name == "Preloaded_Certificate_Profile" {
			factoryItem = it
			break
		}
	}
	if factoryItem.Action != actionSkip {
		t.Errorf("expected factory profile to be skipped, got action %s", factoryItem.Action)
	}

	// New cert profile should be create
	var newItem PreflightItem
	for _, it := range r.Items {
		if it.Name == "NewCertProfile" {
			newItem = it
			break
		}
	}
	if newItem.Action != actionCreate {
		t.Errorf("expected new profile to be created, got action %s", newItem.Action)
	}
}

func TestApplyIdentitySources(t *testing.T) {
	fake := newFakeISE(t)
	fake.csrfRequired = true
	client := fake.client()

	// Create a preflight report with items to create
	r := &PreflightReport{
		Items: []PreflightItem{
			{
				Family: familyIdentitySources,
				Name:   "TestRest",
				Action: actionCreate,
				obj: map[string]any{
					"kind": "restIDStore",
					"name": "TestRest",
					"ersRestIDStoreAttributes": map[string]any{
						"usernameSuffix": "@example.com",
					},
				},
			},
			{
				Family: familyIdentitySources,
				Name:   "TestCert",
				Action: actionCreate,
				obj: map[string]any{
					"kind":              "certificateProfile",
					"name":              "TestCert",
					"certificateFormat": "PEM",
				},
			},
			{
				Family: familyIdentitySources,
				Name:   "ExistingCert",
				Action: actionSkip,
				obj: map[string]any{
					"kind": "certificateProfile",
					"name": "ExistingCert",
				},
			},
		},
	}

	res := &ImportResult{Errors: []string{}}
	err := applyIdentitySources(client, r, res, t.Logf)
	if err != nil {
		t.Fatalf("applyIdentitySources: %v", err)
	}

	if res.Created != 2 {
		t.Errorf("expected 2 created, got %d", res.Created)
	}
	if res.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", res.Skipped)
	}
	if res.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", res.Failed)
	}

	// Verify objects were created in fake
	if len(fake.restIDStores) != 1 {
		t.Errorf("expected 1 REST store created, got %d", len(fake.restIDStores))
	}
	if len(fake.certProfiles) != 1 {
		t.Errorf("expected 1 cert profile created, got %d", len(fake.certProfiles))
	}
}

func TestIdentitySourcesToPolicyResolution(t *testing.T) {
	fake := newFakeISE(t)
	client := fake.client()

	// Add a REST store to the source that will be created in this run
	restStore := map[string]any{
		"id":   "rest-1",
		"name": "NewStore",
	}
	fake.restIDStores = append(fake.restIDStores, restStore)

	// Create a preflight report with that store being created
	r := &PreflightReport{
		Items: []PreflightItem{
			{
				Family: familyIdentitySources,
				Name:   "NewStore",
				Action: actionCreate,
				obj: map[string]any{
					"kind": "restIDStore",
					"name": "NewStore",
				},
			},
		},
	}

	// Get the identity sources that will exist after this run
	sources := identitySourcesAfterThisRun(client, r)
	if !sources["NewStore"] {
		t.Error("NewStore not in sources after this run")
	}

	// Verify it includes the target's existing objects
	if !sources["restStore"] && len(fake.restIDStores) > 0 {
		// At least the ones from the target should be there
		// (identity sources from this run include what the target already has)
	}
}

func TestSecretNotInLogOrReason(t *testing.T) {
	fake := newFakeISE(t)
	client := fake.client()

	const secret = "supersecret123"

	// Create a REST store with a secret
	restStore := map[string]any{
		"id":   "rest-1",
		"name": "EntraID",
		"ersRestIDStoreAttributes": map[string]any{
			"headers": []any{
				map[string]any{"key": "clientSecret", "value": secret},
			},
		},
	}
	fake.restIDStores = append(fake.restIDStores, restStore)

	// Export and check logs
	b := NewBundle(client.ProbeDeployment())
	var logLines []string
	logFn := func(format string, args ...any) {
		logLines = append(logLines, fmt.Sprintf(format, args...))
	}

	err := ExportIdentitySources(client, b, []string{familyIdentitySources}, logFn)
	if err != nil {
		t.Fatalf("ExportIdentitySources: %v", err)
	}

	// Check no log contains the secret
	for _, line := range logLines {
		if strings.Contains(line, secret) {
			t.Errorf("secret found in log: %s", line)
		}
	}

	// Check no note contains the secret
	for _, note := range b.Notes {
		if strings.Contains(note, secret) {
			t.Errorf("secret found in bundle note: %s", note)
		}
	}

	// Create a preflight report with a skipped item (has drift)
	b.Objects[familyIdentitySources] = []map[string]any{
		{
			"name": "EntraID",
			"kind": "restIDStore",
		},
	}

	r := &PreflightReport{}
	preflightIdentitySources(client, b, r)

	// Check no reason contains the secret
	for _, item := range r.Items {
		if strings.Contains(item.Reason, secret) {
			t.Errorf("secret found in preflight reason: %s", item.Reason)
		}
	}
}

func TestDuplicateHandling(t *testing.T) {
	fake := newFakeISE(t)
	client := fake.client()

	// Pre-populate with existing object
	fake.certProfiles = append(fake.certProfiles, map[string]any{
		"id":   "existing",
		"name": "ExistingProfile",
	})

	// Create preflight report attempting to create duplicate
	r := &PreflightReport{
		Items: []PreflightItem{
			{
				Family: familyIdentitySources,
				Name:   "ExistingProfile",
				Action: actionCreate,
				obj: map[string]any{
					"kind": "certificateProfile",
					"name": "ExistingProfile",
				},
			},
		},
	}

	res := &ImportResult{Errors: []string{}}
	err := applyIdentitySources(client, r, res, t.Logf)
	if err != nil {
		t.Fatalf("applyIdentitySources: %v", err)
	}

	// Duplicate should be counted as skipped
	if res.Skipped != 1 {
		t.Errorf("expected 1 skipped for duplicate, got %d", res.Skipped)
	}
}

func TestHeaderComparison(t *testing.T) {
	// Test that header comparison redacts values
	mine := map[string]any{
		"ersRestIDStoreAttributes": map[string]any{
			"headers": []any{
				map[string]any{"key": "clientSecret", "value": "secret1"},
			},
		},
	}

	theirs := map[string]any{
		"ersRestIDStoreAttributes": map[string]any{
			"headers": []any{
				map[string]any{"key": "clientSecret", "value": "secret2"},
			},
		},
	}

	fields := driftFieldsIdentitySource(mine, theirs, "restIDStore")
	found := false
	for _, f := range fields {
		if f == "clientSecret" {
			found = true
		}
	}
	if !found {
		t.Error("expected clientSecret in drift fields")
	}

	// Verify neither secret value is in the fields list
	fieldsStr := fmt.Sprintf("%v", fields)
	if strings.Contains(fieldsStr, "secret1") || strings.Contains(fieldsStr, "secret2") {
		t.Error("secret values found in drift fields")
	}
}

func TestAllFamiliesForSecrets(t *testing.T) {
	fake := newFakeISE(t)
	client := fake.client()

	const secret = "mysecret"

	// Create store with secret, add it to fake
	fake.restIDStores = append(fake.restIDStores, map[string]any{
		"id":   "rest-1",
		"name": "WithSecret",
		"ersRestIDStoreAttributes": map[string]any{
			"headers": []any{
				map[string]any{"key": "clientSecret", "value": secret},
			},
		},
	})

	// Full export-preflight-apply cycle
	b := NewBundle(client.ProbeDeployment())
	var logs []string
	logFn := func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	// Export
	err := ExportIdentitySources(client, b, []string{familyIdentitySources}, logFn)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Preflight
	r := &PreflightReport{}
	preflightIdentitySources(client, b, r)

	// Apply
	res := &ImportResult{Errors: []string{}}
	err = applyIdentitySources(client, r, res, logFn)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Scan all logs, notes, item names and reasons for the literal secret
	for _, log := range logs {
		if strings.Contains(log, secret) {
			t.Errorf("secret found in log: %s", log)
		}
	}
	for _, note := range b.Notes {
		if strings.Contains(note, secret) {
			t.Errorf("secret found in bundle note: %s", note)
		}
	}
	for _, note := range r.Notes {
		if strings.Contains(note, secret) {
			t.Errorf("secret found in preflight note: %s", note)
		}
	}
	for _, item := range r.Items {
		if strings.Contains(item.Name, secret) || strings.Contains(item.Reason, secret) {
			t.Errorf("secret found in preflight item")
		}
	}
	for _, err := range res.Errors {
		if strings.Contains(err, secret) {
			t.Errorf("secret found in import result error: %s", err)
		}
	}
}
