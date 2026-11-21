package in_toto

import (
	"strings"
	"testing"
)

func testLink(name string, materials, products map[string]HashObj) Metadata {
	return &Metablock{Signed: Link{
		Type:      "link",
		Name:      name,
		Materials: materials,
		Products:  products,
	}}
}

func testStep(name string, threshold int, pubKeys ...string) Step {
	return Step{
		SupplyChainItem: SupplyChainItem{Name: name},
		Threshold:       threshold,
		PubKeys:         pubKeys,
	}
}

func hasState(result ThresholdConsensusResult,
	status ThresholdConsensusStatus) bool {
	for _, s := range result.States {
		if s == status {
			return true
		}
	}
	return false
}

func TestVerifyStepThresholdConsensusReached(t *testing.T) {
	step := testStep("package", 2, "alice", "bob", "carol")
	materials := map[string]HashObj{"foo.py": {"sha256": "abc"}}
	products := map[string]HashObj{"bar.py": {"sha256": "def"}}

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package", materials, products)},
		{KeyID: "bob", Link: testLink("package", materials, products)},
	})

	if !result.Trusted() {
		t.Fatalf("expected trusted consensus, got status '%s' (%s)",
			result.Status, result.Summary())
	}
	if result.Status != StatusThresholdReached {
		t.Errorf("expected status '%s', got '%s'", StatusThresholdReached,
			result.Status)
	}
	if result.TrustedGroup == nil || len(result.TrustedGroup.Signers) != 2 {
		t.Errorf("expected trusted group with 2 signers, got %+v",
			result.TrustedGroup)
	}
	if len(result.Groups) != 1 {
		t.Errorf("expected 1 artifact group, got %d", len(result.Groups))
	}
	// carol is authorized but did not submit a link
	if len(result.MissingFunctionaries) != 1 ||
		result.MissingFunctionaries[0] != "carol" {
		t.Errorf("expected missing functionary 'carol', got %v",
			result.MissingFunctionaries)
	}
	if !hasState(result, StatusMissingFunctionaries) {
		t.Errorf("expected state '%s' in %v", StatusMissingFunctionaries,
			result.States)
	}
}

func TestVerifyStepThresholdConsensusDuplicatesNotCounted(t *testing.T) {
	// Threshold 2, but both links come from the same functionary: the
	// duplicate must not count as an independent attestation
	step := testStep("package", 2, "alice", "bob")
	materials := map[string]HashObj{"foo.py": {"sha256": "abc"}}

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package", materials, nil)},
		{KeyID: "alice", Link: testLink("package", materials, nil)},
	})

	if result.Trusted() {
		t.Errorf("duplicate links from one functionary must not reach the" +
			" threshold")
	}
	if result.Status != StatusBelowThreshold {
		t.Errorf("expected status '%s', got '%s'", StatusBelowThreshold,
			result.Status)
	}
	if !hasState(result, StatusDuplicateSignatures) {
		t.Errorf("expected state '%s' in %v", StatusDuplicateSignatures,
			result.States)
	}
	if len(result.Duplicates) != 1 || result.Duplicates[0].KeyID != "alice" ||
		result.Duplicates[0].ExtraLinks != 1 {
		t.Errorf("expected one duplicate link for 'alice', got %+v",
			result.Duplicates)
	}
	if len(result.Groups) != 1 || len(result.Groups[0].Signers) != 1 {
		t.Errorf("expected one group with one distinct signer, got %+v",
			result.Groups)
	}
}

func TestVerifyStepThresholdConsensusConflictingMaterials(t *testing.T) {
	// Two functionaries contradict each other, neither reaches threshold 2
	step := testStep("package", 2, "alice", "bob")

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package",
			map[string]HashObj{"foo.py": {"sha256": "abc"}}, nil)},
		{KeyID: "bob", Link: testLink("package",
			map[string]HashObj{"foo.py": {"sha256": "different"}}, nil)},
	})

	if result.Trusted() {
		t.Errorf("conflicting materials must not form a trusted consensus")
	}
	if result.Status != StatusConflictingMaterials {
		t.Errorf("expected status '%s', got '%s'", StatusConflictingMaterials,
			result.Status)
	}
	if !hasState(result, StatusConflictingMaterials) {
		t.Errorf("expected state '%s' in %v", StatusConflictingMaterials,
			result.States)
	}
	if len(result.Groups) != 2 {
		t.Errorf("expected 2 conflicting groups, got %d", len(result.Groups))
	}
	if !strings.Contains(result.Summary(), "different artifacts") {
		t.Errorf("summary should express the conflict, got '%s'",
			result.Summary())
	}
}

func TestVerifyStepThresholdConsensusConflictingProducts(t *testing.T) {
	// Contradictory products must also be detected
	step := testStep("package", 2, "alice", "bob")
	materials := map[string]HashObj{"foo.py": {"sha256": "abc"}}

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package", materials,
			map[string]HashObj{"bar.py": {"sha256": "def"}})},
		{KeyID: "bob", Link: testLink("package", materials,
			map[string]HashObj{"bar.py": {"sha256": "different"}})},
	})

	if result.Status != StatusConflictingMaterials {
		t.Errorf("expected status '%s', got '%s'", StatusConflictingMaterials,
			result.Status)
	}
}

func TestVerifyStepThresholdConsensusConflictingTie(t *testing.T) {
	// Two contradictory artifact views both reach the threshold: no trusted
	// conclusion may be formed
	step := testStep("package", 2, "alice", "bob", "carol", "dave")

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package",
			map[string]HashObj{"foo.py": {"sha256": "abc"}}, nil)},
		{KeyID: "bob", Link: testLink("package",
			map[string]HashObj{"foo.py": {"sha256": "abc"}}, nil)},
		{KeyID: "carol", Link: testLink("package",
			map[string]HashObj{"foo.py": {"sha256": "different"}}, nil)},
		{KeyID: "dave", Link: testLink("package",
			map[string]HashObj{"foo.py": {"sha256": "different"}}, nil)},
	})

	if result.Trusted() {
		t.Errorf("a tie between contradictory views must not be trusted")
	}
	if result.Status != StatusConflictingMaterials {
		t.Errorf("expected status '%s', got '%s'", StatusConflictingMaterials,
			result.Status)
	}
	if result.TrustedGroup != nil {
		t.Errorf("expected no trusted group, got %+v", result.TrustedGroup)
	}
}

func TestVerifyStepThresholdConsensusBelowThreshold(t *testing.T) {
	step := testStep("package", 3, "alice", "bob")
	materials := map[string]HashObj{"foo.py": {"sha256": "abc"}}

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package", materials, nil)},
		{KeyID: "bob", Link: testLink("package", materials, nil)},
	})

	if result.Trusted() {
		t.Errorf("2 of 3 required functionaries must not be trusted")
	}
	if result.Status != StatusBelowThreshold {
		t.Errorf("expected status '%s', got '%s'", StatusBelowThreshold,
			result.Status)
	}
	if !hasState(result, StatusBelowThreshold) {
		t.Errorf("expected state '%s' in %v", StatusBelowThreshold,
			result.States)
	}
}

func TestVerifyStepThresholdConsensusMissingFunctionaries(t *testing.T) {
	// No links at all: every authorized functionary is missing
	step := testStep("package", 2, "alice", "bob")

	result := VerifyStepThresholdConsensus(step, nil)

	if result.Trusted() {
		t.Errorf("no links must not form a trusted consensus")
	}
	if result.Status != StatusMissingFunctionaries {
		t.Errorf("expected status '%s', got '%s'", StatusMissingFunctionaries,
			result.Status)
	}
	if len(result.MissingFunctionaries) != 2 {
		t.Errorf("expected 2 missing functionaries, got %v",
			result.MissingFunctionaries)
	}
}

func TestVerifyStepThresholdConsensusOutvotedConflict(t *testing.T) {
	// Threshold 2: alice and bob agree, carol contradicts.  The consistent
	// majority forms the trusted consensus, the conflict stays identifiable.
	step := testStep("package", 2, "alice", "bob", "carol")
	products := map[string]HashObj{"bar.py": {"sha256": "def"}}

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package", nil, products)},
		{KeyID: "bob", Link: testLink("package", nil, products)},
		{KeyID: "carol", Link: testLink("package", nil,
			map[string]HashObj{"bar.py": {"sha256": "different"}})},
	})

	if !result.Trusted() {
		t.Fatalf("expected trusted consensus, got '%s' (%s)", result.Status,
			result.Summary())
	}
	if len(result.TrustedGroup.Signers) != 2 {
		t.Errorf("expected 2 signers in trusted group, got %v",
			result.TrustedGroup.Signers)
	}
	if !hasState(result, StatusConflictingMaterials) {
		t.Errorf("outvoted conflict should remain identifiable, states: %v",
			result.States)
	}
	if len(result.Groups) != 2 {
		t.Errorf("expected 2 groups (majority and outvoted), got %d",
			len(result.Groups))
	}
}

func TestVerifyStepThresholdConsensusZeroThreshold(t *testing.T) {
	// A threshold of 0 is treated as 1: one attesting functionary suffices
	step := testStep("package", 0, "alice")

	result := VerifyStepThresholdConsensus(step, []FunctionaryLink{
		{KeyID: "alice", Link: testLink("package", nil, nil)},
	})

	if !result.Trusted() {
		t.Errorf("expected trusted consensus, got '%s'", result.Status)
	}
	if result.Threshold != 1 {
		t.Errorf("expected effective threshold 1, got %d", result.Threshold)
	}
}

func TestVerifyLayoutThresholdConsensus(t *testing.T) {
	layout := Layout{Steps: []Step{
		testStep("write-code", 1, "alice"),
		testStep("package", 2, "bob", "carol"),
		testStep("test", 2, "dave", "erin"),
	}}
	materials := map[string]HashObj{"foo.py": {"sha256": "abc"}}

	stepsMetadata := map[string]map[string]Metadata{
		"write-code": {
			"alice": testLink("write-code", materials, nil),
		},
		"package": {
			"bob":   testLink("package", materials, nil),
			"carol": testLink("package", materials, nil),
		},
		"test": {
			"dave": testLink("test", materials, nil),
		},
	}

	results := VerifyLayoutThresholdConsensus(layout, stepsMetadata)

	if len(results) != 3 {
		t.Fatalf("expected results for 3 steps, got %d", len(results))
	}
	if !results["write-code"].Trusted() {
		t.Errorf("step 'write-code' should be trusted, got '%s'",
			results["write-code"].Status)
	}
	if !results["package"].Trusted() {
		t.Errorf("step 'package' should be trusted, got '%s'",
			results["package"].Status)
	}
	if results["test"].Trusted() ||
		results["test"].Status != StatusBelowThreshold {
		t.Errorf("step 'test' should be below threshold, got '%s'",
			results["test"].Status)
	}
	if len(results["test"].MissingFunctionaries) != 1 ||
		results["test"].MissingFunctionaries[0] != "erin" {
		t.Errorf("expected missing functionary 'erin' for step 'test', got %v",
			results["test"].MissingFunctionaries)
	}
}

func TestReduceStepsMetadataThresholdConsensus(t *testing.T) {
	layout := Layout{Steps: []Step{
		testStep("package", 2, "alice", "bob", "carol"),
	}}
	products := map[string]HashObj{"bar.py": {"sha256": "def"}}

	// Two functionaries agree and reach the threshold, a third one
	// contradicts: reduction must succeed with the trusted majority view
	// instead of erroring out
	stepsMetadata := map[string]map[string]Metadata{
		"package": {
			"alice": testLink("package", nil, products),
			"bob":   testLink("package", nil, products),
			"carol": testLink("package", nil,
				map[string]HashObj{"bar.py": {"sha256": "different"}}),
		},
	}

	result, err := ReduceStepsMetadata(layout, stepsMetadata)
	if err != nil {
		t.Fatalf("ReduceStepsMetadata returned unexpected error: %s", err)
	}
	reduced, ok := result["package"].GetPayload().(Link)
	if !ok {
		t.Fatalf("invalid metadata")
	}
	if reduced.Products["bar.py"]["sha256"] != "def" {
		t.Errorf("expected reduced link to carry the majority products, got %v",
			reduced.Products)
	}

	// A conflicting tie (threshold 2, one link per artifact view) must still
	// error
	stepsMetadata["package"] = map[string]Metadata{
		"alice": testLink("package", nil, products),
		"bob": testLink("package", nil,
			map[string]HashObj{"bar.py": {"sha256": "different"}}),
	}
	if _, err := ReduceStepsMetadata(layout, stepsMetadata); err == nil ||
		!strings.Contains(err.Error(), "different artifacts") {
		t.Errorf("expected a 'different artifacts' error, got %v", err)
	}
}
