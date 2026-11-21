package in_toto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

/*
ThresholdConsensusStatus identifies the outcome of evaluating the links
submitted for a step against the step's signature threshold.  It allows
callers to clearly express why a set of functionary links does or does not
form a trusted conclusion about a supply chain artifact.
*/
type ThresholdConsensusStatus string

const (
	// StatusThresholdReached means that at least Threshold distinct
	// functionaries submitted links that agree on the step's materials and
	// products.  Only in this state is the result trusted.
	StatusThresholdReached ThresholdConsensusStatus = "threshold-reached"

	// StatusBelowThreshold means that the links agree on the reported
	// artifacts, but fewer than Threshold distinct functionaries attested
	// to them.
	StatusBelowThreshold ThresholdConsensusStatus = "below-threshold"

	// StatusConflictingMaterials means that distinct functionaries reported
	// contradictory materials or products for the same step, and no single
	// artifact view gathered enough support to reach the threshold.
	StatusConflictingMaterials ThresholdConsensusStatus = "conflicting-materials"

	// StatusMissingFunctionaries means that one or more functionaries
	// authorized in the step's PubKeys did not submit any link at all.
	StatusMissingFunctionaries ThresholdConsensusStatus = "missing-functionaries"

	// StatusDuplicateSignatures means that a functionary submitted more
	// than one link for the step.  Duplicate links are never counted as
	// independent attestations.
	StatusDuplicateSignatures ThresholdConsensusStatus = "duplicate-signatures"
)

/*
FunctionaryLink associates a link metadata file with the key ID of the
functionary (subject) that signed it.  It is the unit of input for
VerifyStepThresholdConsensus.
*/
type FunctionaryLink struct {
	KeyID string
	Link  Metadata
}

/*
ArtifactGroup is a set of links for one step that report exactly the same
materials and products.  Signers holds the distinct functionary key IDs that
attested to this artifact view; a functionary that submitted duplicate links
appears only once.  ReferenceLink is one representative link of the group and
may be used for subsequent verification (e.g. artifact rule verification)
once the group forms the trusted consensus.
*/
type ArtifactGroup struct {
	Fingerprint   string
	Materials     map[string]HashObj
	Products      map[string]HashObj
	Signers       []string
	ReferenceLink Metadata
}

/*
DuplicateSignature records that the functionary with the given key ID
submitted ExtraLinks more links than the one link that was counted for the
step.
*/
type DuplicateSignature struct {
	KeyID      string
	ExtraLinks int
}

/*
ThresholdConsensusResult is the outcome of grouping the links of one step by
subject (functionary key ID), artifact (materials and products) and step, and
evaluating the groups against the step's threshold.  Status holds the primary
conclusion, while States lists every identifiable condition that was detected
(e.g. a result can be below threshold and have missing functionaries and
duplicate signatures at the same time).  The result is only trustworthy if
Status is StatusThresholdReached, which the Trusted method reports.
*/
type ThresholdConsensusResult struct {
	StepName  string
	Threshold int
	Status    ThresholdConsensusStatus
	States    []ThresholdConsensusStatus

	// Groups holds one entry per distinct artifact view reported for the
	// step, sorted by descending number of distinct signers.
	Groups []ArtifactGroup

	// TrustedGroup is the group that reached the threshold.  It is only
	// set if Status is StatusThresholdReached.
	TrustedGroup *ArtifactGroup

	// Duplicates lists functionaries that submitted more than one link for
	// the step.  Their extra links were not counted towards the threshold.
	Duplicates []DuplicateSignature

	// MissingFunctionaries lists authorized key IDs from the step's
	// PubKeys for which no link was submitted at all.
	MissingFunctionaries []string
}

/*
Trusted reports whether the step's links form a trusted threshold consensus,
i.e. at least Threshold distinct functionaries agree on the same artifacts.
*/
func (r ThresholdConsensusResult) Trusted() bool {
	return r.Status == StatusThresholdReached
}

/*
Summary returns a human readable sentence that clearly expresses the
threshold consensus (or why none was reached) for the step.
*/
func (r ThresholdConsensusResult) Summary() string {
	switch r.Status {
	case StatusThresholdReached:
		return fmt.Sprintf("step '%s': threshold consensus reached, '%d' of"+
			" required '%d' distinct functionaries agree on artifacts '%s'",
			r.StepName, len(r.TrustedGroup.Signers), r.Threshold,
			r.TrustedGroup.Fingerprint)
	case StatusConflictingMaterials:
		return fmt.Sprintf("step '%s': links from distinct functionaries have"+
			" different artifacts, split into '%d' conflicting group(s), none"+
			" reaching the threshold of '%d'", r.StepName, len(r.Groups),
			r.Threshold)
	case StatusMissingFunctionaries:
		return fmt.Sprintf("step '%s': no links found, '%d' authorized"+
			" functionary(ies) are missing: %s", r.StepName,
			len(r.MissingFunctionaries), strings.Join(r.MissingFunctionaries, ", "))
	default:
		signers := 0
		if len(r.Groups) > 0 {
			signers = len(r.Groups[0].Signers)
		}
		return fmt.Sprintf("step '%s': below threshold, only '%d' of required"+
			" '%d' distinct functionaries agree on artifacts '%s'", r.StepName,
			signers, r.Threshold, r.Groups[0].Fingerprint)
	}
}

/*
artifactFingerprint returns a canonical fingerprint for a link's materials
and products, so that links reporting identical artifacts share a fingerprint
and links reporting contradictory artifacts fall into different groups.
*/
func artifactFingerprint(materials, products map[string]HashObj) string {
	var b strings.Builder
	writeArtifacts := func(kind string, artifacts map[string]HashObj) {
		b.WriteString(kind)
		b.WriteString(":")
		names := make([]string, 0, len(artifacts))
		for name := range artifacts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			b.WriteString(name)
			b.WriteString("(")
			hashTypes := make([]string, 0, len(artifacts[name]))
			for hashType := range artifacts[name] {
				hashTypes = append(hashTypes, hashType)
			}
			sort.Strings(hashTypes)
			for _, hashType := range hashTypes {
				b.WriteString(hashType)
				b.WriteString("=")
				b.WriteString(artifacts[name][hashType])
				b.WriteString(";")
			}
			b.WriteString(")")
		}
		b.WriteString("|")
	}
	writeArtifacts("materials", materials)
	writeArtifacts("products", products)
	digest := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(digest[:])
}

/*
VerifyStepThresholdConsensus groups the passed links of a single step by
subject (functionary key ID), artifact (materials and products) and step, and
evaluates the groups against the step's threshold.  A trusted conclusion
(StatusThresholdReached) is only formed if at least Threshold distinct
functionaries attested to the same artifacts.  Duplicate links from the same
functionary are collapsed and reported in the result's Duplicates field,
never counting as independent attestations.  Contradictory materials or
products, missing authorized functionaries and below-threshold groups each
produce an identifiable status in the result.

Links whose payload is not a Link are ignored.  A threshold smaller than 1 is
treated as 1: a trusted conclusion always requires at least one attesting
functionary.
*/
func VerifyStepThresholdConsensus(step Step,
	links []FunctionaryLink) ThresholdConsensusResult {
	threshold := step.Threshold
	if threshold < 1 {
		threshold = 1
	}

	result := ThresholdConsensusResult{
		StepName:  step.Name,
		Threshold: threshold,
	}

	// Group links by the artifacts they report
	groupsByFingerprint := make(map[string]*ArtifactGroup)
	// Track, per group, which functionaries already attested, so that
	// duplicate links from the same subject are not counted twice
	signersByFingerprint := make(map[string]Set)
	duplicates := make(map[string]int)

	for _, functionaryLink := range links {
		link, ok := functionaryLink.Link.GetPayload().(Link)
		if !ok {
			continue
		}

		fingerprint := artifactFingerprint(link.Materials, link.Products)
		group, ok := groupsByFingerprint[fingerprint]
		if !ok {
			group = &ArtifactGroup{
				Fingerprint:   fingerprint,
				Materials:     link.Materials,
				Products:      link.Products,
				ReferenceLink: functionaryLink.Link,
			}
			groupsByFingerprint[fingerprint] = group
			signersByFingerprint[fingerprint] = NewSet()
		}

		signers := signersByFingerprint[fingerprint]
		if _, seen := signers[functionaryLink.KeyID]; seen {
			// Same subject attesting again: record the duplicate but do
			// not count it as an independent attestation
			duplicates[functionaryLink.KeyID]++
			continue
		}
		signers[functionaryLink.KeyID] = struct{}{}
		group.Signers = append(group.Signers, functionaryLink.KeyID)
	}

	// Flatten groups, sorting by number of distinct signers (descending) and
	// fingerprint for a deterministic result
	for _, group := range groupsByFingerprint {
		sort.Strings(group.Signers)
		result.Groups = append(result.Groups, *group)
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		if len(result.Groups[i].Signers) != len(result.Groups[j].Signers) {
			return len(result.Groups[i].Signers) > len(result.Groups[j].Signers)
		}
		return result.Groups[i].Fingerprint < result.Groups[j].Fingerprint
	})

	// Record duplicates, sorted for determinism
	duplicateKeyIDs := make([]string, 0, len(duplicates))
	for keyID := range duplicates {
		duplicateKeyIDs = append(duplicateKeyIDs, keyID)
	}
	sort.Strings(duplicateKeyIDs)
	for _, keyID := range duplicateKeyIDs {
		result.Duplicates = append(result.Duplicates,
			DuplicateSignature{KeyID: keyID, ExtraLinks: duplicates[keyID]})
	}

	// Determine which authorized functionaries did not submit any link
	seen := NewSet()
	for _, group := range result.Groups {
		for _, signer := range group.Signers {
			seen[signer] = struct{}{}
		}
	}
	for _, keyID := range step.PubKeys {
		if _, ok := seen[keyID]; !ok {
			result.MissingFunctionaries = append(result.MissingFunctionaries, keyID)
		}
	}
	sort.Strings(result.MissingFunctionaries)

	// Collect all identifiable states
	if len(result.Duplicates) > 0 {
		result.States = append(result.States, StatusDuplicateSignatures)
	}
	if len(result.MissingFunctionaries) > 0 {
		result.States = append(result.States, StatusMissingFunctionaries)
	}
	if len(result.Groups) > 1 {
		result.States = append(result.States, StatusConflictingMaterials)
	}

	// Find groups that reached the threshold
	var reached []*ArtifactGroup
	for i := range result.Groups {
		if len(result.Groups[i].Signers) >= threshold {
			reached = append(reached, &result.Groups[i])
		}
	}

	switch {
	case len(reached) == 1:
		// Exactly one artifact view gathered enough distinct functionaries:
		// this is the trusted threshold consensus
		result.Status = StatusThresholdReached
		result.TrustedGroup = reached[0]
	case len(reached) > 1:
		// Contradictory artifact views both claim consensus: trust neither
		result.Status = StatusConflictingMaterials
	case len(result.Groups) == 0:
		// No usable links at all
		result.Status = StatusMissingFunctionaries
		if len(result.States) == 0 {
			result.States = append(result.States, StatusMissingFunctionaries)
		}
	case len(result.Groups) > 1:
		// Functionaries contradict each other and no view reached threshold
		result.Status = StatusConflictingMaterials
	default:
		result.Status = StatusBelowThreshold
		result.States = append(result.States, StatusBelowThreshold)
	}

	return result
}

/*
VerifyStepThresholdConsensusFromMap is a convenience wrapper around
VerifyStepThresholdConsensus for link metadata in the map format used
throughout verifylib (step name -> signer key ID -> link metadata).
*/
func VerifyStepThresholdConsensusFromMap(step Step,
	linksPerStep map[string]Metadata) ThresholdConsensusResult {
	keyIDs := make([]string, 0, len(linksPerStep))
	for keyID := range linksPerStep {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)

	links := make([]FunctionaryLink, 0, len(linksPerStep))
	for _, keyID := range keyIDs {
		links = append(links, FunctionaryLink{KeyID: keyID, Link: linksPerStep[keyID]})
	}
	return VerifyStepThresholdConsensus(step, links)
}

/*
VerifyLayoutThresholdConsensus evaluates the threshold consensus for every
step of the passed layout, given link metadata in the map format used
throughout verifylib (step name -> signer key ID -> link metadata).  The
returned map holds one ThresholdConsensusResult per step name, so callers can
clearly express which steps reached a trusted consensus and which steps have
duplicate signatures, conflicting materials, missing functionaries or
below-threshold groups.
*/
func VerifyLayoutThresholdConsensus(layout Layout,
	stepsMetadata map[string]map[string]Metadata) map[string]ThresholdConsensusResult {
	results := make(map[string]ThresholdConsensusResult, len(layout.Steps))
	for _, step := range layout.Steps {
		results[step.Name] = VerifyStepThresholdConsensusFromMap(step,
			stepsMetadata[step.Name])
	}
	return results
}
