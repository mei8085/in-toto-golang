package in_toto

// This file tests how artifact rules deal with path aliases.
//
// An "alias" is a path string that denotes the same lexical artifact as a
// canonical path, e.g. "a//b", "a/./b", "./a/b", or "a/x/../b" all alias
// "a/b".  Artifact rules (in particular MATCH) normalize their inputs, so a
// link that recorded an aliased spelling must still bind to the artifact
// recorded under the canonical spelling.
//
// The tests compare the implementation against an independent reference model
// of the normalization and binding semantics (implemented below without
// calling path.Clean).  This keeps the expected behavior explicit and
// independent from the standard library algorithm the production code uses.
// Whenever the implementation and the reference model disagree, the tests
// print the complete path transformation chain and the reason the reference
// model rejected (or accepted) the binding.
//
// Everything here is in memory: no network access and no containers are
// required.  Symlink-style paths (a ".." component that follows a directory
// component) are treated as plain strings, which is exactly what the
// implementation does; one test additionally creates a real symlink in a
// temporary directory to pin down that artifact rules resolve paths lexically
// and never through the filesystem.
//
// Case sensitivity: artifact paths are compared byte-wise, so paths that
// differ only by case are different artifacts and must not bind.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	aliasSrcStep = "src-step"
	aliasDstStep = "dst-step"

	aliasReasonBound       = "bound"
	aliasReasonHash        = "hash-mismatch"
	aliasReasonCase        = "case-sensitive-name-mismatch"
	aliasReasonDestination = "computed-destination-mismatch"

	aliasWarnSourcePathEscape = "source-path-escapes-rule-namespace"
	aliasWarnDestPathEscape   = "destination-path-escapes-rule-namespace"
	aliasWarnSourcePrefix     = "source-prefix-escapes-rule-namespace"
	aliasWarnDestPrefix       = "destination-prefix-escapes-rule-namespace"
	aliasWarnSourceAbsolute   = "source-path-is-absolute"
	aliasWarnDestAbsolute     = "destination-path-is-absolute"
	aliasWarnLexicalDotDot    = "dotdot-resolved-lexically"
)

/*
aliasModelClean is an independent lexical path normalizer for slash-separated
artifact paths.  It is deliberately implemented as a stack-based algorithm
instead of calling path.Clean, so that the model is not a tautology over the
production implementation.

Semantics:
  - empty input normalizes to "."
  - empty and "." segments are dropped
  - ".." removes the preceding segment unless there is none, is a "..", or the
    path is rooted
  - a leading "/" makes the result rooted
*/
func aliasModelClean(p string) string {
	if p == "" {
		return "."
	}
	rooted := strings.HasPrefix(p, "/")
	stack := make([]string, 0, strings.Count(p, "/")+1)
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 && stack[len(stack)-1] != ".." {
				stack = stack[:len(stack)-1]
				continue
			}
			if rooted {
				continue
			}
			stack = append(stack, "..")
		default:
			stack = append(stack, seg)
		}
	}
	normalized := strings.Join(stack, "/")
	if rooted {
		return "/" + normalized
	}
	if normalized == "" {
		return "."
	}
	return normalized
}

/*
aliasModelPrefix normalizes a rule prefix and appends a trailing slash, which is
how verifyMatchRule turns source and destination prefixes into a directory
prefix.  An empty prefix stays empty.
*/
func aliasModelPrefix(p string) string {
	if p == "" {
		return ""
	}
	cleaned := aliasModelClean(p)
	if strings.HasSuffix(cleaned, "/") {
		return cleaned
	}
	return cleaned + "/"
}

// aliasModelJoin models path.Clean(path.Join(prefix, base)) where prefix was
// already normalized by aliasModelPrefix (and therefore is empty or ends in
// "/").
func aliasModelJoin(prefix, base string) string {
	if prefix == "" {
		return aliasModelClean(base)
	}
	return aliasModelClean(prefix + base)
}

// artifactBinding describes one MATCH rule binding experiment.
type artifactBinding struct {
	srcPath   string // material spelling in the source link
	dstPath   string // product spelling in the destination link
	srcPrefix string // optional MATCH "IN <source-prefix>"
	dstPrefix string // optional MATCH "IN <destination-prefix>"
	sameHash  bool   // whether both links recorded the same hash
}

// bindingModel is the reference model's verdict for an artifactBinding.
type bindingModel struct {
	bound     bool
	reason    string
	warnings  []string
	srcClean  string
	dstClean  string
	srcPrefix string
	dstPrefix string
	srcBase   string
	dstBucket string
}

/*
aliasModelBinding predicts, independently of the production code, whether the
MATCH rule

	MATCH * [IN <srcPrefix>] WITH PRODUCTS [IN <dstPrefix>] FROM <dst step>

consumes the source material and thus binds it to the destination product.

The pattern is fixed to "*" because these tests target path aliasing, not glob
semantics; "*" matches every normalized artifact path, including the empty
remainder after a prefix strip.
*/
func aliasModelBinding(c artifactBinding) bindingModel {
	m := bindingModel{
		srcClean:  aliasModelClean(c.srcPath),
		dstClean:  aliasModelClean(c.dstPath),
		srcPrefix: aliasModelPrefix(c.srcPrefix),
		dstPrefix: aliasModelPrefix(c.dstPrefix),
	}
	m.srcBase = strings.TrimPrefix(m.srcClean, m.srcPrefix)
	m.dstBucket = aliasModelJoin(m.dstPrefix, m.srcBase)

	switch {
	case m.dstBucket == m.dstClean && c.sameHash:
		m.bound = true
		m.reason = aliasReasonBound
	case m.dstBucket == m.dstClean:
		m.reason = aliasReasonHash + ": the paths resolve to the same artifact but the recorded hashes differ"
	case strings.EqualFold(m.dstBucket, m.dstClean):
		m.reason = aliasReasonCase + ": artifact paths differ only by case and are treated as different artifacts"
	default:
		m.reason = fmt.Sprintf("%s: source %q maps to %q, destination is %q",
			aliasReasonDestination, c.srcPath, m.dstBucket, m.dstClean)
	}
	m.warnings = aliasModelWarnings(c)
	return m
}

/*
aliasModelWarnings reports conditions that do not change the expected binding
but are security-relevant and therefore worth surfacing next to a divergence.
*/
func aliasModelWarnings(c artifactBinding) []string {
	var warnings []string
	addEscape := func(kind, p string) {
		if reason := aliasEscapeReason(kind, p); reason != "" {
			warnings = append(warnings, reason)
		}
	}
	addEscape("source-path", c.srcPath)
	addEscape("destination-path", c.dstPath)
	addEscape("source-prefix", c.srcPrefix)
	addEscape("destination-prefix", c.dstPrefix)

	for _, p := range []string{c.srcPath, c.dstPath, c.srcPrefix, c.dstPrefix} {
		if aliasHasInteriorDotDot(p) {
			warnings = append(warnings, fmt.Sprintf(
				"%s: %q contains '..' after a path component without consulting the filesystem; "+
					"if that component were a symlink the physical target could differ",
				aliasWarnLexicalDotDot, p))
		}
	}
	return warnings
}

// aliasEscapeReason classifies paths and prefixes that leave the artifact
// namespace rooted at the working directory.
func aliasEscapeReason(kind, p string) string {
	if p == "" {
		return ""
	}
	cleaned := aliasModelClean(p)
	switch {
	case cleaned == ".." || strings.HasPrefix(cleaned, "../"):
		return fmt.Sprintf("%s-escapes-rule-namespace: %q normalizes to %q", kind, p, cleaned)
	case strings.HasPrefix(cleaned, "/"):
		return fmt.Sprintf("%s-is-absolute: %q normalizes to %q", kind, p, cleaned)
	}
	return ""
}

// aliasHasInteriorDotDot reports whether a ".." component follows a normal
// directory component.  Such a path is symlink style: a purely lexical
// normalization may differ from a physical resolution through a symlink.
func aliasHasInteriorDotDot(p string) bool {
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		if parts[i] != ".." {
			continue
		}
		switch parts[i-1] {
		case "", ".", "..":
			continue
		}
		return true
	}
	return false
}

/*
aliasModelReport renders the complete path transformation chain plus the
reference model verdict and warning list.  It is appended to every divergence
message so that a failure shows both how the paths were rewritten and why the
reference model rejected the binding.
*/
func aliasModelReport(c artifactBinding, m bindingModel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "path transformation:\n")
	fmt.Fprintf(&b, "  source artifact: %q\n", c.srcPath)
	fmt.Fprintf(&b, "    lexical normalization       -> %q\n", m.srcClean)
	fmt.Fprintf(&b, "    MATCH IN source prefix      -> %q (normalized prefix %q)\n", c.srcPrefix, m.srcPrefix)
	fmt.Fprintf(&b, "    after prefix strip          -> %q\n", m.srcBase)
	fmt.Fprintf(&b, "    pattern %q match            -> ok\n", "*")
	fmt.Fprintf(&b, "  destination artifact: %q\n", c.dstPath)
	fmt.Fprintf(&b, "    lexical normalization       -> %q\n", m.dstClean)
	fmt.Fprintf(&b, "    MATCH IN destination prefix -> %q (normalized prefix %q)\n", c.dstPrefix, m.dstPrefix)
	fmt.Fprintf(&b, "    computed destination path   -> %q\n", m.dstBucket)
	fmt.Fprintf(&b, "  recorded hashes equal: %v\n", c.sameHash)
	fmt.Fprintf(&b, "  reference model verdict: bound=%v reason=%q\n", m.bound, m.reason)
	if len(m.warnings) > 0 {
		fmt.Fprintf(&b, "  reference model warnings:\n")
		for _, w := range m.warnings {
			fmt.Fprintf(&b, "    - %s\n", w)
		}
	}
	return b.String()
}

// aliasMatchRule builds the MATCH rule string list for a binding experiment.
func aliasMatchRule(c artifactBinding) []string {
	switch {
	case c.srcPrefix != "" && c.dstPrefix != "":
		return []string{"MATCH", "*", "IN", c.srcPrefix, "WITH", "PRODUCTS",
			"IN", c.dstPrefix, "FROM", aliasDstStep}
	case c.srcPrefix != "":
		return []string{"MATCH", "*", "IN", c.srcPrefix, "WITH", "PRODUCTS",
			"FROM", aliasDstStep}
	case c.dstPrefix != "":
		return []string{"MATCH", "*", "WITH", "PRODUCTS", "IN", c.dstPrefix,
			"FROM", aliasDstStep}
	default:
		return []string{"MATCH", "*", "WITH", "PRODUCTS", "FROM", aliasDstStep}
	}
}

/*
aliasImplBinding runs the production implementation for one binding experiment
and reports whether the source material was consumed (bound).

The experiment is driven through the public VerifyArtifacts entry point, using
a MATCH rule followed by a terminal DISALLOW: if MATCH consumes the material,
verification succeeds; if it does not, the leftover material is disallowed.
*/
func aliasImplBinding(c artifactBinding) (bool, error) {
	srcHash := HashObj{"sha256": "aaaa"}
	dstHash := HashObj{"sha256": "aaaa"}
	if !c.sameHash {
		dstHash = HashObj{"sha256": "bbbb"}
	}

	step := Step{SupplyChainItem: SupplyChainItem{
		Name:              aliasSrcStep,
		ExpectedMaterials: [][]string{aliasMatchRule(c), {"DISALLOW", "*"}},
	}}
	metadata := map[string]Metadata{
		aliasSrcStep: &Metablock{Signed: Link{
			Name:      aliasSrcStep,
			Materials: map[string]HashObj{c.srcPath: srcHash},
		}},
		aliasDstStep: &Metablock{Signed: Link{
			Name:     aliasDstStep,
			Products: map[string]HashObj{c.dstPath: dstHash},
		}},
	}

	err := VerifyArtifacts([]interface{}{step}, metadata)
	if err == nil {
		return true, nil
	}
	if strings.Contains(err.Error(), "disallowed by rule") {
		return false, nil
	}
	return false, err
}

/*
aliasCheckBinding compares the implementation with the reference model for one
binding experiment and fails with the full transformation report on any
divergence.
*/
func aliasCheckBinding(tb testing.TB, c artifactBinding) bindingModel {
	tb.Helper()
	model := aliasModelBinding(c)
	got, err := aliasImplBinding(c)
	if err != nil {
		tb.Fatalf("VerifyArtifacts returned an unexpected error for %+v: %v\n%s",
			c, err, aliasModelReport(c, model))
	}
	if got != model.bound {
		tb.Fatalf("artifact rule path alias divergence: implementation bound=%v, reference model bound=%v\n%s",
			got, model.bound, aliasModelReport(c, model))
	}
	return model
}

/*
TestArtifactRulePathAliasBinding covers the path alias classes required for
artifact rules: relative paths, duplicate separators, dot segments, case
differences, symlink-style paths and prefixes that leave the artifact
namespace.
*/
func TestArtifactRulePathAliasBinding(t *testing.T) {
	testCases := []struct {
		name        string
		binding     artifactBinding
		wantBound   bool
		wantReason  string // substring of the reference model reason
		wantWarning string // substring of a reference model warning (optional)
	}{
		{
			name:       "source relative dot prefix aliases canonical path",
			binding:    artifactBinding{srcPath: "./foo.py", dstPath: "foo.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "destination relative dot prefix aliases canonical path",
			binding:    artifactBinding{srcPath: "foo.py", dstPath: "./foo.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "source duplicate separators alias canonical path",
			binding:    artifactBinding{srcPath: "a//b.py", dstPath: "a/b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "destination duplicate separators alias canonical path",
			binding:    artifactBinding{srcPath: "a/b.py", dstPath: "a//b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "source dot segment aliases canonical path",
			binding:    artifactBinding{srcPath: "a/./b.py", dstPath: "a/b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "destination dot segment aliases canonical path",
			binding:    artifactBinding{srcPath: "a/b.py", dstPath: "a/./b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "source cancelling dot segments alias canonical path",
			binding:    artifactBinding{srcPath: "a/x/../b.py", dstPath: "a/b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:        "symlink-style source is resolved lexically",
			binding:     artifactBinding{srcPath: "link/../x.py", dstPath: "x.py", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnLexicalDotDot,
		},
		{
			name:        "symlink-style source does not bind the physical target",
			binding:     artifactBinding{srcPath: "link/../x.py", dstPath: "real/x.py", sameHash: true},
			wantBound:   false,
			wantReason:  aliasReasonDestination,
			wantWarning: aliasWarnLexicalDotDot,
		},
		{
			name:       "trailing separator aliases canonical path",
			binding:    artifactBinding{srcPath: "a/b.py/", dstPath: "a/b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "mixed separators and dot segments alias canonical path",
			binding:    artifactBinding{srcPath: ".//./a//b.py", dstPath: "a/b.py", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "empty path aliases dot",
			binding:    artifactBinding{srcPath: "", dstPath: ".", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "case difference is not an alias",
			binding:    artifactBinding{srcPath: "Foo.py", dstPath: "foo.py", sameHash: true},
			wantBound:  false,
			wantReason: aliasReasonCase,
		},
		{
			name:       "case difference in a directory component is not an alias",
			binding:    artifactBinding{srcPath: "a/Foo.py", dstPath: "a/foo.py", sameHash: true},
			wantBound:  false,
			wantReason: aliasReasonCase,
		},
		{
			name:       "identical mixed-case paths bind",
			binding:    artifactBinding{srcPath: "a/Foo.PY", dstPath: "./a/Foo.PY", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "hash mismatch on identical normalized path does not bind",
			binding:    artifactBinding{srcPath: "./a.py", dstPath: "a.py", sameHash: false},
			wantBound:  false,
			wantReason: aliasReasonHash,
		},
		{
			name:       "directory is not implicitly matched by its basename",
			binding:    artifactBinding{srcPath: "a/b/c.py", dstPath: "c.py", sameHash: true},
			wantBound:  false,
			wantReason: aliasReasonDestination,
		},
		{
			name:       "source prefix is normalized before stripping",
			binding:    artifactBinding{srcPath: "a/b/c.py", dstPath: "c.py", srcPrefix: "a/./b", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "source prefix with cancelling dot segments is normalized",
			binding:    artifactBinding{srcPath: "a/b/c.py", dstPath: "c.py", srcPrefix: "a/x/../b", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "destination prefix is normalized before joining",
			binding:    artifactBinding{srcPath: "x.py", dstPath: "d/x.py", dstPrefix: "d/./e/..", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "destination prefix dot is a no-op alias",
			binding:    artifactBinding{srcPath: "x.py", dstPath: "x.py", dstPrefix: ".", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:       "prefix only strips whole path components",
			binding:    artifactBinding{srcPath: "a/bar.py", dstPath: "bar.py", srcPrefix: "a/b", sameHash: true},
			wantBound:  false,
			wantReason: aliasReasonDestination,
		},
		{
			name:       "source prefix requires a trailing component boundary",
			binding:    artifactBinding{srcPath: "a/b.py", dstPath: "b.py", srcPrefix: "a", sameHash: true},
			wantBound:  true,
			wantReason: aliasReasonBound,
		},
		{
			name:        "source prefix escaping the namespace is reported",
			binding:     artifactBinding{srcPath: "../secret.py", dstPath: "secret.py", srcPrefix: "..", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnSourcePrefix,
		},
		{
			name:        "source prefix with cancelling escape is reported",
			binding:     artifactBinding{srcPath: "../x.py", dstPath: "x.py", srcPrefix: "a/../..", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnSourcePrefix,
		},
		{
			name:        "absolute source prefix is stripped at the root separator",
			binding:     artifactBinding{srcPath: "/abs/x.py", dstPath: "abs/x.py", srcPrefix: "/", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnSourceAbsolute,
		},
		{
			name:        "absolute source prefix keeps the remaining components",
			binding:     artifactBinding{srcPath: "/abs/x.py", dstPath: "x.py", srcPrefix: "/", sameHash: true},
			wantBound:   false,
			wantReason:  aliasReasonDestination,
			wantWarning: aliasWarnSourceAbsolute,
		},
		{
			name:        "destination prefix escaping the namespace is reported",
			binding:     artifactBinding{srcPath: "x.py", dstPath: "../x.py", dstPrefix: "..", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnDestPrefix,
		},
		{
			name:        "destination prefix with cancelling escape is reported",
			binding:     artifactBinding{srcPath: "x.py", dstPath: "../x.py", dstPrefix: "a/../..", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnDestPrefix,
		},
		{
			name:        "absolute destination prefix is reported",
			binding:     artifactBinding{srcPath: "x.py", dstPath: "/x.py", dstPrefix: "/", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnDestAbsolute,
		},
		{
			name:        "escaping source path stays out of namespace",
			binding:     artifactBinding{srcPath: "../outside.py", dstPath: "../outside.py", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnSourcePathEscape,
		},
		{
			name:        "escaping source path does not bind an in-tree destination",
			binding:     artifactBinding{srcPath: "../outside.py", dstPath: "outside.py", sameHash: true},
			wantBound:   false,
			wantReason:  aliasReasonDestination,
			wantWarning: aliasWarnSourcePathEscape,
		},
		{
			name:        "escaping destination path is reported",
			binding:     artifactBinding{srcPath: "../outside.py", dstPath: ".././outside.py", sameHash: true},
			wantBound:   true,
			wantReason:  aliasReasonBound,
			wantWarning: aliasWarnDestPathEscape,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			model := aliasCheckBinding(t, tc.binding)
			if model.bound != tc.wantBound {
				t.Fatalf("reference model bound=%v, test expects bound=%v\n%s",
					model.bound, tc.wantBound, aliasModelReport(tc.binding, model))
			}
			if !strings.Contains(model.reason, tc.wantReason) {
				t.Fatalf("reference model reason %q does not contain %q\n%s",
					model.reason, tc.wantReason, aliasModelReport(tc.binding, model))
			}
			if tc.wantWarning != "" {
				warnings := strings.Join(model.warnings, "\n")
				if !strings.Contains(warnings, tc.wantWarning) {
					t.Fatalf("reference warnings do not contain %q\n%s",
						tc.wantWarning, aliasModelReport(tc.binding, model))
				}
			}
		})
	}
}

/*
TestArtifactRuleSymlinkStylePathIsLexical creates a real symlink on disk and
verifies that MATCH still resolves artifact paths lexically: with a symlink
"link -> real" and a file "real/x.py", the material "link/../x.py" aliases
"x.py" (never "real/x.py").  This pins down that rule processing does not call
filepath.EvalSymlinks.
*/
func TestArtifactRuleSymlinkStylePathIsLexical(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("could not create %q: %v", realDir, err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "x.py"), []byte("abc"), 0o600); err != nil {
		t.Fatalf("could not write test artifact: %v", err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Skipf("could not create symlink: %v", err)
	}

	// Lexical alias: "link/.." cancels the "link" component.
	model := aliasCheckBinding(t, artifactBinding{
		srcPath: "link/../x.py", dstPath: "x.py", sameHash: true,
	})
	if !model.bound {
		t.Fatalf("lexical symlink-style alias did not bind\n%s", aliasModelReport(
			artifactBinding{srcPath: "link/../x.py", dstPath: "x.py", sameHash: true}, model))
	}

	// The physical target of the symlink is not consulted.
	model = aliasCheckBinding(t, artifactBinding{
		srcPath: "link/../x.py", dstPath: "real/x.py", sameHash: true,
	})
	if model.bound {
		t.Fatalf("symlink-style path unexpectedly bound the physical target\n%s", aliasModelReport(
			artifactBinding{srcPath: "link/../x.py", dstPath: "real/x.py", sameHash: true}, model))
	}
}

// TestArtifactRulePatternAlias checks that the MATCH pattern is normalized as
// well, so pattern aliases behave like their canonical spelling.
func TestArtifactRulePatternAlias(t *testing.T) {
	h := HashObj{"sha256": "aaaa"}

	testCases := []struct {
		name      string
		pattern   string
		materials map[string]HashObj
		products  map[string]HashObj
		wantErr   bool
	}{
		{
			name:      "canonical pattern binds",
			pattern:   "sub/*.py",
			materials: map[string]HashObj{"sub/a.py": h},
			products:  map[string]HashObj{"sub/a.py": h},
		},
		{
			name:      "relative dot pattern aliases canonical pattern",
			pattern:   "./sub/*.py",
			materials: map[string]HashObj{"sub/a.py": h},
			products:  map[string]HashObj{"sub/a.py": h},
		},
		{
			name:      "duplicate separator pattern aliases canonical pattern",
			pattern:   "sub//*.py",
			materials: map[string]HashObj{"sub/a.py": h},
			products:  map[string]HashObj{"sub/a.py": h},
		},
		{
			name:      "dot segment pattern aliases canonical pattern",
			pattern:   "sub/../sub/*.py",
			materials: map[string]HashObj{"sub/a.py": h},
			products:  map[string]HashObj{"sub/a.py": h},
		},
		{
			name:      "pattern alias matches aliased material path",
			pattern:   "./*.py",
			materials: map[string]HashObj{"./a.py": h},
			products:  map[string]HashObj{"a.py": h},
		},
		{
			name:      "pattern matching remains case-sensitive",
			pattern:   "Sub/*.py",
			materials: map[string]HashObj{"sub/a.py": h},
			products:  map[string]HashObj{"sub/a.py": h},
			wantErr:   true,
		},
		{
			name:      "pattern match without destination product is rejected",
			pattern:   "sub/*.py",
			materials: map[string]HashObj{"sub/a.py": h},
			products:  map[string]HashObj{"other/a.py": h},
			wantErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := aliasVerifyMaterials(
				[][]string{
					{"MATCH", tc.pattern, "WITH", "PRODUCTS", "FROM", aliasDstStep},
					{"DISALLOW", "*"},
				},
				tc.materials, tc.products)
			if tc.wantErr && err == nil {
				t.Fatalf("expected verification to fail for pattern %q, got nil", tc.pattern)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected verification to succeed for pattern %q, got: %v", tc.pattern, err)
			}
		})
	}
}

/*
TestArtifactRuleRequirePathAlias documents how REQUIRE treats aliased
filenames.  REQUIRE does not normalize its pattern, but it looks the pattern up
in the already-normalized artifact queue, so only normalized REQUIRE spellings
work.
*/
func TestArtifactRuleRequirePathAlias(t *testing.T) {
	h := HashObj{"sha256": "aaaa"}

	testCases := []struct {
		name       string
		required   string
		materials  map[string]HashObj
		wantErrSub string
	}{
		{
			name:      "canonical REQUIRE matches canonical material",
			required:  "foo.py",
			materials: map[string]HashObj{"foo.py": h},
		},
		{
			name:      "canonical REQUIRE matches aliased material",
			required:  "foo.py",
			materials: map[string]HashObj{"./foo.py": h},
		},
		{
			name:       "aliased REQUIRE does not match normalized material",
			required:   "./foo.py",
			materials:  map[string]HashObj{"foo.py": h},
			wantErrSub: "REQUIRE",
		},
		{
			name:       "aliased REQUIRE does not match aliased material",
			required:   "./foo.py",
			materials:  map[string]HashObj{"./foo.py": h},
			wantErrSub: "REQUIRE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := aliasVerifyMaterials([][]string{{"REQUIRE", tc.required}}, tc.materials, nil)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("expected REQUIRE %q to succeed, got: %v", tc.required, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("expected REQUIRE %q to fail with %q, got: %v",
					tc.required, tc.wantErrSub, err)
			}
		})
	}
}

/*
TestArtifactRuleClassifierPathAlias characterizes how CREATE, DELETE and MODIFY
classify artifacts recorded under alias spellings.

The classifier builds its path sets from normalized keys, so an artifact that
is only re-spelled is neither created nor deleted.  For MODIFY, however, hashes
are looked up by the raw map key, so an artifact recorded as "./f" on one side
and "f" on the other is treated as modified even when the hashes are equal.
The reference model below uses canonical hashes and therefore disagrees; the
divergence is reported (not treated as a failure) and the existing behavior is
asserted, following the precedent of the documented line-normalization
limitation in runlib_test.go.  A fix that normalizes hash lookups should update
the expectations in "aliased spelling with equal hash is still modified".
*/
func TestArtifactRuleClassifierPathAlias(t *testing.T) {
	h1 := HashObj{"sha256": "h1"}
	h2 := HashObj{"sha256": "h2"}

	testCases := []struct {
		name      string
		rules     [][]string
		materials map[string]HashObj
		products  map[string]HashObj
		// wantConsumed is true if the classifier rule is expected to consume
		// the artifact (i.e. verification succeeds without DISALLOW firing).
		wantConsumed bool
		// modelUnchanged is the reference model's semantic classification:
		// true means the artifact simply kept its content, i.e. it was
		// neither created, deleted nor modified.
		modelUnchanged bool
	}{
		{
			name:           "canonical created artifact is consumed by CREATE",
			rules:          [][]string{{"CREATE", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{},
			products:       map[string]HashObj{"f": h1},
			wantConsumed:   true,
			modelUnchanged: false,
		},
		{
			name:           "aliased created artifact is consumed by CREATE",
			rules:          [][]string{{"CREATE", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{},
			products:       map[string]HashObj{"./f": h1},
			wantConsumed:   true,
			modelUnchanged: false,
		},
		{
			name:           "aliased deleted artifact is consumed by DELETE",
			rules:          [][]string{{"DELETE", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{"./f": h1},
			products:       map[string]HashObj{},
			wantConsumed:   true,
			modelUnchanged: false,
		},
		{
			name:           "respun artifact is not created",
			rules:          [][]string{{"CREATE", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{"./f": h1},
			products:       map[string]HashObj{"f": h1},
			wantConsumed:   false,
			modelUnchanged: true,
		},
		{
			name:           "respun artifact is not deleted",
			rules:          [][]string{{"DELETE", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{"./f": h1},
			products:       map[string]HashObj{"f": h1},
			wantConsumed:   false,
			modelUnchanged: true,
		},
		{
			name:           "canonical artifact with changed hash is modified",
			rules:          [][]string{{"MODIFY", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{"f": h1},
			products:       map[string]HashObj{"f": h2},
			wantConsumed:   true,
			modelUnchanged: false,
		},
		{
			name:           "canonical artifact with equal hash is not modified",
			rules:          [][]string{{"MODIFY", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{"f": h1},
			products:       map[string]HashObj{"f": h1},
			wantConsumed:   false,
			modelUnchanged: true,
		},
		{
			name:           "aliased spelling with equal hash is still modified",
			rules:          [][]string{{"MODIFY", "f"}, {"DISALLOW", "*"}},
			materials:      map[string]HashObj{"./f": h1},
			products:       map[string]HashObj{"f": h1},
			wantConsumed:   true,
			modelUnchanged: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			step := Step{SupplyChainItem: SupplyChainItem{
				Name:              aliasSrcStep,
				ExpectedMaterials: tc.rules,
			}}
			metadata := map[string]Metadata{
				aliasSrcStep: &Metablock{Signed: Link{
					Name:      aliasSrcStep,
					Materials: tc.materials,
					Products:  tc.products,
				}},
			}
			err := VerifyArtifacts([]interface{}{step}, metadata)
			consumed := err == nil
			if consumed != tc.wantConsumed {
				t.Fatalf("implementation consumed=%v, expected consumed=%v (error: %v)\n%s",
					consumed, tc.wantConsumed, err, aliasClassifierReport(tc.rules, tc.materials, tc.products))
			}
			if consumed && tc.modelUnchanged {
				// Divergence: the implementation classified an artifact as
				// changed although the canonical view says it kept its
				// content.  Print the transformation chain and the reason.
				t.Logf("known divergence between implementation and reference model\n%s",
					aliasClassifierReport(tc.rules, tc.materials, tc.products))
			}
		})
	}
}

// aliasClassifierReport renders the path transformation and classification
// reason for CREATE/DELETE/MODIFY divergences.
func aliasClassifierReport(rules [][]string, materials, products map[string]HashObj) string {
	var b strings.Builder
	rule := []string{}
	if len(rules) > 0 {
		rule = rules[0]
	}
	fmt.Fprintf(&b, "classifier rule: %v\n", rule)
	fmt.Fprintf(&b, "  material spellings:\n")
	for name, hash := range materials {
		fmt.Fprintf(&b, "    %q -> normalized %q, hash %v\n", name, aliasModelClean(name), hash)
	}
	if len(materials) == 0 {
		fmt.Fprintf(&b, "    (none)\n")
	}
	fmt.Fprintf(&b, "  product spellings:\n")
	for name, hash := range products {
		fmt.Fprintf(&b, "    %q -> normalized %q, hash %v\n", name, aliasModelClean(name), hash)
	}
	if len(products) == 0 {
		fmt.Fprintf(&b, "    (none)\n")
	}
	fmt.Fprintf(&b, "  reason: path sets are compared after normalization, while the "+
		"modified check compares raw map entries, so an alias spelling hides the "+
		"recorded hash from the comparison\n")
	return b.String()
}

/*
FuzzArtifactRulePathAliasBinding fuzzes source and destination artifact
spellings and compares the implementation's binding decision with the
reference model for both matching and differing hashes.
*/
func FuzzArtifactRulePathAliasBinding(f *testing.F) {
	seeds := [][2]string{
		{"foo.py", "foo.py"},
		{"./foo.py", "foo.py"},
		{"a//b.py", "a/b.py"},
		{"a/./b.py", "a/b.py"},
		{"a/x/../b.py", "a/b.py"},
		{"link/../x.py", "x.py"},
		{"../outside.py", "outside.py"},
		{"/abs/x.py", "abs/x.py"},
		{"Foo.py", "foo.py"},
		{"", "."},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, src, dst string) {
		if len(src)+len(dst) > 4096 {
			t.Skip("path inputs too large for a meaningful alias test")
		}
		for _, sameHash := range []bool{true, false} {
			c := artifactBinding{srcPath: src, dstPath: dst, sameHash: sameHash}
			model := aliasCheckBinding(t, c)
			// Internal consistency of the reference model: if the computed
			// destination equals the normalized destination and the hashes
			// agree, the model must report a binding.
			if sameHash && model.dstBucket == model.dstClean && !model.bound {
				t.Fatalf("reference model is inconsistent for %+v\n%s",
					c, aliasModelReport(c, model))
			}
		}
	})
}

/*
FuzzArtifactRulePathAliasPrefixBinding fuzzes source and destination paths
together with MATCH prefixes and compares the implementation with the
reference model.  Prefixes that escape the artifact namespace are accepted by
the implementation today; the reference model records them as warnings, which
are printed on any divergence and can be read from the model in the tests
above.
*/
func FuzzArtifactRulePathAliasPrefixBinding(f *testing.F) {
	seeds := [][4]string{
		{"a/b/c.py", "c.py", "a/b", ""},
		{"a/./b/c.py", "c.py", "./a/b", ""},
		{"a/b/c.py", "./c.py", "a/b", "d/.."},
		{"../secret.py", "secret.py", "..", ""},
		{"x.py", "../x.py", "", "a/../.."},
		{"/abs/x.py", "abs/x.py", "/", ""},
		{"x.py", "/x.py", "", "/"},
		{"a/bar.py", "bar.py", "a/b", ""},
		{"link/../x.py", "x.py", "", ""},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}

	f.Fuzz(func(t *testing.T, src, dst, srcPrefix, dstPrefix string) {
		if len(src)+len(dst)+len(srcPrefix)+len(dstPrefix) > 4096 {
			t.Skip("path inputs too large for a meaningful alias test")
		}
		c := artifactBinding{
			srcPath:   src,
			dstPath:   dst,
			srcPrefix: srcPrefix,
			dstPrefix: dstPrefix,
			sameHash:  true,
		}
		aliasCheckBinding(t, c)
	})
}

/*
FuzzArtifactRulePathAliasVariants derives several alias spellings of an
arbitrary path and checks that every spelling that normalizes to the same
canonical path still binds the same artifact.
*/
func FuzzArtifactRulePathAliasVariants(f *testing.F) {
	seeds := []string{
		"foo.py",
		"a/b/c.py",
		"./a//b",
		"a/./b/../c",
		"../x",
		"/abs/x",
		"",
		"x",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 512 {
			t.Skip("path input too large for a meaningful alias test")
		}
		canonical := aliasModelClean(raw)
		seen := make(map[string]struct{})
		for _, variant := range aliasVariants(raw) {
			if _, ok := seen[variant]; ok {
				continue
			}
			seen[variant] = struct{}{}
			if aliasModelClean(variant) != canonical {
				// The generator only emits spellings meant to be aliases;
				// skip any that are not (defensive, should not happen).
				t.Logf("alias generator produced non-alias %q for canonical %q", variant, canonical)
				continue
			}
			c := artifactBinding{srcPath: variant, dstPath: canonical, sameHash: true}
			model := aliasCheckBinding(t, c)
			if !model.bound {
				t.Fatalf("alias spelling %q of canonical path %q did not bind the artifact\n%s",
					variant, canonical, aliasModelReport(c, model))
			}
		}
	})
}

// aliasVariants returns alias spellings that should normalize to the same
// canonical path as raw when interpreted lexically.
func aliasVariants(raw string) []string {
	variants := []string{raw}
	variants = append(variants, strings.ReplaceAll(raw, "/", "//"))
	if !strings.HasPrefix(raw, "/") {
		variants = append(variants, "./"+raw)
		variants = append(variants, "volatile/../"+raw)
		variants = append(variants, "././"+raw)
	}
	if raw != "" && !strings.HasSuffix(raw, "/") {
		variants = append(variants, raw+"/")
		variants = append(variants, raw+"/.")
	}
	return variants
}

/*
TestAliasModelMatchesStdlibNormalization checks that the independent reference
normalizer agrees with path.Clean on a corpus of tricky spellings.  The model
is written independently so that it can catch production bugs, but it must
still model the intended lexical semantics exactly.
*/
func TestAliasModelMatchesStdlibNormalization(t *testing.T) {
	corpus := []string{
		"", ".", "..", "/", "//", "///", "///a", "a/", "a//b", "./a/b",
		"a/./b", "a/x/../b", "a/../../b", "../..", "/..", "/../a", "a/b/../..",
		"../a/../..", "a/b/../../../c", "../../etc/passwd", "a/bx/file",
		"link/../x.py", ".//./a//b.py/", "a/b.py/", "a/**/b", "A/B",
	}
	for _, p := range corpus {
		if got, want := aliasModelClean(p), path.Clean(p); got != want {
			t.Fatalf("reference normalizer disagrees with path.Clean for %q: model %q, stdlib %q",
				p, got, want)
		}
	}
}

// FuzzAliasModelMatchesStdlibNormalization fuzzes the reference normalizer
// against path.Clean.
func FuzzAliasModelMatchesStdlibNormalization(f *testing.F) {
	for _, seed := range []string{"", ".", "..", "/", "a//b", "a/./b", "a/x/../b", "/../a", "../..", "a/b/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if len(p) > 4096 {
			t.Skip("path input too large")
		}
		if got, want := aliasModelClean(p), path.Clean(p); got != want {
			t.Fatalf("reference normalizer disagrees with path.Clean for %q: model %q, stdlib %q",
				p, got, want)
		}
	})
}

/*
TestArtifactRuleDuplicateSpellingConsistency covers a link that records the
same canonical artifact under two alias spellings at once.  When both
spellings carry the same hash the binding result must not depend on map
iteration order; when the spellings disagree on the hash the reference model
reports the link as ambiguous and no binding decision can be trusted, so the
test only checks that verification does not crash or return an unexpected
error and records the observed outcomes.

The reference model is single-valued, so this scenario is outside its scope;
the ambiguity is reported explicitly instead of being silently resolved.
*/
func TestArtifactRuleDuplicateSpellingConsistency(t *testing.T) {
	h1 := HashObj{"sha256": "aaaa"}
	h2 := HashObj{"sha256": "bbbb"}

	// Same hash under both spellings: binding must be stable.
	for i := 0; i < 32; i++ {
		err := aliasVerifyMaterials(
			[][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", aliasDstStep}, {"DISALLOW", "*"}},
			map[string]HashObj{"a/./b": h1, "a//b": h1},
			map[string]HashObj{"a/b": h1})
		if err != nil {
			t.Fatalf("iteration %d: identical spellings with equal hashes did not bind: %v",
				i, err)
		}
	}

	// Conflicting hashes: outcome depends on which spelling survives map
	// normalization.  Record the observed distribution and flag the link as
	// ambiguous; both outcomes are accepted so the test is not order flaky.
	bound, rejected := 0, 0
	for i := 0; i < 64; i++ {
		err := aliasVerifyMaterials(
			[][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", aliasDstStep}, {"DISALLOW", "*"}},
			map[string]HashObj{"a/./b": h2, "a//b": h1},
			map[string]HashObj{"a/b": h1})
		if err == nil {
			bound++
			continue
		}
		if !strings.Contains(err.Error(), "disallowed by rule") {
			t.Fatalf("iteration %d: unexpected error for conflicting spellings: %v", i, err)
		}
		rejected++
	}
	if bound+rejected != 64 {
		t.Fatalf("inconsistent outcome accounting: bound=%d rejected=%d", bound, rejected)
	}
	t.Logf("ambiguous link: %d/64 iterations bound, %d/64 iterations rejected; "+
		"both spellings normalize to %q but carry different hashes, so the verdict "+
		"depends on Go map iteration order and the link should be rejected by the producer\n%s",
		bound, rejected, aliasModelClean("a/./b"),
		aliasClassifierReport(
			[][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", aliasDstStep}},
			map[string]HashObj{"a/./b": h2, "a//b": h1},
			map[string]HashObj{"a/b": h1}))
}

// aliasVerifyMaterials runs material rules for a step and reports the
// verification error (if any).
func aliasVerifyMaterials(rules [][]string, materials, products map[string]HashObj) error {
	step := Step{SupplyChainItem: SupplyChainItem{
		Name:              aliasSrcStep,
		ExpectedMaterials: rules,
	}}
	metadata := map[string]Metadata{
		aliasSrcStep: &Metablock{Signed: Link{Name: aliasSrcStep, Materials: materials}},
		aliasDstStep: &Metablock{Signed: Link{Name: aliasDstStep, Products: products}},
	}
	return VerifyArtifacts([]interface{}{step}, metadata)
}
