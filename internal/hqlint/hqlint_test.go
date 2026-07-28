package hqlint

// Structural lint for the hq/ headquarters layout.
//
// Enforces the invariants promised in hq/00-GENESIS/how-we-work.md: the five
// areas exist with their READMEs, research topics carry legal non-terminal
// states (no graduated/abandoned folder lingers), journey episodes are
// contiguously numbered from 0001 and indexed, every episode records its
// reversal condition, the constitution carries its canonical heading, and
// relative markdown links inside hq/ resolve. A frozen 99-ARCHIVE subtree is
// permitted as an extra area and is excluded from the link check — it is
// superseded material, not the live design.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var (
	areas        = []string{"00-GENESIS", "01-RESEARCH", "02-DESIGN", "03-IMPLEMENTATION", "04-JOURNEY"}
	genesisFiles = []string{"README.md", "vision.md", "constitution.md", "how-we-work.md"}
	legalStates  = map[string]bool{"active": true, "graduated": true, "abandoned": true}
	terminal     = map[string]bool{"graduated": true, "abandoned": true}
	nonEpisode   = map[string]bool{"README.md": true, "TEMPLATE.md": true}

	episodeRe = regexp.MustCompile(`^\d{4}-[a-z0-9-]+\.md$`)
	stateRe   = regexp.MustCompile(`(?m)^\*\*State:\*\* *(\S+)`)
	linkRe    = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)\)`)
)

// repoRoot resolves the repository root from this test file's own location
// (<root>/internal/hqlint/hqlint_test.go), so the lint works from any working
// directory, locally and in CI.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func mustFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		t.Errorf("missing required file: %s", path)
	}
}

// episodes lists the episode files in hq/04-JOURNEY (everything that is not a
// README/TEMPLATE), sorted by name.
func episodes(t *testing.T, hq string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(hq, "04-JOURNEY"))
	if err != nil {
		t.Fatalf("reading hq/04-JOURNEY: %v", err)
	}
	var eps []string
	for _, e := range entries {
		if e.IsDir() || nonEpisode[e.Name()] {
			continue
		}
		eps = append(eps, e.Name())
	}
	sort.Strings(eps)
	return eps
}

func TestHQAreasExistWithReadmes(t *testing.T) {
	hq := filepath.Join(repoRoot(t), "hq")
	mustFile(t, filepath.Join(hq, "README.md"))
	for _, area := range areas {
		mustFile(t, filepath.Join(hq, area, "README.md"))
	}
	for _, name := range genesisFiles {
		mustFile(t, filepath.Join(hq, "00-GENESIS", name))
	}
	mustFile(t, filepath.Join(hq, "01-RESEARCH", "TEMPLATE.md"))
	mustFile(t, filepath.Join(hq, "04-JOURNEY", "TEMPLATE.md"))
}

func TestResearchTopicsHaveLegalNonterminalStates(t *testing.T) {
	research := filepath.Join(repoRoot(t), "hq", "01-RESEARCH")
	entries, err := os.ReadDir(research)
	if err != nil {
		t.Fatalf("reading hq/01-RESEARCH: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(research, e.Name(), "README.md"))
		if err != nil {
			t.Errorf("%s: research topic without README.md", e.Name())
			continue
		}
		text := string(data)
		if !strings.HasPrefix(strings.TrimLeft(text, " \n\t"), "# ") {
			t.Errorf("%s: README lacks a title", e.Name())
		}
		if !strings.Contains(text, "## Abstract") {
			t.Errorf("%s: README lacks an Abstract section", e.Name())
		}
		m := stateRe.FindStringSubmatch(text)
		if m == nil {
			t.Errorf("%s: README lacks a '**State:** ...' line", e.Name())
			continue
		}
		state := m[1]
		switch {
		case !legalStates[state]:
			t.Errorf("%s: illegal state %q", e.Name(), state)
		case terminal[state]:
			t.Errorf("%s: state %q is terminal but the folder lingers — "+
				"/research-graduate removes the topic folder on every outcome", e.Name(), state)
		}
	}
}

func TestJourneyEpisodesNumberedContiguously(t *testing.T) {
	eps := episodes(t, filepath.Join(repoRoot(t), "hq"))
	var nums []int
	for _, name := range eps {
		if !episodeRe.MatchString(name) {
			t.Errorf("file in hq/04-JOURNEY that is not an NNNN-slug.md episode: %s", name)
			continue
		}
		n, _ := strconv.Atoi(name[:4])
		nums = append(nums, n)
	}
	seen := map[int]bool{}
	for _, n := range nums {
		if seen[n] {
			t.Errorf("duplicate episode number: %04d", n)
		}
		seen[n] = true
	}
	sort.Ints(nums)
	for i, n := range nums {
		if n != i+1 {
			t.Errorf("episode numbers not contiguous from 0001: %v", nums)
			break
		}
	}
}

func TestJourneyEpisodesAreIndexed(t *testing.T) {
	hq := filepath.Join(repoRoot(t), "hq")
	data, err := os.ReadFile(filepath.Join(hq, "04-JOURNEY", "README.md"))
	if err != nil {
		t.Fatalf("reading hq/04-JOURNEY/README.md: %v", err)
	}
	index := string(data)
	for _, name := range episodes(t, hq) {
		if !strings.Contains(index, name) {
			t.Errorf("episode missing from the hq/04-JOURNEY/README.md index: %s", name)
		}
	}
}

func TestJourneyEpisodesRecordReversalCondition(t *testing.T) {
	hq := filepath.Join(repoRoot(t), "hq")
	dir := filepath.Join(hq, "04-JOURNEY")
	for _, name := range episodes(t, hq) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.Contains(string(data), "Reversal condition:") {
			t.Errorf("episode without the required 'Reversal condition:' line: %s "+
				"(see hq/04-JOURNEY/TEMPLATE.md)", name)
		}
	}
}

func TestConstitutionIsCanonical(t *testing.T) {
	canonical := filepath.Join(repoRoot(t), "hq", "00-GENESIS", "constitution.md")
	data, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("reading canonical constitution: %v", err)
	}
	if !strings.Contains(string(data), "# SoulIdentity Constitution") {
		t.Error("canonical constitution missing its '# SoulIdentity Constitution' heading")
	}
}

func TestHQRelativeLinksResolve(t *testing.T) {
	root := repoRoot(t)
	hq := filepath.Join(root, "hq")
	var broken []string
	err := filepath.WalkDir(hq, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "99-ARCHIVE" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range linkRe.FindAllStringSubmatch(string(data), -1) {
			target := m[1]
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
				continue
			}
			p, _, _ := strings.Cut(target, "#")
			if p == "" {
				continue
			}
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(path), p)); statErr != nil {
				rel, _ := filepath.Rel(root, path)
				broken = append(broken, rel+" -> "+target)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking hq/: %v", err)
	}
	if len(broken) > 0 {
		t.Errorf("broken relative markdown links inside hq/:\n%s", strings.Join(broken, "\n"))
	}
}
