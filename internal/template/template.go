package template

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gosleek/gosleek/pkg/types"
	"gopkg.in/yaml.v3"
)

// LoadDir loads all YAML templates from a directory (recursively).
func LoadDir(dir string) ([]*types.Template, error) {
	var templates []*types.Template
	var walkErr error
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		// Walk errors (e.g., permission denied on a subdirectory) are
		// logged but not fatal — we skip the problematic entry and
		// continue walking the rest of the tree.
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] 跳过目录遍历错误 %s: %v\n", path, err)
			// Remember the error but don't abort the walk.
			// We'll return it after collecting whatever templates we could.
			walkErr = err
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		tmpl, err := LoadFile(path)
		if err != nil {
			// Don't fail the whole scan for one bad template, but warn so
			// the failure isn't silently lost (e.g. a typo'd YAML field or
			// a misplaced template file).
			fmt.Fprintf(os.Stderr, "[WARN] 跳过无法加载的模板 %s: %v\n", path, err)
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	// Walk itself returning an error (e.g. root dir doesn't exist) takes
	// precedence over any walkErr we collected inside the callback.
	if err != nil {
		return nil, err
	}
	if walkErr != nil {
		return templates, walkErr
	}
	return templates, nil
}

// LoadFile loads a single template YAML file.
func LoadFile(path string) (*types.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tmpl types.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	tmpl.FilePath = path
	tmpl.SHA256 = Sign(data)
	// default matchers-condition
	if tmpl.MatchersCondition == "" {
		tmpl.MatchersCondition = "or"
	}
	for i := range tmpl.HTTP {
		if tmpl.HTTP[i].MatchersCondition == "" {
			tmpl.HTTP[i].MatchersCondition = "or"
		}
	}
	return &tmpl, nil
}

// Sign computes the SHA256 hash of the raw template bytes.
func Sign(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// VerifySign verifies a template's SHA256 against an expected hash.
func VerifySign(data []byte, expectedSHA string) bool {
	return Sign(data) == expectedSHA
}

// FilterByTag returns templates matching any of the given tags.
func FilterByTag(templates []*types.Template, tags []string) []*types.Template {
	if len(tags) == 0 {
		return templates
	}
	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = true
	}
	var out []*types.Template
	for _, tmpl := range templates {
		for _, t := range tmpl.Tags {
			if tagSet[strings.ToLower(t)] {
				out = append(out, tmpl)
				break
			}
		}
	}
	return out
}

// FilterBySeverity returns templates matching any of the given severities.
func FilterBySeverity(templates []*types.Template, severities []string) []*types.Template {
	if len(severities) == 0 {
		return templates
	}
	sevSet := make(map[string]bool)
	for _, s := range severities {
		sevSet[strings.ToLower(s)] = true
	}
	var out []*types.Template
	for _, tmpl := range templates {
		if sevSet[strings.ToLower(tmpl.Severity)] {
			out = append(out, tmpl)
		}
	}
	return out
}

// FilterByID returns templates matching any of the given IDs.
func FilterByID(templates []*types.Template, ids []string) []*types.Template {
	if len(ids) == 0 {
		return templates
	}
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[strings.ToLower(id)] = true
	}
	var out []*types.Template
	for _, tmpl := range templates {
		if idSet[strings.ToLower(tmpl.ID)] {
			out = append(out, tmpl)
		}
	}
	return out
}

// ExcludeByID removes templates with matching IDs.
func ExcludeByID(templates []*types.Template, ids []string) []*types.Template {
	if len(ids) == 0 {
		return templates
	}
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[strings.ToLower(id)] = true
	}
	var out []*types.Template
	for _, tmpl := range templates {
		if !idSet[strings.ToLower(tmpl.ID)] {
			out = append(out, tmpl)
		}
	}
	return out
}

// SortBySeverity sorts templates by severity (critical first).
func SortBySeverity(templates []*types.Template) {
	sort.SliceStable(templates, func(i, j int) bool {
		return types.SeverityRank[strings.ToLower(templates[i].Severity)] >
			types.SeverityRank[strings.ToLower(templates[j].Severity)]
	})
}
