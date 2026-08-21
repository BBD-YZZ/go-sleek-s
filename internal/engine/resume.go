package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResumeState tracks scan progress for interrupt/resume.
type ResumeState struct {
	StartTime   time.Time         `json:"start_time"`
	Completed   []string          `json:"completed"` // "target|templateID"
	Targets     []string          `json:"targets"`
	TemplateIDs []string          `json:"template_ids"`
	mu          sync.Mutex
	filePath    string
	// throttleSave prevents flooding the fs when many tasks complete quickly.
	// LastSaveTime is atomic so the periodic saver can read it lock-free;
	// the actual mutation is protected by mu.
	lastSaveTime atomic.Value // time.Time
	saveInterval time.Duration
}

// NewResumeState creates or loads a resume state.
func NewResumeState(path string) *ResumeState {
	rs := &ResumeState{
		filePath:     path,
		saveInterval: 5 * time.Second, // write at most every 5s
	}
	rs.lastSaveTime.Store(time.Time{})
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			json.Unmarshal(data, rs)
		}
	}
	return rs
}

// MarkDone records a completed (target, template) pair.
func (rs *ResumeState) MarkDone(target, templateID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	key := target + "|" + templateID
	rs.Completed = append(rs.Completed, key)
}

// IsDone checks if a (target, template) pair was already completed.
func (rs *ResumeState) IsDone(target, templateID string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	key := target + "|" + templateID
	for _, c := range rs.Completed {
		if c == key {
			return true
		}
	}
	return false
}

// Save writes the resume state to disk. Thread-safe.
func (rs *ResumeState) Save() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.filePath == "" {
		return nil
	}
	// Deduplicate before saving to avoid redundant entries
	seen := make(map[string]bool, len(rs.Completed))
	deduped := rs.Completed[:0]
	for _, c := range rs.Completed {
		if !seen[c] {
			seen[c] = true
			deduped = append(deduped, c)
		}
	}
	rs.Completed = deduped
	dir := filepath.Dir(rs.filePath)
	_ = os.MkdirAll(dir, 0755)
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(rs.filePath, data, 0644); err != nil {
		return err
	}
	rs.lastSaveTime.Store(time.Now())
	return nil
}

// TrySave atomically checks whether enough time has elapsed and saves if so.
// This eliminates the TOCTOU race that would occur with separate ShouldSave()+Save() calls.
// Returns true if a save was performed, false if the throttle interval has not elapsed.
func (rs *ResumeState) TrySave() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	last := rs.lastSaveTime.Load().(time.Time)
	if time.Since(last) < rs.saveInterval {
		return false
	}
	if rs.filePath == "" {
		return false
	}
	dir := filepath.Dir(rs.filePath)
	_ = os.MkdirAll(dir, 0755)
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return false
	}
	if err := os.WriteFile(rs.filePath, data, 0644); err != nil {
		return false
	}
	rs.lastSaveTime.Store(time.Now())
	return true
}

// SetSaveInterval adjusts the throttling window. Defaults to 5s.
func (rs *ResumeState) SetSaveInterval(d time.Duration) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.saveInterval = d
}

// FilterPending returns (targets, templateIDs) that haven't been completed.
// Returns empty slices if ALL pairs are already done.
func (rs *ResumeState) FilterPending(targets, templateIDs []string) ([]string, []string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if len(rs.Completed) == 0 {
		return targets, templateIDs
	}

	done := make(map[string]bool, len(rs.Completed))
	for _, c := range rs.Completed {
		done[c] = true
	}

	// Check each pair individually
	var pendingTargets []string
	for _, t := range targets {
		allDone := true
		for _, tid := range templateIDs {
			if !done[t+"|"+tid] {
				allDone = false
				break
			}
		}
		if !allDone {
			pendingTargets = append(pendingTargets, t)
		}
	}

	// Also filter templateIDs per target
	var pendingTemplates []string
	if len(pendingTargets) > 0 && len(templateIDs) > 0 {
		// Build a set of all pending pairs
		pendingPairs := make(map[string]bool)
		for _, t := range pendingTargets {
			for _, tid := range templateIDs {
				pendingPairs[t+"|"+tid] = true
			}
		}
		// Keep only templateIDs that have at least one pending pair
		for _, tid := range templateIDs {
			hasPending := false
			for _, t := range pendingTargets {
				if pendingPairs[t+"|"+tid] {
					hasPending = true
					break
				}
			}
			if hasPending {
				pendingTemplates = append(pendingTemplates, tid)
			}
		}
	}

	return pendingTargets, pendingTemplates
}

// Summary returns a human-readable state summary.
func (rs *ResumeState) Summary() string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return fmt.Sprintf("resume: %d completed, %d targets, %d templates",
		len(rs.Completed), len(rs.Targets), len(rs.TemplateIDs))
}

// Clear deletes the resume file.
func (rs *ResumeState) Clear() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.filePath == "" {
		return nil
	}
	rs.Completed = nil
	rs.Targets = nil
	rs.TemplateIDs = nil
	return os.Remove(rs.filePath)
}

// ParseTargetTemplateIDs parses a list of "target|templateID" strings.
func ParseTargetTemplateIDs(items []string) (targets, templateIDs []string) {
	for _, item := range items {
		parts := strings.SplitN(item, "|", 2)
		if len(parts) == 2 {
			targets = append(targets, parts[0])
			templateIDs = append(templateIDs, parts[1])
		}
	}
	return
}

// SplitPair splits a "target|templateID" string into its components.
// Exported so cmd/gosleek can reuse this instead of duplicating the logic.
func SplitPair(pair string) (target, templateID string) {
	idx := strings.Index(pair, "|")
	if idx < 0 {
		return pair, ""
	}
	return pair[:idx], pair[idx+1:]
}
