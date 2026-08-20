package plugin

import (
	"strings"
)

// FilterOptions carries the filter predicates applied to a plugin list.
type FilterOptions struct {
	TemplateIDs []string // also used for plugin IDs when filtering
	Tags        []string
	Severity    []string
	ExcludeIDs  []string
}

// Filter returns the subset of plugins matching the given options.
// The logic mirrors the filtering done in the scan/list command entrypoints,
// so both paths share a single implementation.
func Filter(plugins []Plugin, opts FilterOptions) []Plugin {
	if len(opts.TemplateIDs) == 0 && len(opts.Tags) == 0 &&
		len(opts.Severity) == 0 && len(opts.ExcludeIDs) == 0 {
		return plugins
	}

	out := make([]Plugin, 0, len(plugins))
	for _, p := range plugins {
		meta := p.Meta()
		// By ID
		if len(opts.TemplateIDs) > 0 {
			found := false
			for _, id := range opts.TemplateIDs {
				if strings.EqualFold(meta.ID, id) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		// By tag
		if len(opts.Tags) > 0 {
			found := false
			for _, tag := range opts.Tags {
				for _, pt := range meta.Tags {
					if strings.EqualFold(tag, pt) {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
		}
		// By severity
		if len(opts.Severity) > 0 {
			found := false
			for _, sev := range opts.Severity {
				if strings.EqualFold(sev, meta.Severity) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		// Exclude
		excluded := false
		for _, eid := range opts.ExcludeIDs {
			if strings.EqualFold(eid, meta.ID) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		out = append(out, p)
	}
	return out
}
