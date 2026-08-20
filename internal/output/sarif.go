package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gosleek/gosleek/pkg/types"
)

// SARIF (Static Analysis Results Interchange Format) output for CI/IDE integration.
// https://sarifweb.azurewebsites.net/

// SARIFReport is the top-level SARIF structure.
type SARIFReport struct {
	Schema  string         `json:"$schema"`
	Version string         `json:"version"`
	Runs    []SARIFRun     `json:"runs"`
}

// SARIFRun represents a single scan run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver holds tool metadata.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule maps to a gosleek template.
type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFDescription `json:"shortDescription"`
	FullDescription  SARIFDescription `json:"fullDescription"`
	DefaultLevel     string           `json:"defaultLevel"`
	HelpURI          string           `json:"helpUri,omitempty"`
}

// SARIFDescription holds rule text.
type SARIFDescription struct {
	Text string `json:"text"`
}

// SARIFResult is a single finding.
type SARIFResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    SARIFMessage      `json:"message"`
	Locations  []SARIFLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	CodeFlows  []SARIFCodeFlow   `json:"codeFlows,omitempty"`
}

// SARIFCodeFlow holds a single code flow with one thread flow.
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

// SARIFThreadFlow holds the sequence of message locations in a flow.
type SARIFThreadFlow struct {
	Messages []SARIFMessage `json:"messages"`
}

// SARIFMessage holds result message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation pinpoints the finding.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation holds URL and region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation holds the target URL.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

func writeSARIF(results []*types.Result, path string, toolVersion string) error {
	version := toolVersion
	if version == "" {
		version = "unknown"
	}
	report := SARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "gosleek",
						Version:        version,
						InformationURI: "https://github.com/gosleek/gosleek",
					},
				},
			},
		},
	}

	rules := make(map[string]bool)
	var sarifResults []SARIFResult

	for _, r := range results {
		if !rules[r.TemplateID] {
			rules[r.TemplateID] = true
			rule := SARIFRule{
				ID:               r.TemplateID,
				Name:             r.Name,
				ShortDescription: SARIFDescription{Text: r.Description},
				FullDescription:  SARIFDescription{Text: r.Description},
				DefaultLevel:     severityToSARIFLevel(r.Severity),
				HelpURI:          buildHelpURI(r),
			}
			report.Runs[0].Tool.Driver.Rules = append(report.Runs[0].Tool.Driver.Rules, rule)
		}

		msg := r.Evidence
		if msg == "" {
			msg = r.Description
		}

		// Build fingerprint for deduplication
		fp := make(map[string]string)
		if r.RawRequest != "" {
			fp["request_sha256"] = sha256hex(r.RawRequest)
		}
		if r.RawResponse != "" {
			fp["response_sha256"] = sha256hex(r.RawResponse)
		}

		// Build code flow: request → response
		var codeFlows []SARIFCodeFlow
		if r.RawRequest != "" || r.RawResponse != "" {
			var msgs []SARIFMessage
			if r.RawRequest != "" {
				msgs = append(msgs, SARIFMessage{Text: "Request: " + truncate(r.RawRequest, 200)})
			}
			if r.RawResponse != "" {
				msgs = append(msgs, SARIFMessage{Text: "Response: " + truncate(r.RawResponse, 200)})
			}
			if len(msgs) > 0 {
				codeFlows = []SARIFCodeFlow{{ThreadFlows: []SARIFThreadFlow{{Messages: msgs}}}}
			}
		}

		sarifResults = append(sarifResults, SARIFResult{
			RuleID:       r.TemplateID,
			Level:        severityToSARIFLevel(r.Severity),
			Message:      SARIFMessage{Text: msg},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: r.Target},
					},
				},
			},
			Fingerprints: fp,
			CodeFlows:    codeFlows,
		})
	}

	report.Runs[0].Results = sarifResults

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func buildHelpURI(r *types.Result) string {
	if len(r.Reference) > 0 {
		return r.Reference[0]
	}
	return ""
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func severityToSARIFLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}
