package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/umutciftci/nazar/internal/osv"
)

// SARIF 2.1.0 output for GitHub/GitLab security tab integration.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifText           `json:"shortDescription"`
	HelpURI          string              `json:"helpUri"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

// RenderSARIF writes a SARIF 2.1.0 document to w. Each (package, vuln) pair
// becomes one result pointing at the lockfile that introduced it.
func RenderSARIF(w io.Writer, root string, results []Result, toolVersion string) error {
	// Collect unique rules (one per vuln ID).
	ruleIndex := map[string]int{}
	var rules []sarifRule
	for _, r := range results {
		for _, pv := range r.Packages {
			for _, v := range pv.Vulns {
				if _, seen := ruleIndex[v.ID]; seen {
					continue
				}
				ruleIndex[v.ID] = len(rules)
				summary := v.Summary
				if summary == "" {
					summary = v.ID
				}
				rules = append(rules, sarifRule{
					ID:               v.ID,
					Name:             v.ID,
					ShortDescription: sarifText{Text: summary},
					HelpURI:          "https://osv.dev/vulnerability/" + v.ID,
					Properties:       sarifRuleProperties{SecuritySeverity: sarifCVSSScore(v.Severity)},
				})
			}
		}
	}

	// Build results.
	var sarifResults []sarifResult
	for _, r := range results {
		// Make lockfile URI relative to root.
		lockRel, err := filepath.Rel(root, r.Project.LockfilePath)
		if err != nil || strings.HasPrefix(lockRel, "..") {
			lockRel = r.Project.LockfilePath
		}
		// SARIF URIs use forward slashes.
		lockURI := filepath.ToSlash(lockRel)

		for _, pv := range r.Packages {
			for _, v := range pv.Vulns {
				msg := fmt.Sprintf("Vulnerable package: %s@%s", pv.Package.Name, pv.Package.Version)
				if v.FixedIn != "" {
					msg += fmt.Sprintf(" (fix: upgrade to %s)", v.FixedIn)
				}
				sarifResults = append(sarifResults, sarifResult{
					RuleID: v.ID,
					Level:  sarifLevel(v.Severity),
					Message: sarifText{Text: msg},
					Locations: []sarifLocation{{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{
								URI:       lockURI,
								URIBaseID: "%SRCROOT%",
							},
						},
					}},
				})
			}
		}
	}

	doc := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "nazar",
				Version:        toolVersion,
				InformationURI: "https://github.com/umutciftci/nazar",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps a Severity bucket to a SARIF result level.
func sarifLevel(s osv.Severity) string {
	switch s {
	case osv.SeverityCritical, osv.SeverityHigh:
		return "error"
	case osv.SeverityMedium:
		return "warning"
	case osv.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// sarifCVSSScore returns a representative numeric CVSS score for the
// security-severity property used by GitHub Code Scanning.
func sarifCVSSScore(s osv.Severity) string {
	switch s {
	case osv.SeverityCritical:
		return "9.5"
	case osv.SeverityHigh:
		return "7.5"
	case osv.SeverityMedium:
		return "5.0"
	case osv.SeverityLow:
		return "2.0"
	default:
		return ""
	}
}
