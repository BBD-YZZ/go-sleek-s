package fingerprint

import (
	"testing"

	"github.com/gosleek/gosleek/pkg/types"
)

func makeFp(titles []string, headers map[string]string, server, body string) *TargetFingerprint {
	return &TargetFingerprint{
		Titles:  titles,
		Headers: headers,
		Server:  server,
		Body:    body,
	}
}

func TestMatches_NoRules(t *testing.T) {
	fp := makeFp([]string{"Test"}, map[string]string{"Server": "nginx"}, "nginx", "body")
	d := &Detector{}
	if !d.Matches(fp, nil) {
		t.Error("nil rules should always match")
	}
	if !d.Matches(fp, []types.FingerprintRule{}) {
		t.Error("empty rules should always match")
	}
}

func TestMatches_TitleOnly(t *testing.T) {
	fp := makeFp([]string{"Apache Tomcat/9.0"}, map[string]string{"Server": "Apache-Coyote/1.1"}, "Apache-Coyote/1.1", "body")
	d := &Detector{}

	// Should match
	if !d.Matches(fp, []types.FingerprintRule{{Title: "Apache Tomcat"}}) {
		t.Error("title match failed for 'Apache Tomcat'")
	}
	// Case insensitive
	if !d.Matches(fp, []types.FingerprintRule{{Title: "apache tomcat"}}) {
		t.Error("title match should be case-insensitive")
	}
	// Should not match
	if d.Matches(fp, []types.FingerprintRule{{Title: "nginx"}}) {
		t.Error("title should not match 'nginx'")
	}
}

func TestMatches_HeaderOnly(t *testing.T) {
	fp := makeFp([]string{"Test"}, map[string]string{"Server": "nginx/1.21", "X-Application-Context": "prod"}, "nginx/1.21", "body")
	d := &Detector{}

	// Key + pattern match
	if !d.Matches(fp, []types.FingerprintRule{{Header: []string{"Server", "nginx"}}}) {
		t.Error("header match failed for Server: nginx")
	}
	// Key only (exists check)
	if !d.Matches(fp, []types.FingerprintRule{{Header: []string{"X-Application-Context"}}}) {
		t.Error("header key-only match failed")
	}
	// Should not match (key missing)
	if d.Matches(fp, []types.FingerprintRule{{Header: []string{"X-Custom-Header"}}}) {
		t.Error("header should not match missing key")
	}
	// Should not match (value pattern)
	if d.Matches(fp, []types.FingerprintRule{{Header: []string{"Server", "apache"}}}) {
		t.Error("header should not match wrong value")
	}
}

func TestMatches_BodyOnly(t *testing.T) {
	fp := makeFp([]string{}, map[string]string{}, "", `<html><body>Welcome to Django</body></html>`)
	d := &Detector{}

	// Should match
	if !d.Matches(fp, []types.FingerprintRule{{Body: "Django"}}) {
		t.Error("body match failed for 'Django'")
	}
	// Case insensitive
	if !d.Matches(fp, []types.FingerprintRule{{Body: "django"}}) {
		t.Error("body match should be case-insensitive")
	}
	// Should not match
	if d.Matches(fp, []types.FingerprintRule{{Body: "Spring Boot"}}) {
		t.Error("body should not match 'Spring Boot'")
	}
}

func TestMatches_AND_WithinRule(t *testing.T) {
	fp := makeFp([]string{"Spring Boot"}, map[string]string{"X-Application-Context": "main"}, "nginx", "Spring Boot application")
	d := &Detector{}

	// Both title AND header must match
	if !d.Matches(fp, []types.FingerprintRule{
		{Title: "Spring Boot", Header: []string{"X-Application-Context"}},
	}) {
		t.Error("AND within rule: title + header should match")
	}

	// Same rule with body AND header
	if !d.Matches(fp, []types.FingerprintRule{
		{Body: "Spring Boot", Header: []string{"X-Application-Context"}},
	}) {
		t.Error("AND within rule: body + header should match")
	}

	// Title matches but header doesn't → should fail
	if d.Matches(fp, []types.FingerprintRule{
		{Title: "Spring Boot", Header: []string{"X-Missing-Header"}},
	}) {
		t.Error("AND within rule: missing header should cause failure")
	}

	// Body matches but title doesn't → should fail
	if d.Matches(fp, []types.FingerprintRule{
		{Title: "Spring Boot", Body: "nonexistent string"},
	}) {
		t.Error("AND within rule: body mismatch should cause failure")
	}
}

func TestMatches_OR_BetweenRules(t *testing.T) {
	// Rule 1: title match, Rule 2: header match
	fp := makeFp([]string{"WordPress"}, map[string]string{"Server": "nginx"}, "nginx", "body")
	d := &Detector{}

	if !d.Matches(fp, []types.FingerprintRule{
		{Title: "WordPress"},
		{Header: []string{"Server", "nginx"}},
	}) {
		t.Error("OR between rules: first rule should match")
	}

	// Only header matches
	fp2 := makeFp([]string{"Some App"}, map[string]string{"X-Powered-By": "PHP/8.0"}, "nginx", "body")
	if !d.Matches(fp2, []types.FingerprintRule{
		{Title: "WordPress"},     // won't match
		{Header: []string{"X-Powered-By", "PHP"}}, // will match
	}) {
		t.Error("OR between rules: second rule should match")
	}

	// Nothing matches
	if d.Matches(fp2, []types.FingerprintRule{
		{Title: "WordPress"},
		{Title: "Django"},
	}) {
		t.Error("OR between rules: nothing should match")
	}
}

func TestMatches_RuleWithBody(t *testing.T) {
	fp := makeFp([]string{}, map[string]string{}, "", `<html><head><title>Jenkins</title></head><body>Jenkins</body></html>`)
	d := &Detector{}

	// Body contains Jenkins but title extraction might also find it
	if !d.Matches(fp, []types.FingerprintRule{{Body: "Jenkins"}}) {
		t.Error("body fingerprint should match 'Jenkins'")
	}

	// Body fingerprint with header combined
	fp2 := makeFp([]string{}, map[string]string{"Server": "Apache-Coyote/1.1"}, "Apache-Coyote/1.1",
		`<html>Jenkins</html>`)
	if !d.Matches(fp2, []types.FingerprintRule{
		{Body: "Jenkins", Header: []string{"Server", "Coyote"}},
	}) {
		t.Error("combined body+header fingerprint should match")
	}
}

func TestMatches_EmptyHeaderEntries(t *testing.T) {
	fp := makeFp([]string{"Test"}, map[string]string{"Server": "nginx"}, "nginx", "body")
	d := &Detector{}

	// Empty entries in new format should be skipped
	if !d.Matches(fp, []types.FingerprintRule{
		{Header: []string{"", "Server: nginx"}},
	}) {
		t.Error("empty header entries should be skipped")
	}
}

func TestMatches_MultipleHeadersInOneRule(t *testing.T) {
	fp := makeFp([]string{}, map[string]string{"Server": "nginx", "X-Powered-By": "PHP/8.0"}, "nginx", "body")
	d := &Detector{}

	// Multiple headers in one rule, both must match (AND)
	if !d.Matches(fp, []types.FingerprintRule{
		{Header: []string{"Server: nginx", "X-Powered-By: PHP"}},
	}) {
		t.Error("multiple headers in one rule should all match")
	}
}

func TestMatches_CaseInsensitive(t *testing.T) {
	fp := makeFp([]string{"APACHE TOMCAT"}, map[string]string{"SERVER": "Apache-Coyote/1.1"}, "Apache-Coyote/1.1", "BODY WITH WORD")
	d := &Detector{}

	// All matching should be case-insensitive
	if !d.Matches(fp, []types.FingerprintRule{
		{Title: "apache tomcat"},
		{Body: "body with word"},
		{Header: []string{"server", "apache"}},
	}) {
		t.Error("all matching should be case-insensitive")
	}
}

func TestMatches_FullPageWithMultipleTitles(t *testing.T) {
	fp := makeFp([]string{"Spring Boot", "Application"}, map[string]string{}, "", "<title>Spring Boot</title><body>App</body>")
	d := &Detector{}

	if !d.Matches(fp, []types.FingerprintRule{{Title: "Spring Boot"}}) {
		t.Error("should match first title")
	}
	if !d.Matches(fp, []types.FingerprintRule{{Title: "Application"}}) {
		t.Error("should match second title")
	}
}
