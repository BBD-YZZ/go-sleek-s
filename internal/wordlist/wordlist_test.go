package wordlist

import (
	"testing"
)

func TestSQLiPayloads(t *testing.T) {
	if len(SQLiPayloads) == 0 {
		t.Fatal("SQLiPayloads is empty")
	}
	// 检查有分类
	hasBasic := false
	for _, e := range SQLiPayloads {
		if e.Category == "basic" {
			hasBasic = true
			break
		}
	}
	if !hasBasic {
		t.Error("expected at least one 'basic' category entry")
	}
}

func TestXSSPayloads(t *testing.T) {
	if len(XSSPayloads) == 0 {
		t.Fatal("XSSPayloads is empty")
	}
}

func TestSSRFPayloads(t *testing.T) {
	if len(SSRFPayloads) == 0 {
		t.Fatal("SSRFPayloads is empty")
	}
}

func TestLFIPayloads(t *testing.T) {
	if len(LFIPayloads) == 0 {
		t.Fatal("LFIPayloads is empty")
	}
}

func TestRCEPayloads(t *testing.T) {
	if len(RCEPayloads) == 0 {
		t.Fatal("RCEPayloads is empty")
	}
}

func TestPathPayloads(t *testing.T) {
	if len(PathPayloads) == 0 {
		t.Fatal("PathPayloads is empty")
	}
}

func TestAllBuiltins(t *testing.T) {
	all := AllBuiltins()
	if len(all) != 6 {
		t.Fatalf("expected 6 categories, got %d", len(all))
	}
	// Check all expected categories exist
	expected := map[string]bool{"sqli": false, "xss": false, "ssrf": false, "lfi": false, "rce": false, "path": false}
	for _, m := range all {
		for k := range m {
			expected[k] = true
		}
	}
	for k, found := range expected {
		if !found {
			t.Errorf("missing category: %s", k)
		}
	}
}

func TestGetCategoryPayloads(t *testing.T) {
	pay := GetCategoryPayloads("sqli")
	if len(pay) == 0 {
		t.Error("expected sqli payloads")
	}
	unknown := GetCategoryPayloads("nonexistent")
	if len(unknown) != 0 {
		t.Errorf("expected 0 for unknown category, got %d", len(unknown))
	}
}

func TestDetectFormat(t *testing.T) {
	// UTF-8 with BOM
	data := []byte("\xef\xbb\xbf# comment\nline1\n\nline2")
	info := DetectFormat(data)
	if !info.HasBOM {
		t.Error("expected BOM detection")
	}
	if !info.HasComments {
		t.Error("expected comment detection")
	}
	if info.LineCount != 3 {
		t.Errorf("expected 3 lines, got %d", info.LineCount)
	}

	// No BOM, plain ASCII
	data2 := []byte("line1\nline2\n# comment\n\n")
	info2 := DetectFormat(data2)
	if info2.HasBOM {
		t.Error("unexpected BOM")
	}
	if info2.LineCount != 3 {
		t.Errorf("expected 3 lines, got %d", info2.LineCount)
	}
	if !info2.HasComments {
		t.Error("expected comment detection")
	}
}

func TestComputeStats(t *testing.T) {
	entries := []Entry{
		{Value: "a", Category: "cat1"},
		{Value: "b", Category: "cat1"},
		{Value: "a", Category: "cat2"}, // duplicate
	}
	stats := ComputeStats(entries)
	if stats.TotalLines != 3 {
		t.Errorf("expected 3 total, got %d", stats.TotalLines)
	}
	if stats.UniqueValues != 2 {
		t.Errorf("expected 2 unique, got %d", stats.UniqueValues)
	}
	if stats.Duplicates != 1 {
		t.Errorf("expected 1 duplicate, got %d", stats.Duplicates)
	}
}

func TestDeduplicate(t *testing.T) {
	entries := []Entry{
		{Value: "A"},
		{Value: "a"},
		{Value: "B"},
		{Value: "a"},
	}
	result := Deduplicate(entries)
	if len(result) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(result))
	}
	if result[0].Value != "A" || result[1].Value != "B" {
		t.Errorf("unexpected order: %v", result)
	}
}

func TestFilterEmpty(t *testing.T) {
	entries := []Entry{
		{Value: "a"},
		{Value: "  "},
		{Value: ""},
		{Value: "b"},
	}
	result := FilterEmpty(entries)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestFilterComments(t *testing.T) {
	entries := []Entry{
		{Value: "a"},
		{Value: "# comment"},
		{Value: "// another"},
		{Value: "b"},
	}
	result := FilterComments(entries)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0].Value != "a" || result[1].Value != "b" {
		t.Errorf("unexpected: %v", result)
	}
}

func TestParseLines(t *testing.T) {
	data := []byte("# header comment\n\nline1\nline2\n# trailing\n")
	entries := ParseLines(data)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Value != "line1" || entries[1].Value != "line2" {
		t.Errorf("unexpected: %v", entries)
	}
}

func TestParseDelimited(t *testing.T) {
	data := []byte("a, b, c, a")
	entries := ParseDelimited(data, ",")
	if len(entries) != 4 {
		t.Fatalf("expected 4, got %d", len(entries))
	}
	if entries[0].Value != "a" || entries[1].Value != "b" {
		t.Errorf("unexpected: %v", entries)
	}
}

func TestInjectPlaceholder(t *testing.T) {
	entries := []Entry{
		{Value: "http://{{Host}}/api", Category: "test"},
		{Value: "http://{{Host}}/admin", Category: "test"},
	}
	result := InjectPlaceholder(entries, "Host", "127.0.0.1")
	if result[0].Value != "http://127.0.0.1/api" {
		t.Errorf("unexpected: %s", result[0].Value)
	}
	if result[1].Value != "http://127.0.0.1/admin" {
		t.Errorf("unexpected: %s", result[1].Value)
	}
}

func TestGenerateFromTemplate(t *testing.T) {
	template := "http://{{Host}}/api?param={{Value}}"
	vars := map[string][]string{
		"Host":   {"127.0.0.1", "localhost"},
		"Value":  {"test", "admin"},
	}
	result := GenerateFromTemplate(template, vars)
	if len(result) != 4 {
		t.Fatalf("expected 4 combinations, got %d", len(result))
	}

	// 验证所有组合都存在
	expected := []string{
		"http://127.0.0.1/api?param=test",
		"http://127.0.0.1/api?param=admin",
		"http://localhost/api?param=test",
		"http://localhost/api?param=admin",
	}
	found := make(map[string]bool)
	for _, r := range result {
		found[r.Value] = true
	}
	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("missing expected combination: %s", exp)
		}
	}
}

func TestGenerateFromTemplateNoVars(t *testing.T) {
	result := GenerateFromTemplate("simple", nil)
	if len(result) != 1 || result[0].Value != "simple" {
		t.Errorf("unexpected: %v", result)
	}
}
