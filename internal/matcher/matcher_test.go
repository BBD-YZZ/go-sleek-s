package matcher

import (
	"testing"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// TestJSONWord_CeyeDNS 模拟 ceye type=dns API 返回的 JSON, 验证 json-word
// matcher 能解析顶层 data 数组, 对每个元素的 name 字段做大小写不敏感匹配.
//
// 这是修复 OOB 验证的关键: ceye DNS 记录 name 是混合大小写 (如 gS-xxx.LBWssd.ceye.iO),
// 而我们生成的 oob_label 是全小写 (如 gs-xxx). 用直接 Contains(body) 可能命中,
// 但因服务端 filter 大小写敏感, 可能返回空 data 数组. json-word 直接解析响应 body
// 彻底绕开服务端 filter, 在客户端统一比对.
func TestJSONWord_CeyeDNS(t *testing.T) {
	// 真实 ceye type=dns API 返回示例 (第一条混合大小写, 第二条全小写)
	dnsBody := `{
		"meta": {"code": 200, "message": "OK"},
		"data": [
			{"id": "123", "name": "gS-50888f51.LBWssd.ceye.iO", "remote_addr": "172.253.5.22", "created_at": "2026-08-06 10:39:17"},
			{"id": "124", "name": "gs-50888f51.lbwssd.ceye.io", "remote_addr": "172.253.6.13", "created_at": "2026-08-06 10:39:18"}
		]
	}`

	ctxDNS := NewMatchContext(200, dnsBody, "", 0)

	// 1. json-word + 大小写不敏感 + 数组遍历: 必须匹配上
	m := types.Matcher{
		Type:            "json-word",
		JSONPath:        "data",
		JSONField:       "name",
		Words:           []string{"gs-50888f51"},
		CaseInsensitive: true,
	}
	matched, evidence := Evaluate([]types.Matcher{m}, "or", ctxDNS)
	if !matched {
		t.Errorf("json-word (CI) should match ceye DNS record (mixed-case), got evidence: %s", evidence)
	}

	// 2. 严格大小写 (CaseInsensitive=false): 仍匹配第 2 条小写记录 (any 模式)
	mStrict := types.Matcher{
		Type:      "json-word",
		JSONPath:  "data",
		JSONField: "name",
		Words:     []string{"gs-50888f51"},
	}
	matched, evidence = Evaluate([]types.Matcher{mStrict}, "or", ctxDNS)
	if !matched {
		t.Errorf("json-word (strict) should match lower-case record in array, got evidence: %s", evidence)
	}

	// 3. 找不到的 label: 不应匹配
	mMiss := types.Matcher{
		Type:            "json-word",
		JSONPath:        "data",
		JSONField:       "name",
		Words:           []string{"gs-notexist"},
		CaseInsensitive: true,
	}
	if matched, _ := Evaluate([]types.Matcher{mMiss}, "or", ctxDNS); matched {
		t.Errorf("json-word should NOT match missing label")
	}

	// 4. body 不是合法 JSON: 不应匹配
	badCtx := NewMatchContext(200, "<html>not json</html>", "", 0)
	if matched, _ := Evaluate([]types.Matcher{m}, "or", badCtx); matched {
		t.Errorf("json-word should fail on non-JSON body")
	}

	// 5. data 数组为空: 不应匹配
	emptyCtx := NewMatchContext(200, `{"meta":{"code":200,"message":"OK"},"data":[]}`, "", 0)
	if matched, _ := Evaluate([]types.Matcher{m}, "or", emptyCtx); matched {
		t.Errorf("json-word should not match empty data array")
	}
}

// TestJSONWord_CeyeHTTP 模拟 ceye type=http API 返回, 验证 HTTP 类型
// (name 字段是完整 URL 形式 "http://xxx.ceye.io/") 也能匹配.
func TestJSONWord_CeyeHTTP(t *testing.T) {
	httpBody := `{
		"meta": {"code": 200, "message": "OK"},
		"data": [
			{
				"id": "135193177",
				"name": "http://gs-bald6e84.lbwssd.ceye.io/",
				"method": "GET",
				"remote_addr": "123.138.73.170",
				"user_agent": "curl/7.64.0",
				"data": "",
				"content_type": null,
				"created_at": "2026-08-06 10:40:44"
			},
			{
				"id": "135193176",
				"name": "HTTP://GS-BALD6E84.LBWSSD.CEYE.IO/",
				"method": "GET",
				"remote_addr": "123.138.73.170",
				"user_agent": "curl/7.64.0",
				"created_at": "2026-08-06 10:40:36"
			}
		]
	}`

	ctx := NewMatchContext(200, httpBody, "", 0)

	m := types.Matcher{
		Type:            "json-word",
		JSONPath:        "data",
		JSONField:       "name",
		Words:           []string{"gs-bald6e84"},
		CaseInsensitive: true,
	}
	if matched, evidence := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Errorf("json-word should match HTTP record (mixed-case URL), got: %s", evidence)
	}

	// AND 条件 - 两个 label 都必须找到
	mAnd := types.Matcher{
		Type: "json-word",
		JSONPath:  "data",
		JSONField: "name",
		Words: []string{"gs-bald6e84", ".ceye.io"},
		CaseInsensitive: true,
		Condition: "and",
	}
	if matched, _ := Evaluate([]types.Matcher{mAnd}, "and", ctx); !matched {
		t.Errorf("json-word AND should match when both substrings present")
	}
}

// TestCaseInsensitiveWord 验证 word matcher 在 case-insensitive=true 时
// 能匹配大小写不同的子串. 这是修复 OOB 模板 verify-dns 步骤的关键:
// ceye DNS 记录 name 形如 "gS-xxxxxx.LBWssd.ceye.iO" 是大小写混合,
// 但我们生成的 oob_label 是全小写 "gs-xxxxxx".
func TestCaseInsensitiveWord(t *testing.T) {
	// 模拟 ceye DNS API 返回 (大小写混合)
	dnsBody := `{"code":200,"message":"OK","data":[{"id":"123","name":"gS-50888f51.LBWssd.ceye.iO","remote_addr":"172.253.5.22","created_at":"2026-08-06 10:39:17"}]}`

	// 模拟 ceye HTTP API 返回 (虽然是全小写, 但作为通用测试)
	httpBody := `{"code":200,"message":"OK","data":[{"id":"456","name":"http://gs-bald6e84.lbwssd.ceye.io/","method":"GET","remote_addr":"123.138.73.170","user_agent":"curl/7.64.0","data":"","content_type":null,"created_at":"2026-08-06 10:40:44"}]}`

	ctxDNS := NewMatchContext(200, dnsBody, "", 0)
	ctxHTTP := NewMatchContext(200, httpBody, "", 0)

	// 1. 大小写敏感 (默认) - 应匹配不上 DNS 记录
	strictMatcher := types.Matcher{
		Type:    "word",
		Part:    "body",
		Words:   []string{"gs-50888f51"}, // 全小写
	}
	if matched, _ := Evaluate([]types.Matcher{strictMatcher}, "or", ctxDNS); matched {
		t.Errorf("strict matcher should NOT match mixed-case DNS record")
	}

	// 2. 大小写不敏感 - 应匹配上 DNS 记录
	ciMatcher := types.Matcher{
		Type:            "word",
		Part:            "body",
		Words:           []string{"gs-50888f51"}, // 全小写
		CaseInsensitive: true,
	}
	if matched, evidence := Evaluate([]types.Matcher{ciMatcher}, "or", ctxDNS); !matched {
		t.Errorf("case-insensitive matcher should match mixed-case DNS record, got evidence: %s", evidence)
	}

	// 3. HTTP 类型 - 大小写不敏感也应该匹配 (HTTP body 含全小写 label)
	if matched, _ := Evaluate([]types.Matcher{{
		Type: "word", Part: "body", Words: []string{"gs-bald6e84"}, CaseInsensitive: true,
	}}, "or", ctxHTTP); !matched {
		t.Errorf("case-insensitive matcher should match HTTP record")
	}

	// 3b. HTTP 类型 - 强制大小写变化时也匹配 (避免漏掉大写 substring)
	if matched, _ := Evaluate([]types.Matcher{{
		Type: "word", Part: "body", Words: []string{"GS-BALD6E84"}, CaseInsensitive: true,
	}}, "or", ctxHTTP); !matched {
		t.Errorf("case-insensitive matcher should match uppercase search against lowercase body")
	}

	// 4. 多个 words + and 条件
	multiMatcher := types.Matcher{
		Type: "word",
		Part: "body",
		Words: []string{
			"gs-50888f51", // 匹配 DNS
			"GS-50888F51", // 也匹配 (大小写不敏感)
		},
		Condition:       "and",
		CaseInsensitive: true,
	}
	if matched, _ := Evaluate([]types.Matcher{multiMatcher}, "and", ctxDNS); !matched {
		t.Errorf("case-insensitive AND should match when both words are found")
	}

	t.Logf("all case-insensitive word tests passed")
}

// TestStatusMatcher verifies exact status code matching.
func TestStatusMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "ok", "HTTP/1.1 200 OK", 0)
	if matched, _ := Evaluate([]types.Matcher{{Type: "status", Status: []int{200}}}, "or", ctx); !matched {
		t.Error("status 200 should match when 200 in list")
	}
	if matched, _ := Evaluate([]types.Matcher{{Type: "status", Status: []int{404, 500}}}, "or", ctx); matched {
		t.Error("status 200 should NOT match when only 404/500 in list")
	}
}

// TestRegexMatcher verifies regex matching on body (case-insensitive flag).
func TestRegexMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "session token=ABC123", "", 0)
	m := types.Matcher{Type: "regex", Part: "body", Regex: []string{`token=[A-Za-z0-9]+`}}
	if matched, _ := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Error("regex token= should match case-sensitively")
	}
	// Case-insensitive
	mCI := types.Matcher{Type: "regex", Part: "body", Regex: []string{`TOKEN=[A-Z0-9]+`}, CaseInsensitive: true}
	if matched, _ := Evaluate([]types.Matcher{mCI}, "or", ctx); !matched {
		t.Error("case-insensitive regex TOKEN= should match")
	}
}

// TestHeaderMatcher verifies header matching.
func TestHeaderMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "", "Server: nginx/1.21.0\r\nContent-Type: text/html", 0)
	m := types.Matcher{Type: "header", Header: []string{"Server: nginx"}}
	if matched, _ := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Error("header 'Server: nginx' should match")
	}
	if matched, _ := Evaluate([]types.Matcher{{Type: "header", Header: []string{"X-Powered-By: PHP"}}}, "or", ctx); matched {
		t.Error("absent header should not match")
	}
}

// TestSizeMatcher verifies size expressions (>, <, ==).
func TestSizeMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "12345", "", 0) // ContentSize = 5
	if matched, _ := Evaluate([]types.Matcher{{Type: "size", Size: []string{">3"}}}, "or", ctx); !matched {
		t.Error("size >3 should match (len 5)")
	}
	if matched, _ := Evaluate([]types.Matcher{{Type: "size", Size: []string{"<3"}}}, "or", ctx); matched {
		t.Error("size <3 should NOT match (len 5)")
	}
	if matched, _ := Evaluate([]types.Matcher{{Type: "size", Size: []string{"==5"}}}, "or", ctx); !matched {
		t.Error("size ==5 should match")
	}
}

// TestTimeMatcher verifies time comparison.
func TestTimeMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "", "", 1500*time.Millisecond) // 1.5s
	if matched, _ := Evaluate([]types.Matcher{{Type: "time", Time: ">1"}}, "or", ctx); !matched {
		t.Error("time >1s should match (1.5s)")
	}
	if matched, _ := Evaluate([]types.Matcher{{Type: "time", Time: "<1"}}, "or", ctx); matched {
		t.Error("time <1s should NOT match (1.5s)")
	}
}

// TestBinaryMatcher verifies hex-decoded binary search.
func TestBinaryMatcher(t *testing.T) {
	// Body contains bytes 0D 0A (CRLF). Hex string "0d0a" should match.
	ctx := NewMatchContext(200, "line1\r\nline2", "", 0)
	m := types.Matcher{Type: "binary", Binary: []string{"0d0a"}}
	if matched, _ := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Error("binary 0d0a should match CRLF in body")
	}
	if matched, _ := Evaluate([]types.Matcher{{Type: "binary", Binary: []string{"deadbeef"}}}, "or", ctx); matched {
		t.Error("binary deadbeef should NOT match")
	}
}

// TestNegativeMatcher verifies negative (inverse) matching.
func TestNegativeMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "welcome", "", 0)
	m := types.Matcher{Type: "word", Part: "body", Words: []string{"forbidden"}, Negative: true}
	if matched, _ := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Error("negative word (absent) should match")
	}
	m2 := types.Matcher{Type: "word", Part: "body", Words: []string{"welcome"}, Negative: true}
	if matched, _ := Evaluate([]types.Matcher{m2}, "or", ctx); matched {
		t.Error("negative word (present) should NOT match")
	}
}

// TestMatchersConditionAnd verifies "and" aggregation across multiple matchers.
func TestMatchersConditionAnd(t *testing.T) {
	ctx := NewMatchContext(200, "admin panel", "", 0)
	matchers := []types.Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Part: "body", Words: []string{"admin"}},
	}
	if matched, _ := Evaluate(matchers, "and", ctx); !matched {
		t.Error("AND: both status and word match → should pass")
	}
	matchers[1] = types.Matcher{Type: "word", Part: "body", Words: []string{"rootkit"}}
	if matched, _ := Evaluate(matchers, "and", ctx); matched {
		t.Error("AND: word missing → should fail")
	}
}

// TestDSLMatcher verifies DSL matcher through the public Evaluate entry point.
func TestDSLMatcher(t *testing.T) {
	ctx := NewMatchContext(200, "uid=0(root)", "Content-Type: text/plain", 0)
	cases := []struct {
		name string
		dsl  string
		want bool
	}{
		{"status equals", "status_code == 200", true},
		{"status mismatch", "status_code == 404", false},
		{"contains func", "contains(body, 'root')", true},
		{"contains_any", "contains_any(body, 'nope', 'root')", true},
		{"contains_all", "contains_all(body, 'uid=', 'root')", true},
		{"regex func", "regex(body, 'uid=\\d+')", true},
		{"and chain", "status_code == 200 && contains(body, 'root')", true},
		{"or chain", "status_code == 500 || contains(body, 'root')", true},
		{"not", "!contains(body, 'missing')", true},
		{"len compare", "len(body) > 5", true},
		{"len compare false", "len(body) > 9999", false},
		{"len equals", "len(body) == 11", true},
	}
	for _, c := range cases {
		m := types.Matcher{Type: "dsl", DSL: []string{c.dsl}}
		got, _ := Evaluate([]types.Matcher{m}, "or", ctx)
		if got != c.want {
			t.Errorf("DSL %q: got %v, want %v", c.dsl, got, c.want)
		}
	}
}

// TestJSON2DArray_DNSLog verifies json-2darray matcher against dnslog.cn responses.
// dnslog returns: [["domain","ip","time"],...] (root-level 2D array)
func TestJSON2DArray_DNSLog(t *testing.T) {
	// Simulated dnslog response with a matching record
	body := `[["aaaa.ppw8iu.dnslog.cn","218.x.x.x","2024-03-18 22:20:13"],["aaaa.ppw8iu.dnslog.cn","218.x.x.206","2024-03-18 22:20:13"]]`

	ctx := NewMatchContext(200, body, "", 0)
	m := types.Matcher{
		Type:               "json-2darray",
		JSONPath:           "", // root array
		JSON2DColumn:  0,
		Words:              []string{"aaaa"},
		CaseInsensitive:    true,
	}
	if matched, evidence := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Errorf("json-2darray should match dnslog record, got: %s", evidence)
	}

	// Negative: non-existent label
	mNeg := types.Matcher{
		Type:              "json-2darray",
		JSONPath:          "",
		JSON2DColumn: 0,
		Words:             []string{"zzzz"},
	}
	if matched, _ := Evaluate([]types.Matcher{mNeg}, "or", ctx); matched {
		t.Error("json-2darray should NOT match non-existent label")
	}

	// Empty response
	emptyCtx := NewMatchContext(200, "[]", "", 0)
	if matched, _ := Evaluate([]types.Matcher{m}, "or", emptyCtx); matched {
		t.Error("json-2darray should not match empty array")
	}
}

// TestJSON2DArray_CallbackRed verifies json-2darray can also handle
// callback.red's nested format (though json-word is preferred for it).
func TestJSON2DArray_NestedArray(t *testing.T) {
	body := `{"code":200,"data":[["tsgm.callback.red","60.x.x.160","dns"],["tsgm.callback.red","58.x.x.111","http"]]}`

	ctx := NewMatchContext(200, body, "", 0)
	m := types.Matcher{
		Type:               "json-2darray",
		JSONPath:           "data",
		JSON2DColumn:  0,
		Words:              []string{"tsgm"},
		CaseInsensitive:    true,
	}
	if matched, _ := Evaluate([]types.Matcher{m}, "or", ctx); !matched {
		t.Error("json-2darray should match nested array")
	}
}
