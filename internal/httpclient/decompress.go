package httpclient

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// SetCookieJar injects an http.CookieJar into the context for a single request.
// Useful for workflow steps that need session persistence across requests.
func SetCookieJar(ctx context.Context, jar http.CookieJar) context.Context {
	return context.WithValue(ctx, ContextKeyCookieJar{}, jar)
}

// getCookieJar retrieves a cookie jar from the context, if any.
func getCookieJar(ctx context.Context) http.CookieJar {
	if v, ok := ctx.Value(ContextKeyCookieJar{}).(http.CookieJar); ok && v != nil {
		return v
	}
	return nil
}

// decompressBody attempts to decompress a response body based on Content-Encoding.
// Returns the decompressed body and the resolved Content-Type.
func decompressBody(rawBody []byte, contentType string, encoding string) ([]byte, string) {
	encoding = strings.TrimSpace(strings.ToLower(encoding))
	if encoding == "" || encoding == "identity" {
		return rawBody, contentType
	}

	var decompressed []byte
	var err error

	switch {
	case strings.Contains(encoding, "gzip"):
		decompressed, err = decompressGzip(rawBody)
	case strings.Contains(encoding, "deflate"):
		decompressed, err = decompressDeflate(rawBody)
	case strings.Contains(encoding, "br"):
		// brotli not in stdlib — return raw for matcher to handle
		return rawBody, contentType
	case strings.Contains(encoding, "zstd"):
		// zstd not in stdlib — return raw
		return rawBody, contentType
	default:
		return rawBody, contentType
	}

	if err != nil {
		// Decompression failed — return raw body so matcher still sees something
		return rawBody, contentType
	}

	// Update content type for text responses
	if len(decompressed) > 0 {
		contentType = inferContentType(decompressed, contentType)
	}
	return decompressed, contentType
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(io.NopCloser(strings.NewReader(string(data))))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func decompressDeflate(data []byte) ([]byte, error) {
	r := flate.NewReader(io.NopCloser(strings.NewReader(string(data))))
	defer r.Close()
	return io.ReadAll(r)
}

// inferContentType guesses the content type from body bytes if the header is ambiguous.
func inferContentType(body []byte, current string) string {
	lower := strings.ToLower(current)
	if strings.Contains(lower, "text") || strings.Contains(lower, "json") ||
		strings.Contains(lower, "xml") || strings.Contains(lower, "html") {
		return current
	}
	// Peek at first few bytes to detect text vs binary
	sample := body
	if len(sample) > 512 {
		sample = sample[:512]
	}
	// Check for null bytes (binary indicator)
	for _, b := range sample {
		if b == 0 {
			return "application/octet-stream"
		}
	}
	// Likely text
	if len(lower) == 0 || lower == "application/octet-stream" {
		return "text/plain; charset=utf-8"
	}
	return current
}

// fixEncoding detects and fixes common charset issues in response bodies.
// Handles GBK/GB2312 detected from meta tags or Content-Type, and UTF-8 BOM stripping.
func fixEncoding(body []byte, contentType string) []byte {
	// Strip UTF-8 BOM
	if len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF {
		body = body[3:]
	}

	lowerCT := strings.ToLower(contentType)
	// Detect GBK/GB2312 from Content-Type
	if strings.Contains(lowerCT, "gbk") || strings.Contains(lowerCT, "gb2312") ||
		strings.Contains(lowerCT, "gb18030") {
		if decoded, err := decodeGBK(body); err == nil {
			return decoded
		}
	}

	// Also check meta charset tag for HTML content
	if strings.Contains(lowerCT, "text/html") {
		if metaEncoding := detectMetaCharset(body); metaEncoding != "" {
			if decoded, err := decodeByEncoding(body, metaEncoding); err == nil {
				return decoded
			}
		}
	}

	return body
}

// decodeGBK decodes GBK-encoded bytes to UTF-8.
func decodeGBK(data []byte) ([]byte, error) {
	reader := transform.NewReader(strings.NewReader(string(data)), simplifiedchinese.GBK.NewDecoder())
	return io.ReadAll(reader)
}

// decodeByEncoding decodes data using the specified encoding name.
func decodeByEncoding(data []byte, encoding string) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	switch enc {
	case "gbk", "gb2312", "gb18030":
		return decodeGBK(data)
	case "utf-8", "utf8":
		// Already UTF-8, just validate
		if len(data) > 0 && isUTF8(data) {
			return data, nil
		}
		return nil, fmt.Errorf("not valid utf-8")
	case "utf-16", "utf16":
		return nil, fmt.Errorf("utf-16 not supported")
	case "iso-8859-1", "latin1":
		return data, nil // bytes are already the characters
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// detectMetaCharset scans HTML body for <meta charset="..."> or <meta http-equiv="Content-Type" ...>.
func detectMetaCharset(body []byte) string {
	s := string(body)
	// <meta charset="GBK">
	if idx := strings.Index(strings.ToLower(s), "meta charset"); idx >= 0 {
		rest := s[idx+len("meta charset"):]
		rest = strings.TrimLeft(rest, " =\t\n\r\"'")
		end := strings.IndexAny(rest, "\"' \t\n\r>")
		if end > 0 {
			return rest[:end]
		}
	}
	// <meta http-equiv="Content-Type" content="text/html; charset=GBK">
	if idx := strings.Index(strings.ToLower(s), "http-equiv"); idx >= 0 {
		rest := s[idx:]
		if strings.Contains(rest, "content-type") || strings.Contains(rest, "content type") {
			if ci := strings.Index(rest, "charset"); ci >= 0 {
				after := rest[ci+len("charset"):]
				after = strings.TrimLeft(after, " =\t\n\r\"'")
				end := strings.IndexAny(after, "\"' \t\n\r>")
				if end > 0 {
					return after[:end]
				}
			}
		}
	}
	return ""
}

// isUTF8 checks if bytes are valid UTF-8.
func isUTF8(data []byte) bool {
	for i := 0; i < len(data); {
		if data[i] < 0x80 {
			i++
			continue
		}
		if data[i] < 0xc0 {
			return false
		}
		var run int
		switch {
		case data[i] < 0xe0:
			run = 2
		case data[i] < 0xf0:
			run = 3
		case data[i] < 0xf8:
			run = 4
		default:
			return false
		}
		if i+run > len(data) {
			return false
		}
		for j := 1; j < run; j++ {
			if data[i+j]&0xc0 != 0x80 {
				return false
			}
		}
		i += run
	}
	return true
}
