package httpclient

// ContextKeyFollowRedirects is the context key used to pass per-request
// redirect-following semantics into the retry loop. When set to a non-nil
// bool: true means follow up to MaxRedirects, false means immediately
// return the last response. Absent key → Client-level default (cfg).
type ContextKeyFollowRedirects struct{}

// ContextKeyCookieJar is the context key used to pass a cookie jar for a
// single request (useful for session-aware workflow steps).
type ContextKeyCookieJar struct{}

