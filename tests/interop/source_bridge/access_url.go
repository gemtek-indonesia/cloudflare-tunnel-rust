package access

import "net/url"

// RustInteropAccessURL exposes the frozen package helper only in the scratch oracle build.
func RustInteropAccessURL(input string) (*url.URL, error) {
	return parseURL(input)
}

// RustInteropCurlURL exposes the distinct curl request-URI helper in the scratch oracle build.
func RustInteropCurlURL(input string) (*url.URL, error) {
	return processURL(input)
}
