package token

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRustRedirectDecodedSSOPathContract(t *testing.T) {
	base, _ := url.Parse("https://synthetic.invalid/base")
	for _, ref := range []string{"/%63dn-cgi/access/login", "/%ff/cdn-cgi/access/login", "/%63dn-cgi/access/authorized"} {
		target, err := base.Parse(ref)
		if err != nil {
			t.Fatal(err)
		}
		req := &http.Request{URL: target, Header: make(http.Header)}
		previous := &http.Request{URL: base, Response: &http.Response{Header: http.Header{"Set-Cookie": []string{"CF_AppSession=synthetic-session; Path=/"}}}}
		if err := handleRedirects(req, []*http.Request{previous}, "synthetic-org"); err != nil {
			t.Fatal(err)
		}
		want := "CF_Authorization=synthetic-org"
		if strings.Contains(ref, "authorized") {
			want = "CF_AppSession=synthetic-session"
		}
		if req.Header.Get("Cookie") != want {
			t.Fatalf("decodedSSO cookie=%q want=%q", req.Header.Get("Cookie"), want)
		}
	}
}
