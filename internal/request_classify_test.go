// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const chromeNavigationAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

func newClassifyRequest(method string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	return r
}

// Each scenario is checked against all three classifiers, so one table shows how a
// given request is seen by each of them.
func TestRequestClassification(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		siteHost string
		headers  map[string]string

		wantNavigation  bool
		wantPreflight   bool
		wantBrowserLike bool
	}{
		{
			name:     "chrome top-level navigation (typed url)",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":                    chromeNavigationAccept,
				"Sec-Fetch-Site":            "none",
				"Sec-Fetch-Mode":            "navigate",
				"Sec-Fetch-Dest":            "document",
				"Sec-Fetch-User":            "?1",
				"Upgrade-Insecure-Requests": "1",
			},
			wantNavigation:  true,
			wantBrowserLike: false, // Sec-Fetch-Site none, no Referer
		},
		{
			name:     "chrome same-origin link click",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":         chromeNavigationAccept,
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "navigate",
				"Sec-Fetch-Dest": "document",
				"Sec-Fetch-User": "?1",
				"Referer":        "https://example.com/articles/",
			},
			wantNavigation:  true,
			wantBrowserLike: true,
		},
		{
			name:     "same-origin fetch()",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":         "*/*",
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://example.com/articles/42",
			},
			wantBrowserLike: true,
		},
		{
			name:     "same-origin fetch() asking for html is still not a navigation",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":         "text/html",
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://example.com/",
			},
			wantBrowserLike: true,
		},
		{
			name:     "cross-origin fetch() from a sibling subdomain",
			method:   http.MethodPost,
			siteHost: "api.example.com",
			headers: map[string]string{
				"Accept":         "application/json",
				"Origin":         "https://www.example.com",
				"Sec-Fetch-Site": "same-site",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://www.example.com/dashboard",
			},
			// same-site, but the Referer host is a sibling of api.example.com, not it or a subdomain
			wantBrowserLike: false,
		},
		{
			name:     "fetch() to the apex from a subdomain page",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":         "application/json",
				"Origin":         "https://www.example.com",
				"Sec-Fetch-Site": "same-site",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://www.example.com/",
			},
			wantBrowserLike: true,
		},
		{
			name:     "<img> load",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":         "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "no-cors",
				"Sec-Fetch-Dest": "image",
				"Referer":        "https://example.com/gallery",
			},
			wantBrowserLike: true,
		},
		{
			name:     "CORS preflight",
			method:   http.MethodOptions,
			siteHost: "api.example.com",
			headers: map[string]string{
				"Accept":                         "*/*",
				"Origin":                         "https://www.example.com",
				"Access-Control-Request-Method":  "PUT",
				"Access-Control-Request-Headers": "content-type",
				"Sec-Fetch-Site":                 "same-site",
				"Sec-Fetch-Mode":                 "cors",
				"Sec-Fetch-Dest":                 "empty",
				"Referer":                        "https://www.example.com/",
			},
			wantPreflight: true,
		},
		{
			name:     "plain OPTIONS without Access-Control-Request-Method",
			method:   http.MethodOptions,
			siteHost: "example.com",
			headers: map[string]string{
				"Origin": "https://example.com",
			},
		},
		{
			name:     "OPTIONS with an empty Access-Control-Request-Method is still a preflight",
			method:   http.MethodOptions,
			siteHost: "example.com",
			headers: map[string]string{
				"Origin":                        "https://example.com",
				"Access-Control-Request-Method": "",
			},
			wantPreflight: true,
		},
		{
			name:     "OPTIONS with Access-Control-Request-Method but no Origin",
			method:   http.MethodOptions,
			siteHost: "example.com",
			headers: map[string]string{
				"Access-Control-Request-Method": "PUT",
			},
		},
		{
			name:     "OPTIONS with Access-Control-Request-Method and a blank Origin",
			method:   http.MethodOptions,
			siteHost: "example.com",
			headers: map[string]string{
				"Origin":                        "  ",
				"Access-Control-Request-Method": "PUT",
			},
		},
		{
			name:     "GET carrying Access-Control-Request-Method",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Access-Control-Request-Method": "POST",
			},
		},
		{
			name:     "old browser without Sec-Fetch headers, html Accept",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Referer": "https://example.com/",
			},
			wantNavigation: true,
		},
		{
			name:     "old browser without Sec-Fetch headers, json Accept",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept":  "application/json, text/plain, */*",
				"Referer": "https://example.com/",
			},
		},
		{
			name:     "curl with no headers",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers:  map[string]string{},
		},
		{
			name:     "curl default Accept",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept": "*/*",
			},
		},
		{
			name:     "mixed-case values and surrounding whitespace, navigation",
			method:   http.MethodGet,
			siteHost: "Example.COM",
			headers: map[string]string{
				"Sec-Fetch-Site": "  Same-Origin ",
				"Sec-Fetch-Mode": " NaViGaTe\t",
				"Sec-Fetch-Dest": "DOCUMENT",
				"Referer":        "HTTPS://WWW.EXAMPLE.COM/Page",
			},
			wantNavigation:  true,
			wantBrowserLike: true,
		},
		{
			name:     "mixed-case values, fetch",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "SAME-SITE",
				"Sec-Fetch-Mode": "CORS",
				"Sec-Fetch-Dest": "Empty",
				"Referer":        "https://Example.com:8443/x",
			},
			wantBrowserLike: true,
		},
		{
			name:     "mixed-case html Accept without Sec-Fetch-Mode",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Accept": "TEXT/HTML",
			},
			wantNavigation: true,
		},
		{
			name:     "Referer from a different site",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://attacker.example.net/",
			},
		},
		{
			name:     "Referer host that only ends with the site name",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://notexample.com/",
			},
		},
		{
			name:     "Referer host that starts with the site name",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://example.com.attacker.net/",
			},
		},
		{
			name:     "cross-site fetch with a matching Referer",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "cross-site",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://example.com/",
			},
		},
		{
			name:     "missing Referer",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
			},
		},
		{
			name:     "Referer without a scheme has no host",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "example.com/page",
			},
		},
		{
			name:     "missing Sec-Fetch-Dest",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Referer":        "https://example.com/",
			},
		},
		{
			name:     "missing Sec-Fetch-Site",
			method:   http.MethodGet,
			siteHost: "example.com",
			headers: map[string]string{
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://example.com/",
			},
		},
		{
			name:     "empty site host",
			method:   http.MethodGet,
			siteHost: "",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Referer":        "https://example.com/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newClassifyRequest(tt.method, tt.headers)
			if got := IsNavigation(r); got != tt.wantNavigation {
				t.Errorf("IsNavigation() = %v, want %v", got, tt.wantNavigation)
			}
			if got := IsPreflight(r); got != tt.wantPreflight {
				t.Errorf("IsPreflight() = %v, want %v", got, tt.wantPreflight)
			}
			if got := IsBrowserLike(r, tt.siteHost); got != tt.wantBrowserLike {
				t.Errorf("IsBrowserLike(%q) = %v, want %v", tt.siteHost, got, tt.wantBrowserLike)
			}
		})
	}
}

// Sec-Fetch-Mode decides on its own when present, whatever Accept says.
func TestIsNavigationSecFetchModeValues(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"navigate", true},
		{"NAVIGATE", true},
		{"  navigate  ", true},
		{"cors", false},
		{"same-origin", false},
		{"no-cors", false},
		{"websocket", false},
		{"nested-navigate", false}, // unknown value
		{"navigate, cors", false},  // unknown value
		{"", true},                 // empty counts as absent: falls back to the html Accept below
		{"   ", true},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			r := newClassifyRequest(http.MethodGet, map[string]string{
				"Accept":         "text/html",
				"Sec-Fetch-Mode": tt.mode,
			})
			if got := IsNavigation(r); got != tt.want {
				t.Errorf("IsNavigation() with Sec-Fetch-Mode %q = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

// One case per rule in IsSubresource. Browser header sets are as sent by current Chromium
// and Firefox; the inconsistent ones are what a browser never sends, so a client forging
// part of a set is still counted.
func TestIsSubresource(t *testing.T) {
	sameOrigin := func(mode, dest string) map[string]string {
		return map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest}
	}
	with := func(headers map[string]string, name, value string) map[string]string {
		out := map[string]string{name: value}
		for k, v := range headers {
			if k != name {
				out[k] = v
			}
		}
		return out
	}
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		// fetch() and XHR
		{"same-origin fetch()", with(sameOrigin("cors", "empty"), "Accept", "*/*"), true},
		{"same-origin fetch() in same-origin mode", sameOrigin("same-origin", "empty"), true},
		{"fetch() with no-cors mode", sameOrigin("no-cors", "empty"), true},
		{"cross-origin fetch()", map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Origin": "https://www.example.com"}, true},
		{"cross-site fetch()", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}, true},
		{"XHR with Sec-Fetch headers", with(sameOrigin("cors", "empty"), "X-Requested-With", "XMLHttpRequest"), true},
		{"mixed-case header values", map[string]string{"Sec-Fetch-Site": " Same-Origin", "Sec-Fetch-Mode": "CORS ", "Sec-Fetch-Dest": "  EMPTY "}, true},
		{"fetch() asking for html is still a subresource", with(sameOrigin("cors", "empty"), "Accept", "text/html"), true},

		// other subresources (gap: these used to get the HTML challenge and be counted)
		{"<img> load", sameOrigin("no-cors", "image"), true},
		{"<script> load", sameOrigin("no-cors", "script"), true},
		{"module script", sameOrigin("cors", "script"), true},
		{"stylesheet", sameOrigin("no-cors", "style"), true},
		{"web font", sameOrigin("cors", "font"), true},
		{"video", sameOrigin("no-cors", "video"), true},
		{"worker script", sameOrigin("same-origin", "worker"), true},
		{"json module import", sameOrigin("cors", "json"), true},

		// WebSocket handshake: same answer in every browser
		{"chromium WebSocket handshake", sameOrigin("websocket", "websocket"), true},
		{"firefox WebSocket handshake", sameOrigin("websocket", "empty"), true},
		{"websocket mode with an image destination", sameOrigin("websocket", "image"), false},
		{"websocket destination without websocket mode", sameOrigin("cors", "websocket"), false},

		// pages get the HTML challenge
		{"chrome navigation", map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1", "Accept": chromeNavigationAccept}, false},
		{"same-origin link click", sameOrigin("navigate", "document"), false},
		{"iframe navigation", sameOrigin("navigate", "iframe"), false},
		{"frame", sameOrigin("navigate", "frame"), false},
		{"<object> load", sameOrigin("no-cors", "object"), false},
		{"<embed> load", sameOrigin("no-cors", "embed"), false},
		{"unknown destination", sameOrigin("no-cors", "hologram"), false},
		{"unknown mode", sameOrigin("nested-navigate", "empty"), false},

		// inconsistent sets: a browser never sends these
		{"empty destination with navigate mode", sameOrigin("navigate", "empty"), false},
		{"document destination with cors mode", sameOrigin("cors", "document"), false},
		{"missing Sec-Fetch-Dest", map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}, false},
		{"missing Sec-Fetch-Site", map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}, false},
		{"Sec-Fetch-Site none on a subresource", map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}, false},
		{"Sec-Fetch-User on a subresource", with(sameOrigin("cors", "empty"), "Sec-Fetch-User", "?1"), false},
		{"empty Sec-Fetch-User on a subresource", with(sameOrigin("cors", "empty"), "Sec-Fetch-User", ""), false},
		{"XHR with a lone empty Sec-Fetch-Dest", map[string]string{"Sec-Fetch-Dest": "empty", "X-Requested-With": "XMLHttpRequest"}, true},
		{"lone empty Sec-Fetch-Dest without X-Requested-With", map[string]string{"Sec-Fetch-Dest": "empty"}, false},
		{"page Sec-Fetch-Dest without Sec-Fetch-Mode", map[string]string{"Sec-Fetch-Dest": "document", "X-Requested-With": "XMLHttpRequest"}, false},
		{"Sec-Fetch-Site without Sec-Fetch-Mode", map[string]string{"Sec-Fetch-Site": "same-origin", "X-Requested-With": "XMLHttpRequest"}, false},
		{"Sec-Fetch-Dest wins over X-Requested-With", with(sameOrigin("navigate", "document"), "X-Requested-With", "XMLHttpRequest"), false},

		// no Fetch Metadata: older browsers, or plain http to a non-localhost host
		{"old browser jQuery XHR", map[string]string{"Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest"}, true},
		{"old browser, X-Requested-With lowercase", map[string]string{"X-Requested-With": " xmlhttprequest "}, true},
		{"old browser fetch() without X-Requested-With", map[string]string{"Accept": "application/json"}, false},
		{"old browser navigation", map[string]string{"Accept": "text/html,application/xhtml+xml"}, false},
		{"X-Requested-With from an Android WebView app id", map[string]string{"X-Requested-With": "com.example.app"}, false},
		{"curl with no headers", map[string]string{}, false},
		{"curl default Accept", map[string]string{"Accept": "*/*"}, false},
		{"api client asking for json", map[string]string{"Accept": "application/json", "Content-Type": "application/json"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSubresource(newClassifyRequest(http.MethodGet, tt.headers)); got != tt.want {
				t.Errorf("IsSubresource() = %v, want %v", got, tt.want)
			}
		})
	}
}
