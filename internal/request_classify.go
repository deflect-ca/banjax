// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Request classification from the browser's Fetch Metadata (Sec-Fetch-*) and related
// headers. nginx proxy_passes the client's request headers to banjax unchanged (see
// supporting-containers/nginx/nginx.conf), so these read the client's own values.
//
// Browsers send Sec-Fetch-* only to potentially trustworthy origins (https, or
// localhost). Over plain http they are absent, so IsNavigation falls back to Accept and
// IsBrowserLike is always false.

// headerToken is a header value trimmed of surrounding whitespace and lowercased, for
// case-insensitive comparison. An absent header gives "".
func headerToken(r *http.Request, name string) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get(name)))
}

// IsNavigation reports whether r is a top-level or frame navigation, which a browser
// will render as a page and so can show an HTML challenge.
//
// With Sec-Fetch-Mode, only "navigate" is a navigation; "cors", "same-origin",
// "no-cors", "websocket" and unknown values are not. Without it (older browsers, or
// plain http), a request is a navigation if its Accept header contains "text/html".
// An empty or whitespace-only Sec-Fetch-Mode counts as absent.
func IsNavigation(r *http.Request) bool {
	mode := headerToken(r, "Sec-Fetch-Mode")
	if mode == "" {
		return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
	}
	return mode == "navigate"
}

// IsXHR reports whether r is a browser's fetch() or XMLHttpRequest call, which can't
// display an HTML challenge. Banjax answers a challenged XHR with a 403 JSON error instead,
// and does not count it toward the failed challenge ban.
//
// With Sec-Fetch-Dest, only "empty" is an XHR: browsers send it for fetch(), XHR,
// EventSource and sendBeacon, and a specific destination for everything else ("document"
// for navigations, "image", "script" and so on). Without Sec-Fetch-Dest (older browsers, or
// plain http), only an X-Requested-With: XMLHttpRequest header (sent by jQuery and many
// frameworks) marks one.
//
// Kept strict on purpose: a non-browser client (curl, most bots) sends neither header, so it
// keeps getting the HTML challenge and keeps counting toward the ban. Both headers can be
// forged, but a bot has to choose to.
func IsXHR(r *http.Request) bool {
	if dest := headerToken(r, "Sec-Fetch-Dest"); dest != "" {
		return dest == "empty"
	}
	return headerToken(r, "X-Requested-With") == "xmlhttprequest"
}

// IsPreflight reports whether r is a CORS preflight: an OPTIONS request carrying
// Access-Control-Request-Method. A plain OPTIONS request is not a preflight.
func IsPreflight(r *http.Request) bool {
	if r.Method != http.MethodOptions {
		return false
	}
	_, present := r.Header[http.CanonicalHeaderKey("Access-Control-Request-Method")]
	return present
}

// IsBrowserLike reports whether r carries the headers a current browser sends for a
// subresource request made by a page on siteHost (or one of its subdomains). Not used by
// the challenge path at the moment:
//   - Sec-Fetch-Site, Sec-Fetch-Mode and Sec-Fetch-Dest are all present (non-empty),
//   - Sec-Fetch-Site is "same-origin" or "same-site",
//   - Referer is present and its host is siteHost or a subdomain of siteHost.
//
// These headers are easy to forge, so this is a hint for softening enforcement on
// requests that already look legitimate, never a reason to grant access on its own.
//
// Note the Referer rule is relative to siteHost: a fetch() to api.example.com from a
// page on www.example.com is "same-site" but its Referer host is a sibling, not
// api.example.com or a subdomain of it, so it is not browser-like here.
func IsBrowserLike(r *http.Request, siteHost string) bool {
	site := headerToken(r, "Sec-Fetch-Site")
	if site == "" || headerToken(r, "Sec-Fetch-Mode") == "" || headerToken(r, "Sec-Fetch-Dest") == "" {
		return false
	}
	if site != "same-origin" && site != "same-site" {
		return false
	}

	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return false
	}
	refererURL, err := url.Parse(referer)
	if err != nil {
		return false
	}
	return hostIsOrIsSubdomainOf(refererURL.Hostname(), siteHost)
}

// hostIsOrIsSubdomainOf reports whether host equals parent or is a subdomain of it,
// ignoring case, any port and a trailing dot. An empty host or parent never matches.
func hostIsOrIsSubdomainOf(host string, parent string) bool {
	host = normalizeHost(host)
	parent = normalizeHost(parent)
	if host == "" || parent == "" {
		return false
	}
	return host == parent || strings.HasSuffix(host, "."+parent)
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}
