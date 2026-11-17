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

// subresourceModes are the Sec-Fetch-Mode values of a request the browser will not render
// as a page. "navigate" is the only other value browsers send.
var subresourceModes = map[string]bool{
	"cors":        true,
	"no-cors":     true,
	"same-origin": true,
	"websocket":   true,
}

// subresourceDests are the Sec-Fetch-Dest values of a request whose response is consumed
// by script or a subresource loader, never rendered as a page. Left out on purpose: the
// page destinations (document, iframe, frame, embed, object, fencedframe) and any value
// browsers may add later, which fall back to the HTML challenge until listed here.
var subresourceDests = map[string]bool{
	"empty":         true, // fetch(), XMLHttpRequest, EventSource, sendBeacon; Firefox WebSocket
	"websocket":     true, // Chromium WebSocket
	"audio":         true,
	"audioworklet":  true,
	"font":          true,
	"image":         true,
	"json":          true,
	"manifest":      true,
	"paintworklet":  true,
	"report":        true,
	"script":        true,
	"serviceworker": true,
	"sharedworker":  true,
	"style":         true,
	"track":         true,
	"video":         true,
	"worker":        true,
	"xslt":          true,
}

// IsSubresource reports whether r is a browser request whose response the browser will
// not render as a page: fetch() or XMLHttpRequest, an image, script, stylesheet, font,
// media file, worker, WebSocket handshake and so on. Such a request can't display an
// HTML challenge, so banjax answers a challenged one with a 403 JSON error instead (see
// xhrChallenge) and does not count it toward the failed challenge ban.
//
// Because that exempts the request from counting, the check is strict and any header
// combination a browser would not send counts as a page request (HTML challenge,
// counted):
//   - Sec-Fetch-Mode must be cors, no-cors, same-origin or websocket, and Sec-Fetch-Dest
//     a subresource destination (subresourceDests).
//   - A WebSocket mode goes with a websocket or empty destination, and a websocket
//     destination with the websocket mode only.
//   - Sec-Fetch-Site must be present and not "none" (sent only for user-typed navigations).
//   - Sec-Fetch-User must be absent (sent only on user-activated navigations).
//   - Without Sec-Fetch-Mode (older browsers, or plain http to a non-localhost host) no
//     other Sec-Fetch-* header may be present, and only X-Requested-With: XMLHttpRequest
//     (sent by jQuery and many frameworks) marks one.
//
// A non-browser client (curl, most bots) sends none of these, so it keeps getting the HTML
// challenge and keeps counting toward the ban. All of them can be forged, but a bot has to
// choose to, and has to forge a consistent set.
func IsSubresource(r *http.Request) bool {
	mode := headerToken(r, "Sec-Fetch-Mode")
	dest := headerToken(r, "Sec-Fetch-Dest")
	site := headerToken(r, "Sec-Fetch-Site")
	_, hasUser := r.Header[http.CanonicalHeaderKey("Sec-Fetch-User")]

	if mode == "" {
		// A lone Sec-Fetch-Dest: empty is tolerated: WebKit rolled the headers out in stages,
		// and it adds nothing a client could not claim with X-Requested-With anyway.
		if (dest != "" && dest != "empty") || site != "" || hasUser {
			return false
		}
		return headerToken(r, "X-Requested-With") == "xmlhttprequest"
	}
	if hasUser || site == "" || site == "none" {
		return false
	}
	if !subresourceModes[mode] || !subresourceDests[dest] {
		return false
	}
	if mode == "websocket" {
		return dest == "websocket" || dest == "empty"
	}
	return dest != "websocket"
}

// IsPreflight reports whether r is a CORS preflight: an OPTIONS request carrying
// Access-Control-Request-Method and a non-empty Origin, which browsers always send on a
// preflight. A plain OPTIONS request is not a preflight. Both headers can be forged, so
// this lets a request skip a challenge (see skipChallenge in decisionForNginx2), never a block.
func IsPreflight(r *http.Request) bool {
	if r.Method != http.MethodOptions || strings.TrimSpace(r.Header.Get("Origin")) == "" {
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
