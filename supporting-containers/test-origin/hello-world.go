// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// resource is the thing the PUT/DELETE endpoints operate on, so a test can
// check the origin really applied the change and not just returned 200.
type resource struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

// store is an in-memory resource table. Seeded so PUT/DELETE have something to
// hit on a fresh container.
var store = struct {
	sync.Mutex
	items map[string]resource
}{items: map[string]resource{
	"1": {ID: "1", Name: "first", Value: "seeded"},
	"2": {ID: "2", Name: "second", Value: "seeded"},
}}

// requestReport is what the origin actually saw. When a request is proxied
// through nginx + banjax the body can get dropped on the way (e.g. by
// proxy_pass_request_body off on the auth_request location), so every endpoint
// reports the body it received alongside the Content-Length the client claimed.
type requestReport struct {
	Method            string `json:"method"`
	Path              string `json:"path"`
	Proto             string `json:"proto"`
	ContentType       string `json:"content_type"`
	ContentLengthHdr  string `json:"content_length_header"`
	BodyBytesReceived int    `json:"body_bytes_received"`
	Body              string `json:"body"`
	BodyComplete      bool   `json:"body_complete"`
	ReadError         string `json:"read_error,omitempty"`
	XForwardedFor     string `json:"x_forwarded_for"`
	DeflectSession    string `json:"deflect_session"`
}

// readRequest drains the request body and describes what arrived. It never
// fails the request on a read error; the error is reported in the body instead
// so the test script can see how the proxy chain truncated things.
func readRequest(c *gin.Context) (requestReport, []byte) {
	body, err := io.ReadAll(c.Request.Body)

	report := requestReport{
		Method:            c.Request.Method,
		Path:              c.Request.URL.Path,
		Proto:             c.Request.Proto,
		ContentType:       c.ContentType(),
		ContentLengthHdr:  c.GetHeader("Content-Length"),
		BodyBytesReceived: len(body),
		Body:              string(body),
		XForwardedFor:     c.GetHeader("X-Forwarded-For"),
	}
	if err != nil {
		report.ReadError = err.Error()
	}

	// BodyComplete tells you at a glance whether the body survived the proxy
	// chain: we got as many bytes as the client said it sent.
	claimed, convErr := strconv.Atoi(report.ContentLengthHdr)
	report.BodyComplete = convErr == nil && claimed == len(body)
	if report.ContentLengthHdr == "" {
		report.BodyComplete = len(body) > 0
	}

	if cookie, err := c.Cookie("deflect_session"); err == nil {
		report.DeflectSession = cookie
	}

	return report, body
}

// handleLogin simulates a login form POST. Credentials are accepted from either
// a JSON body or a urlencoded form so both content types can be exercised.
func handleLogin(c *gin.Context) {
	report, body := readRequest(c)

	var creds struct {
		Username string `json:"username" form:"username"`
		Password string `json:"password" form:"password"`
	}

	// Bind by hand from the bytes we already read: c.ShouldBind consumes the
	// body, and we need the raw copy for the report.
	switch {
	case len(body) == 0:
		c.JSON(http.StatusBadRequest, gin.H{
			"ok":      false,
			"error":   "empty request body - the POST body never reached the origin",
			"request": report,
		})
		return
	case c.ContentType() == "application/json":
		if err := json.Unmarshal(body, &creds); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"error":   "malformed json: " + err.Error(),
				"request": report,
			})
			return
		}
	default:
		values, err := url.ParseQuery(string(body))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"error":   "malformed form body: " + err.Error(),
				"request": report,
			})
			return
		}
		creds.Username = values.Get("username")
		creds.Password = values.Get("password")
	}

	// Any non-empty username with the password "correct-horse" logs in. This is
	// a test origin; there is nothing to protect here.
	if creds.Username == "" || creds.Password != "correct-horse" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"ok":      false,
			"error":   "invalid credentials",
			"request": report,
		})
		return
	}

	c.SetCookie("test_origin_session", "session-for-"+creds.Username, 3600, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"username": creds.Username,
		"request":  report,
	})
}

// handleUpdateResource simulates an API client modifying a resource with PUT.
func handleUpdateResource(c *gin.Context) {
	report, body := readRequest(c)
	id := c.Param("id")

	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"ok":      false,
			"error":   "empty request body - the PUT body never reached the origin",
			"request": report,
		})
		return
	}

	var update struct {
		Name  *string `json:"name"`
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(body, &update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"ok":      false,
			"error":   "malformed json: " + err.Error(),
			"request": report,
		})
		return
	}

	store.Lock()
	defer store.Unlock()

	existing, found := store.items[id]
	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"ok":      false,
			"error":   "no resource with id " + id,
			"request": report,
		})
		return
	}

	before := existing
	if update.Name != nil {
		existing.Name = *update.Name
	}
	if update.Value != nil {
		existing.Value = *update.Value
	}
	existing.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	store.items[id] = existing

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"before":   before,
		"resource": existing,
		"request":  report,
	})
}

// handleDeleteResource simulates an API client deleting a resource. DELETE
// usually carries no body, so an absent one is not an error here.
func handleDeleteResource(c *gin.Context) {
	report, _ := readRequest(c)
	id := c.Param("id")

	store.Lock()
	defer store.Unlock()

	deleted, found := store.items[id]
	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"ok":      false,
			"error":   "no resource with id " + id,
			"request": report,
		})
		return
	}
	delete(store.items, id)

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"deleted": deleted,
		"request": report,
	})
}

// handleListResources lets a test confirm the state the writes left behind.
func handleListResources(c *gin.Context) {
	store.Lock()
	defer store.Unlock()

	ids := make([]string, 0, len(store.items))
	for id := range store.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	items := make([]resource, 0, len(ids))
	for _, id := range ids {
		items = append(items, store.items[id])
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "resources": items})
}

// handleResetResources restores the seed data so a test script can re-run.
func handleResetResources(c *gin.Context) {
	store.Lock()
	defer store.Unlock()

	store.items = map[string]resource{
		"1": {ID: "1", Name: "first", Value: "seeded"},
		"2": {ID: "2", Name: "second", Value: "seeded"},
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "reset": true})
}

// handleEcho answers any method on /echo with a plain report of what arrived.
// This is the endpoint to reach for when the question is only "did the body
// make it through the proxy chain?".
func handleEcho(c *gin.Context) {
	report, _ := readRequest(c)
	c.JSON(http.StatusOK, gin.H{"ok": true, "request": report})
}

// spaPage is a small single-page app for testing how banjax challenges requests that
// cannot show a challenge page: fetch(), XHR, <img>, <script>, <link rel=stylesheet>,
// no-cors and cross-origin calls to /spa/api/*, plus an iframe and a reload that still
// get the HTML challenge page. Per call it shows what banjax answered.
//
//go:embed spa.html
var spaPage []byte

// spaFramePage is what /spa/app/frame answers when banjax lets the request through:
// a tiny page (not the SPA, which would start polling inside the iframe) that the
// SPA's iframe test recognises by its marker element. A challenged iframe gets the
// HTML challenge page instead, which has no such marker.
const spaFramePage = `<!doctype html><html><head><meta charset="utf-8"><title>SPA frame</title></head>` +
	`<body style="font:14px system-ui;margin:.5em"><p id="spa-frame-ok">Frame loaded: banjax let this iframe through to the origin.</p></body></html>`

func serveSPA(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
	if c.Param("route") == "/frame" {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(spaFramePage))
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", spaPage)
}

// spaAPI is the JSON the SPA's API calls get. The API lives under /spa/api/
// with no file extension because nginx sends *.json (and *.js) paths straight
// to the origin, so they would never reach banjax.
func spaAPI(c *gin.Context, body gin.H) {
	c.Header("Cache-Control", "no-store")
	body["ok"] = true
	body["server_time"] = time.Now().UTC().Format("15:04:05")
	c.JSON(http.StatusOK, body)
}

func handleSPAFeed(c *gin.Context) {
	t := time.Now().UTC().Format("15:04:05")
	spaAPI(c, gin.H{"items": []gin.H{
		{"title": "Latest article", "time": t},
		{"title": "Comment on your post", "time": t},
		{"title": "Weekly digest", "time": t},
	}})
}

func handleSPANotifications(c *gin.Context) {
	spaAPI(c, gin.H{"unread": time.Now().Second() % 5})
}

func handleSPALike(c *gin.Context) {
	spaAPI(c, gin.H{"liked": true})
}

func handleSPARoute(c *gin.Context) {
	spaAPI(c, gin.H{"route": c.Param("route")})
}

// handleSPAWhoami reports the request headers the origin received, so you can
// see what nginx passed through, and the deflect_session cookie for sending a
// challenge_session command (the cookie is not readable from JavaScript).
func handleSPAWhoami(c *gin.Context) {
	session, _ := c.Cookie("deflect_session")
	spaAPI(c, gin.H{
		"deflect_session": session,
		"host":            c.Request.Host,
		"headers": gin.H{
			"Sec-Fetch-Site": c.GetHeader("Sec-Fetch-Site"),
			"Sec-Fetch-Mode": c.GetHeader("Sec-Fetch-Mode"),
			"Sec-Fetch-Dest": c.GetHeader("Sec-Fetch-Dest"),
			"Referer":        c.GetHeader("Referer"),
			"Accept":         c.GetHeader("Accept"),
		},
	})
}

// onePixelPNG is a 1x1 transparent PNG for the <img> test.
var onePixelPNG, _ = base64.StdEncoding.DecodeString(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")

// The three endpoints below are loaded by <img>, <script> and <link rel=stylesheet>.
// Their paths have no file extension on purpose: nginx sends *.png, *.js and *.css
// straight to the origin, so those requests would never reach banjax.
func handleSPAPixel(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "image/png", onePixelPNG)
}

func handleSPAScript(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/javascript", []byte("window.__spaScriptLoaded = Date.now();\n"))
}

func handleSPAStyle(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/css", []byte("#spa-style-probe { outline: 0; }\n"))
}

// spaCORS lets the SPA open on localhost call /spa/api/* on www.localhost and the other
// way round (any scheme or port), with cookies, so the cross-origin test can force a
// preflight. Any other Origin gets no CORS headers. A CORS preflight is answered here
// with 204: banjax skips challenges for it and lets it reach the origin.
func spaCORS(c *gin.Context) {
	c.Header("Vary", "Origin")
	if origin := c.GetHeader("Origin"); spaOriginAllowed(origin) {
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, X-SPA-Test")
		c.Header("Access-Control-Expose-Headers", "X-Banjax-Decision")
	}
	if c.Request.Method == http.MethodOptions {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	c.Next()
}

func spaOriginAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return u.Hostname() == "localhost" || u.Hostname() == "www.localhost"
}

func main() {
	r := gin.Default()
	r.Static("/assets", "./assets")
	r.GET("/hello", func(c *gin.Context) {
		c.String(200, "hello!\n")
	})

	r.POST("/login", handleLogin)
	r.PUT("/api/resources/:id", handleUpdateResource)
	r.DELETE("/api/resources/:id", handleDeleteResource)
	r.GET("/api/resources", handleListResources)
	r.POST("/api/resources/reset", handleResetResources)
	r.Any("/echo", handleEcho)

	r.GET("/spa", serveSPA)
	r.GET("/spa/app/*route", serveSPA) // client-side routes, so a reload on one still works
	api := r.Group("/spa/api", spaCORS)
	api.OPTIONS("/*any", func(c *gin.Context) {}) // spaCORS answers it
	api.GET("/feed", handleSPAFeed)
	api.GET("/notifications", handleSPANotifications)
	api.POST("/like", handleSPALike)
	api.GET("/route/:route", handleSPARoute)
	api.GET("/whoami", handleSPAWhoami)
	api.GET("/pixel", handleSPAPixel)
	api.GET("/script", handleSPAScript)
	api.GET("/style", handleSPAStyle)

	r.NoRoute(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
		c.Header("Content-Type", "text/html; charset=utf-8")
		// c.Header("Cache-Control", "public,max-age=30")
		var page string = "<html><head><title>Banjax test-origin</title>"
		page = page + "<style>body{padding: 2em;background-color:rgb(236, 236, 226);}</style></head>"
		page = page + "<body><img src=\"/assets/deflect_100.png\">"
		page = page + "<h1>Requested URL: " + c.Request.URL.Path + "</h1>"
		page = page + "<p><a href=\"/spa\">SPA test page</a>: fetch/XHR/img/script/style/iframe requests, for testing how banjax challenges requests that cannot show a page</p>"
		page = page + "Banjax test-origin @ " + time.Now().UTC().Format("15:04:05") + " UTC+0</body>"
		c.String(404, page)
	})
	r.Run("0.0.0.0:8080")
}
