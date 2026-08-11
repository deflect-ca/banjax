// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
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

	r.NoRoute(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
		c.Header("Content-Type", "text/html; charset=utf-8")
		// c.Header("Cache-Control", "public,max-age=30")
		var page string = "<html><head><title>Banjax test-origin</title>"
		page = page + "<style>body{padding: 2em;background-color:rgb(236, 236, 226);}</style></head>"
		page = page + "<body><img src=\"/assets/deflect_100.png\">"
		page = page + "<h1>Requested URL: " + c.Request.URL.Path + "</h1>"
		page = page + "Banjax test-origin @ " + time.Now().UTC().Format("15:04:05") + " UTC+0</body>"
		c.String(404, page)
	})
	r.Run("0.0.0.0:8080")
}
