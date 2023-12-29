// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.Static("/assets", "./assets")
	r.GET("/hello", func(c *gin.Context) {
		c.String(200, "hello!\n")
	})
	r.NoRoute(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
		c.Header("Content-Type", "text/html; charset=utf-8")
		// c.Header("Cache-Control", "public,max-age=30")
		var page string = "<html><head><title>Banjax test-origin</title>"
		page = page + "<style>body{padding: 2em;background-color:rgb(236, 236, 226);}</style></head>"
		page = page + "<body><img src=\"assets/deflect_100.png\">"
		page = page + "<h1>Requested URL: " + c.Request.URL.Path + "</h1>"
		page = page + "Banjax test-origin @ " + time.Now().UTC().Format("15:04:05") + " UTC+0</body>"
		c.String(404, page)
	})
	r.Run("0.0.0.0:8080")
}
