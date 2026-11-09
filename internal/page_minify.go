// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"regexp"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"github.com/tdewolff/minify/v2/svg"
)

// preMinifiedJSAvgLineLen: a script whose lines average longer than this is already a
// minified bundle (the inlined ALTCHA widget is one 118 KB line). It is served byte for
// byte instead of being minified again, so it stays the exact pinned upstream file.
const preMinifiedJSAvgLineLen = 1000

// passThroughPreMinifiedJS minifies inline JS, except scripts that are already minified.
func passThroughPreMinifiedJS(m *minify.M, w io.Writer, r io.Reader, params map[string]string) error {
	src, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if len(src) > preMinifiedJSAvgLineLen*(bytes.Count(src, []byte("\n"))+1) {
		_, err = w.Write(src)
		return err
	}
	// keep names: the server's per-request rewrites reference variables by name
	return (&js.Minifier{KeepVarNames: true}).Minify(m, w, bytes.NewReader(src), params)
}

func newPageMinifier() *minify.M {
	m := minify.New()
	m.Add("text/html", &html.Minifier{
		// the server's rewrites match quoted attributes such as challenge="{}"
		KeepQuotes:       true,
		KeepDocumentTags: true,
		KeepEndTags:      true,
	})
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("image/svg+xml", svg.Minify)
	// "module" is how the HTML minifier names <script type="module">; without it,
	// module scripts are left unminified
	m.AddFuncRegexp(regexp.MustCompile(`^(application|text)/(x-)?(javascript|ecmascript)$|^module$`), passThroughPreMinifiedJS)
	return m
}

// minifyChallengePage returns a minified copy of page for serving. Source pages stay
// readable; only the bytes held in Config are minified.
//
// markers are the exact strings the server rewrites per request (modifyHTMLContent and
// friends). A minifier would reformat them ("a" + b becomes "a"+b, quotes get dropped),
// so each one is swapped for an opaque token that is valid as both a JS identifier and
// an HTML attribute name, and swapped back afterwards. If minifying fails or any marker
// does not come back exactly as often as it was in the source, the source page is
// returned unchanged: a smaller page is never worth a challenge that cannot be solved.
func minifyChallengePage(name string, page []byte, markers []string) []byte {
	minified, err := minifyWithMarkers(page, markers)
	if err != nil {
		log.Printf("INIT: serving %s unminified: %v", name, err)
		return page
	}
	log.Printf("INIT: minified %s from %d to %d bytes", name, len(page), len(minified))
	return minified
}

func minifyWithMarkers(page []byte, markers []string) ([]byte, error) {
	protected := page
	tokens := make([][]byte, len(markers))
	counts := make([]int, len(markers))
	for i, marker := range markers {
		tokens[i] = []byte(fmt.Sprintf("bjxkeep%dx", i))
		if bytes.Contains(page, tokens[i]) {
			return nil, fmt.Errorf("page already contains placeholder %q", tokens[i])
		}
		counts[i] = bytes.Count(page, []byte(marker))
		protected = bytes.ReplaceAll(protected, []byte(marker), tokens[i])
	}

	var out bytes.Buffer
	if err := newPageMinifier().Minify("text/html", &out, bytes.NewReader(protected)); err != nil {
		return nil, err
	}

	minified := out.Bytes()
	for i, marker := range markers {
		if got := bytes.Count(minified, tokens[i]); got != counts[i] {
			return nil, fmt.Errorf("marker %q: %d in source, %d after minifying", marker, counts[i], got)
		}
		minified = bytes.ReplaceAll(minified, tokens[i], []byte(marker))
	}
	return minified, nil
}
