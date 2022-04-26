//go:build performance

package main

import (
	"net/http"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	setUp()
	exit_code := m.Run()
	tearDown()
	os.Exit(exit_code)
}

func BenchmarkAuthRequest(b *testing.B) {
	var resp *http.Response
	client := http.Client{}
	for i := 0; i < b.N; i++ {
		resp = httpRequest(
			&client,
			TestResource{"GET", "/auth_request", 200, randomXClientIP(), nil},
		)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}
}
