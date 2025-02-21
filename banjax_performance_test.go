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
			TestResource{"GET", "/auth_request", 0, randomXClientIP(), nil},
			b,
		)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}
}

func BenchmarkProtectedPaths(b *testing.B) {
	var resp *http.Response
	client := http.Client{}
	prefix := "/auth_request?path="
	protected_paths := []TestResource{
		// protected resources
		{"GET", prefix + "wp-admin", 0, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin", 0, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin//", 0, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin.php", 0, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin.php#test", 0, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin.php?a=1&b=2", 0, randomXClientIP(), nil},
		// exceptions
		{"GET", prefix + "wp-admin/admin-ajax.php", 0, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php", 0, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php?a=1", 0, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php?a=1&b=2", 0, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php#test", 0, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin-ajax.php/", 0, randomXClientIP(), nil},
	}

	for i := 0; i < b.N; i++ {
		for _, protected_resource := range protected_paths {
			resp = httpRequest(
				&client,
				protected_resource,
				b,
			)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}
	}

}
