//go:build integration

package main

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

const endpoint = "http://localhost:8081"

func TestMain(m *testing.M) {
	setUp()
	os.Exit(m.Run())
}

func setUp() {
	go main()
	time.Sleep(1 * time.Second)
}

type TestResource struct {
	method        string
	name          string
	response_code int
	headers       http.Header
}

func HTTPTester(t *testing.T, resources []TestResource) {
	client := &http.Client{}
	for _, resource := range resources {
		test_name := "Test_" + resource.method + "_" + resource.name
		t.Run(test_name, func(t *testing.T) {
			req, err := http.NewRequest(resource.method, endpoint+resource.name, nil)
			if err != nil {
				t.Error("Error when creating the request object",
					resource.method, resource.name)
			}
			for key, values := range resource.headers {
				for _, value := range values {
					req.Header.Set(key, value)
				}
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Error("Error when making the request", resource.method, resource.name)
			}
			if resp.StatusCode != resource.response_code {
				t.Errorf("Expected %d and got %d when testing %s %s",
					resource.response_code, resp.StatusCode, resource.method, resource.name)
			}
		})
	}
}

func TestBanjaxEndpoint(t *testing.T) {
	banjax_resources := []TestResource{
		{"GET", "/auth_request", 200, nil},
		{"POST", "/auth_request", 200, nil},
		{"PUT", "/auth_request", 200, nil},
		{"PATCH", "/auth_request", 200, nil},
		{"HEAD", "/auth_request", 200, nil},
		{"OPTIONS", "/auth_request", 200, nil},
		{"DELETE", "/auth_request", 200, nil},
		{"CONNECT", "/auth_request", 200, nil},
		{"TRACE", "/auth_request", 200, nil},
		{"GET", "/info", 200, nil},
		{"GET", "/decision_lists", 200, nil},
		{"GET", "/rate_limit_states", 200, nil},
	}
	HTTPTester(t, banjax_resources)
}

func TestReloadProtectedResources(t *testing.T) {
	HTTPTester(t, []TestResource{{"GET", "/auth_request?path=wp-admin", 401, nil}})
	reloadBanjax()
	addProtectedResourceToConfig("wp-admin2")
	HTTPTester(t, []TestResource{{"GET", "/auth_request?path=wp-admin2", 401, nil}})
}

func reloadBanjax() {
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(1 * time.Second)
}

func addProtectedResourceToConfig(path string) bool {
	// TODO: Implement the logic to save a copy of the config file in a temp dir
	//       and add the protected resource before reloading Banjax.
	return true
}
