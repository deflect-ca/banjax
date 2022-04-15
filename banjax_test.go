//go:build integration

package main

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const endpoint = "http://localhost:8081"

var tmpDir string
var configFile string

func TestMain(m *testing.M) {
	setUp()
	exit_code := m.Run()
	tearDown()
	os.Exit(exit_code)
}

func setUp() {
	createTempDir()
	copyConfigFile("./fixtures/banjax-config-test.yaml")
	setCommandLineFlags()
	go main()
	time.Sleep(1 * time.Second)
}

func tearDown() {
	os.RemoveAll(tmpDir)
}

func createTempDir() {
	dir, err := ioutil.TempDir("", "banjax-integration-tests")
	if err != nil {
		log.Fatal(err)
	}
	tmpDir = dir
}

func copyConfigFile(src string) {
	source, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()

	dst := filepath.Join(tmpDir, "banjax-config.yaml")
	dest, err := os.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	if err != nil {
		log.Fatal(err)
	}

	configFile = dst
}

func setCommandLineFlags() {
	os.Args = []string{os.Args[0]}
	os.Args = append(os.Args, "-config-file", configFile)
	os.Args = append(os.Args, "-standalone-testing")
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
	copyConfigFile("./fixtures/banjax-config-test-reload.yaml")
	reloadBanjax()
	HTTPTester(t, []TestResource{{"GET", "/auth_request?path=wp-admin2", 401, nil}})
}

func reloadBanjax() {
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(1 * time.Second)
}
