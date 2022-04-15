//go:build integration

package main

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	contains      []string
}

func httpTester(t *testing.T, resources []TestResource) {
	client := http.Client{}
	for _, resource := range resources {
		test_name := "Test_" + resource.method + "_" + resource.name
		t.Run(test_name, func(t *testing.T) {
			resp := httpRequest(client, resource)

			if resp.StatusCode != resource.response_code {
				t.Errorf("Expected %d and got %d when testing %s %s",
					resource.response_code, resp.StatusCode, resource.method, resource.name)
			}

			if len(resource.contains) > 0 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Fatal("Error when ready Body from ", resource.method, resource.name)
				}
				resp.Body.Close()
				for _, lookup := range resource.contains {
					if !strings.Contains(string(body), lookup) {
						t.Errorf("Expected string [[ %s ]] not found when testing: %s %s",
							lookup, resource.method, resource.name)
					}
				}
			}

		})
	}
}

func httpRequest(client http.Client, resource TestResource) *http.Response {
	req, err := http.NewRequest(resource.method, endpoint+resource.name, nil)
	if err != nil {
		log.Fatal("Error when creating the request object",
			resource.method, resource.name)
	}
	for key, values := range resource.headers {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error when doing the request", resource.method, resource.name)
	}
	return resp
}

func TestBanjaxEndpoint(t *testing.T) {
	banjax_resources := []TestResource{
		{"GET", "/auth_request", 200, nil, nil},
		{"POST", "/auth_request", 200, nil, nil},
		{"PUT", "/auth_request", 200, nil, nil},
		{"PATCH", "/auth_request", 200, nil, nil},
		{"HEAD", "/auth_request", 200, nil, nil},
		{"OPTIONS", "/auth_request", 200, nil, nil},
		{"DELETE", "/auth_request", 200, nil, nil},
		{"CONNECT", "/auth_request", 200, nil, nil},
		{"TRACE", "/auth_request", 200, nil, nil},
		{"GET", "/info", 200, nil, nil},
		{"GET", "/decision_lists", 200, nil, nil},
		{"GET", "/rate_limit_states", 200, nil, nil},
	}
	httpTester(t, banjax_resources)
}

func TestReloadProtectedResources(t *testing.T) {
	protected_res := "wp-admin"
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-01-02"}},
		{"GET", "/auth_request?path=" + protected_res, 401, nil, nil},
	})
	copyConfigFile("./fixtures/banjax-config-test-reload.yaml")
	reloadBanjax()
	protected_res = "wp-admin2"
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		{"GET", "/auth_request?path=" + protected_res, 401, nil, nil},
	})
}

func reloadBanjax() {
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(1 * time.Second)
}
