package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const endpoint = "http://localhost:8081"
const fixtureConfigTest = "./fixtures/banjax-config-test.yaml"
const fixtureConfigTestReload = "./fixtures/banjax-config-test-reload.yaml"
const fixtureConfigTestShaInv = "./fixtures/banjax-config-test-sha-inv.yaml"
const fixtureConfigTestRegexBanner = "./fixtures/banjax-config-test-regex-banner.yaml"
const fixtureConfigTestReloadCIDR = "./fixtures/banjax-config-test-reload-cidr.yaml"
const fixtureConfigTestPersiteFail = "./fixtures/banjax-config-test-persite-fail.yaml"

var tmpDir string
var configFile string

func setUp() {
	createTempDir()
	copyConfigFile(fixtureConfigTest)
	setCommandLineFlags()
	log.SetFlags(log.LstdFlags | log.Lshortfile) // show line num in logs
	go main()
	time.Sleep(1 * time.Second)
}

func tearDown() {
	os.RemoveAll(tmpDir)
}

func createTempDir() {
	dir, err := ioutil.TempDir("", "banjax-tests")
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
	flag.Parse()
	os.Args = []string{os.Args[0]}
	os.Args = append(os.Args, "-config-file", configFile)
	os.Args = append(os.Args, "-standalone-testing")
	os.Args = append(os.Args, "-debug")
}

type TestResource struct {
	method        string
	name          string
	response_code int
	headers       http.Header
	contains      []string
}

func httpTester(t *testing.T, resources []TestResource) {
	client := &http.Client{}
	for _, resource := range resources {
		test_name := "Test_" + resource.method + "_" + resource.name
		t.Run(test_name, func(t *testing.T) {
			httpCheck(client, &resource, t)
		})
	}
}

func httpCheck(client *http.Client, resource_ptr *TestResource, t *testing.T) {
	resource := *resource_ptr
	resp := httpRequest(client, resource)

	assert.Equal(t, resource.response_code, resp.StatusCode, "Response code is not correct")

	if len(resource.contains) > 0 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal("Error when ready Body from ", resource.method, resource.name)
		}
		resp.Body.Close()
		for _, lookup := range resource.contains {
			if !strings.Contains(string(body), lookup) {
				log.Fatalf("Expected string [[ %s ]] not found when testing: %s %s",
					lookup, resource.method, resource.name)
			}
		}
	}
}

func httpStress(resources []TestResource, repeat int) {
	var resp *http.Response
	client := http.Client{}
	for _, resource := range resources {
		for i := 0; i <= repeat; i++ {
			resp = httpRequest(&client, resource)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}
	}
}

func httpRequest(client *http.Client, resource TestResource) *http.Response {
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
		log.Fatal("Error when doing the request ", resource.method, resource.name, err)
	}

	if req != nil && req.Body != nil {
		req.Body.Close()
	}
	return resp
}

func randomXClientIP() http.Header {
	return http.Header{"X-Client-IP": {randomIP()}}
}

func ClientIP(ip string) http.Header {
	return http.Header{"X-Client-IP": {ip}}
}

func randomIP() string {
	octets := []string{}
	for i := 0; i < 4; i++ {
		octet := rand.Intn(252)
		octets = append(octets, strconv.Itoa(octet))
	}
	return strings.Join(octets, ".")
}

func reloadConfig(path string, randomReqCount int) {
	done := make(chan bool)

	// just to make a mark in log so we know when the reload is done
	httpStress(
		[]TestResource{{"GET", "/auth_request?path=/reloadConfig", 200, randomXClientIP(), nil}}, 1)

	// Simulate activity of http requests when the config is reloaded
	go func() {
		httpStress(
			[]TestResource{{"GET", "/auth_request?path=/", 200, randomXClientIP(), nil}},
			randomReqCount)
		done <- true
	}()

	copyConfigFile(path)
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(1 * time.Second)
	<-done
}
