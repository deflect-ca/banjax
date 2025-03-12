package main

import (
	"flag"
	"io"
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
	time.Sleep(10 * time.Second) //we need MORE time because of the image controller, it needs the time to partition the image BEFORE starting up
}

func tearDown() {
	os.RemoveAll(tmpDir)
}

func createTempDir() {
	dir, err := os.MkdirTemp("", "banjax-tests")
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
	resp := httpRequest(client, resource, t)

	assert.Equal(t, resource.response_code, resp.StatusCode, "Response code is not correct")

	if len(resource.contains) > 0 {
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err, "Error when ready Body from ", resource.method, resource.name)
		resp.Body.Close()
		for _, lookup := range resource.contains {
			assert.Containsf(
				t,
				string(body),
				lookup,
				"Expected string [[ %s ]] not found when testing: %s %s",
				lookup,
				resource.method,
				resource.name,
			)
		}
	}
}

type CookieMap map[string]*http.Cookie

func httpTesterWithCookie(t *testing.T, resources []TestResource) {
	client := &http.Client{}
	for _, resource := range resources {
		test_name := "Test_" + resource.method + "_" + resource.name
		t.Run(test_name, func(t *testing.T) {
			cookies := httpCheckWithCookie(client, &resource, t)
			assert.Contains(t, cookies, resource.contains[0])
			if len(resource.contains) > 1 {
				log.Print(cookies[resource.contains[0]])
				expectedMaxAge, _ := strconv.Atoi(resource.contains[1])
				assert.Equal(t, expectedMaxAge, cookies[resource.contains[0]].MaxAge)
			}
		})
	}
}

func httpCheckWithCookie(client *http.Client, resource_ptr *TestResource, t *testing.T) (cookieMap CookieMap) {
	resource := *resource_ptr
	resp := httpRequest(client, resource, t)

	assert.Equal(t, resource.response_code, resp.StatusCode, "Response code is not correct")

	cookieMap = make(CookieMap)
	if len(resp.Cookies()) > 0 {
		for _, cookie := range resp.Cookies() {
			cookieMap[cookie.Name] = cookie
		}
	}

	return
}

func httpStress(resources []TestResource, repeat int, t *testing.T) {
	var resp *http.Response
	client := http.Client{}
	for _, resource := range resources {
		for i := 0; i <= repeat; i++ {
			resp = httpRequest(&client, resource, t)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}
	}
}

func httpRequest(client *http.Client, resource TestResource, t testing.TB) *http.Response {
	req, err := http.NewRequest(resource.method, endpoint+resource.name, nil)
	assert.Nil(t, err, "Error when creating the request object", resource.method, resource.name)

	for key, values := range resource.headers {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}
	resp, err := client.Do(req)
	assert.Nil(t, err, "Error when doing the request ", resource.method, resource.name, err)

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

func reloadConfig(path string, randomReqCount int, t *testing.T) {
	done := make(chan bool)

	// just to make a mark in log so we know when the reload is done
	httpStress(
		[]TestResource{{"GET", "/auth_request?path=/reloadConfig", 200, randomXClientIP(), nil}},
		1,
		t,
	)

	// Simulate activity of http requests when the config is reloaded
	go func() {
		httpStress(
			[]TestResource{{"GET", "/auth_request?path=/", 200, randomXClientIP(), nil}},
			randomReqCount,
			t,
		)
		done <- true
	}()

	copyConfigFile(path)
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(10 * time.Second) //we need MORE time because of the image controller, it needs the time to partition the image BEFORE starting up
	<-done
}
