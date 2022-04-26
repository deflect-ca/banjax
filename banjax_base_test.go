package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const endpoint = "http://localhost:8081"
const fixtureConfigTest = "./fixtures/banjax-config-test.yaml"

var tmpDir string
var configFile string

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
	flag.Parse()
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
	ip := fmt.Sprintf("10.2.0.%d", rand.Intn(252))
	return http.Header{"X-Client-IP": {ip}}
}
