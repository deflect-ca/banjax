//go:build integration

package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

const endpoint = "http://127.0.0.1:8081"

func TestMain(m *testing.M) {
	defer tearDown()
	setUp()
	os.Exit(m.Run())
}

func tearDown() {
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
}

func setUp() {
	go exitCallback()
	go main()
	time.Sleep(1 * time.Second)
}

func exitCallback() int {
	sigint_channel := make(chan os.Signal, 1)
	signal.Notify(sigint_channel, syscall.SIGINT)
	for _ = range sigint_channel {
		log.Println("SIGINT received; stopping Banjax")
		os.Exit(0)
	}
	return 1
}

type TestResource struct {
	method        string
	name          string
	response_code int
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
		{"GET", "/auth_request", 200},
		{"POST", "/auth_request", 200},
		{"PUT", "/auth_request", 200},
		{"PATCH", "/auth_request", 200},
		{"HEAD", "/auth_request", 200},
		{"OPTIONS", "/auth_request", 200},
		{"DELETE", "/auth_request", 200},
		{"CONNECT", "/auth_request", 200},
		{"TRACE", "/auth_request", 200},
		{"GET", "/info", 200},
		{"GET", "/decision_lists", 200},
		{"GET", "/rate_limit_states", 200},
	}
	HTTPTester(t, banjax_resources)
}

func TestReloadConfig(t *testing.T) {
	log.Println("TestReload running")
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	time.Sleep(1 * time.Second)
	TestBanjaxEndpoint(t)
}
