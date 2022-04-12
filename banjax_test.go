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

func TestBanjaxAPI(t *testing.T) {
	log.Println("Testing Banjax API")
	_, err := http.Get("http://127.0.0.1:8081")
	if err != nil {
		t.Error()
	}
}

func TestReloadConfig(t *testing.T) {
	log.Println("TestReload running")
	TestBanjaxAPI(t)
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	TestBanjaxAPI(t)
}
