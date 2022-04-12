//go:build integration

package main

import (
	"log"
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

func TestAPICalls(t *testing.T) {
	log.Println("TestAPICalls running")
	RunAPICalls()
}

func TestReloadConfig(t *testing.T) {
	log.Println("TestReload running")
	RunAPICalls()
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	RunAPICalls()
}

func RunAPICalls() {
	time.Sleep(1 * time.Second)
}
