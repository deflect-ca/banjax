// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"testing"
	"time"
)

func TestLogThrottleShouldLog(t *testing.T) {
	s := &LogThrottleStates{states: make(map[string]time.Time)}
	interval := 60 * time.Second
	base := time.Unix(1_700_000_000, 0)
	key := "1.2.3.4|example.com|global_ip_list"

	if !s.ShouldLog(key, interval, base) {
		t.Fatal("first call should log")
	}
	if s.ShouldLog(key, interval, base.Add(30*time.Second)) {
		t.Fatal("second call within interval should be throttled")
	}
	if !s.ShouldLog(key, interval, base.Add(61*time.Second)) {
		t.Fatal("call after interval should log again")
	}
	// after logging again at base+61s, base+91s is within the interval -> throttled
	if s.ShouldLog(key, interval, base.Add(91*time.Second)) {
		t.Fatal("call within interval of the most recent log should be throttled")
	}

	// a different key is tracked independently
	if !s.ShouldLog("5.6.7.8|example.com|global_ip_list", interval, base.Add(30*time.Second)) {
		t.Fatal("different key should log")
	}
}

func TestLogThrottleRelease(t *testing.T) {
	s := &LogThrottleStates{states: make(map[string]time.Time)}
	interval := 60 * time.Second
	base := time.Unix(1_700_000_000, 0)
	key := "1.2.3.4|example.com|global_ip_list"

	if !s.ShouldLog(key, interval, base) {
		t.Fatal("first call should log")
	}
	// Without a release, a follow-up within the interval is throttled.
	if s.ShouldLog(key, interval, base.Add(1*time.Second)) {
		t.Fatal("second call within interval should be throttled before release")
	}
	// Releasing the reservation (e.g. the line was dropped) lets the next request log.
	s.Release(key)
	if !s.ShouldLog(key, interval, base.Add(2*time.Second)) {
		t.Fatal("call after release should log again even within the interval")
	}

	// Releasing an unknown key is a no-op and must not panic.
	s.Release("never|seen|key")
}

func TestAsyncBanLoggerEnqueueReportsDrop(t *testing.T) {
	a := &AsyncBanLogger{queue: make(chan bannerLogEntry, 1)}
	// Note: no run() goroutine is started, so nothing drains the queue.

	if !a.Enqueue("first", false) {
		t.Fatal("first enqueue should succeed (queue has capacity 1)")
	}
	if a.Enqueue("second", false) {
		t.Fatal("second enqueue should report drop (queue full)")
	}
	if got := a.dropped.Load(); got != 1 {
		t.Fatalf("expected dropped count 1, got %d", got)
	}
}

func TestLogThrottlePrune(t *testing.T) {
	s := &LogThrottleStates{states: make(map[string]time.Time)}
	interval := 60 * time.Second
	base := time.Unix(1_700_000_000, 0)

	s.ShouldLog("stale", interval, base)
	s.ShouldLog("fresh", interval, base.Add(120*time.Second))

	// prune at base+130s with interval 60s: "stale" (130s old) goes, "fresh" (10s old) stays
	s.prune(base.Add(130*time.Second), interval)

	if _, ok := s.states["stale"]; ok {
		t.Fatal("stale entry should have been pruned")
	}
	if _, ok := s.states["fresh"]; !ok {
		t.Fatal("fresh entry should remain")
	}
	if s.Len() != 1 {
		t.Fatalf("expected 1 entry after prune, got %d", s.Len())
	}
}
