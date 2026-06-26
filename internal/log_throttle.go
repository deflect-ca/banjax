// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// LogThrottleStates tracks, per client key, the last time a banning-log line was
// written for that key. It is used to throttle the high-volume per-request block
// logging from Banner.LogListDecision so a given client is logged at most once per
// interval. Mirrors the rate-limit state pattern in rate_limit.go.
type LogThrottleStates struct {
	mutex  sync.Mutex
	states map[string]time.Time // key -> last-logged time
}

// NewLogThrottleStates creates the throttle state and starts a background goroutine
// that periodically prunes stale entries so the map stays bounded under a distributed
// attack (the rate-limit state maps never prune; this one does).
func NewLogThrottleStates(configHolder *ConfigHolder) *LogThrottleStates {
	s := &LogThrottleStates{states: make(map[string]time.Time)}

	go func() {
		for range time.NewTicker(time.Minute).C {
			config := configHolder.Get()
			interval := time.Duration(config.DecisionLogThrottleIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = time.Minute
			}
			s.prune(time.Now(), interval)
		}
	}()

	return s
}

// ShouldLog reports whether key may be logged now, recording the time when it returns true.
func (s *LogThrottleStates) ShouldLog(key string, interval time.Duration, now time.Time) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if last, ok := s.states[key]; ok && now.Sub(last) < interval {
		return false
	}
	s.states[key] = now
	return true
}

// Release removes a key's throttle reservation. It undoes a ShouldLog that recorded a
// log which then failed to be written (e.g. the async queue was full and the line was
// dropped), so a later request for the same client can be logged instead of being
// suppressed for the rest of the interval over a line that never landed. Because a key
// is reserved by exactly one ShouldLog winner at a time (concurrent callers get false),
// deleting is safe: ShouldLog only records when there was no fresh entry to preserve.
func (s *LogThrottleStates) Release(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.states, key)
}

// prune deletes entries last logged more than interval ago. They are useless for
// throttling once older than interval (ShouldLog would return true and overwrite),
// so removing them only frees memory.
func (s *LogThrottleStates) prune(now time.Time, interval time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for key, last := range s.states {
		if now.Sub(last) > interval {
			delete(s.states, key)
		}
	}
}

// Len returns the number of tracked keys.
func (s *LogThrottleStates) Len() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return len(s.states)
}

// bannerLogEntry is one queued banning-log line.
type bannerLogEntry struct {
	line string
	temp bool // true => LoggerTemp (disable_logging host), false => Logger
}

// AsyncBanLogger decouples banning-log writes from the request hot path. Callers
// enqueue a marshaled line (non-blocking); a single dedicated goroutine drains the
// queue and performs the synchronous disk write. When the queue is full the line is
// dropped rather than blocking nginx's auth_request critical path.
type AsyncBanLogger struct {
	Logger     *log.Logger
	LoggerTemp *log.Logger
	queue      chan bannerLogEntry
	dropped    atomic.Uint64
}

// NewAsyncBanLogger starts the writer goroutine and a periodic reporter that surfaces
// dropped-line counts (so drops are never silent).
func NewAsyncBanLogger(logger *log.Logger, loggerTemp *log.Logger, queueSize int) *AsyncBanLogger {
	a := &AsyncBanLogger{
		Logger:     logger,
		LoggerTemp: loggerTemp,
		queue:      make(chan bannerLogEntry, queueSize),
	}

	go a.run()

	go func() {
		for range time.NewTicker(time.Minute).C {
			if n := a.dropped.Swap(0); n > 0 {
				log.Printf("AsyncBanLogger: dropped %d ban-log lines (queue full)", n)
			}
		}
	}()

	return a
}

func (a *AsyncBanLogger) run() {
	for e := range a.queue {
		if e.temp {
			a.LoggerTemp.Println(e.line)
		} else {
			a.Logger.Println(e.line)
		}
	}
}

// Enqueue is non-blocking; it drops the line if the queue is full to protect the hot
// path. It returns true if the line was queued, false if it was dropped.
func (a *AsyncBanLogger) Enqueue(line string, temp bool) bool {
	select {
	case a.queue <- bannerLogEntry{line, temp}:
		return true
	default:
		a.dropped.Add(1)
		return false
	}
}
