// Copyright (c) 2023, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"testing"
	"time"
)

func TestSessionCookie(t *testing.T) {
	fmt.Println("Testing session cookie performance...")
	total := 1000
	start := time.Now()
	cookie := ""
	ip := "123.123.123.123"
	for i := 0; i < total; i++ {
		cookie = newSessionCookie("a secret key", 3, ip)
	}
	elapsed := time.Since(start)
	fmt.Println(cookie)
	fmt.Printf("It took %s for %d cookies\n\n", elapsed, total)

	fmt.Println("Testing session cookie validation...")
	now := time.Now()
	err := validateSessionCookie(cookie, "a secret key", now, ip)
	if err != nil {
		t.Error("Failed. A valid cookie validation failed.")
		t.Error(err)
	} else {
		fmt.Println("Passed.")
	}

	fmt.Println("Testing session cookie wrong IP validation...")
	err = validateSessionCookie(cookie, "a secret key", now, "a wrong ip: 1.1.1.1")
	if err != nil {
		fmt.Println("Passed")
	} else {
		t.Error("Failed. A cookie with wrong IP successfully validated")
	}

	fmt.Println("Testing session cookie Hmac validation...")
	err = validateSessionCookie("123456Zf3n791yKsb5vcjh7dOzVzX0e9AAAAAGUCG+k=", "a secret key", now, ip)
	if err != nil {
		fmt.Println("Passed")
	} else {
		t.Error("Failed. A random cookie successfully validated")
	}

	fmt.Println("Testing cookie expiration... Sleeping...")
	time.Sleep(3 * time.Second)
	err = validateSessionCookie(cookie, "a secret key", time.Now(), ip)
	if err != nil {
		fmt.Println("Passed")
	} else {
		t.Error("Failed. An expired cookie successfully validated")
	}
}
