// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"testing"
)

func TestCookieModification(t *testing.T) {
	passwordPageBytes := []byte("document.cookie = \"deflect_password3=\" + base64_cookie + \";SameSite=Lax;path=/;\";")

	fmt.Println("-- 1 --")
	modifiedBytes := applyCookieMaxAge(passwordPageBytes, "deflect_password3", 100)

	if string(modifiedBytes) != "document.cookie = \"deflect_password3=\" + base64_cookie + \";max-age=100\" + \";SameSite=Lax;path=/;\";" {
		fmt.Println(string(modifiedBytes))
		t.Errorf("Unexpected result from applyCookieMaxAge")
	}

	fmt.Println("-- 2 --")
	modifiedBytes = applyCookieDomain(passwordPageBytes, "deflect_password3")

	if string(modifiedBytes) != "document.cookie = \"deflect_password3=\" + base64_cookie + \";domain=\" + window.location.hostname + \";SameSite=Lax;path=/;\";" {
		fmt.Println(string(modifiedBytes))
		t.Errorf("Unexpected result from applyCookieMaxAge")
	}
}
