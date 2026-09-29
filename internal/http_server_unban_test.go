// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func newUnbanTestRouter(decisionLists *DynamicDecisionLists) *gin.Engine {
	gin.SetMode(gin.TestMode)

	configHolder := &ConfigHolder{}
	configHolder.config.Store(&Config{})

	r := gin.New()
	r.POST("/unban", unbanHandler(configHolder, decisionLists, &MockBanner{}))
	return r
}

func postUnban(t *testing.T, r *gin.Engine, form url.Values) (int, map[string]interface{}) {
	req := httptest.NewRequest("POST", "/unban", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	assert.Nil(t, err)
	return w.Code, body
}

func TestUnban_ByHost_ClearsSitewideChallenge(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	r := newUnbanTestRouter(decisionLists)

	code, body := postUnban(t, r, url.Values{"host": {" example.com "}})

	assert.Equal(t, 200, code)
	assert.Equal(t, "example.com", body["host"])
	assert.Equal(t, true, body["found_in_decision_list"])
	assert.Equal(t, "Challenge", body["decision"])
	assert.Equal(t, true, body["unban"])

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestUnban_ByHost_NotFound(t *testing.T) {
	r := newUnbanTestRouter(NewDynamicDecisionLists())

	code, body := postUnban(t, r, url.Values{"host": {"unknown.com"}})

	assert.Equal(t, 200, code)
	assert.Equal(t, "unknown.com", body["host"])
	assert.Equal(t, false, body["found_in_decision_list"])
	assert.Equal(t, false, body["unban"])
}

func TestUnban_ByUA_ClearsUADecision(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)
	r := newUnbanTestRouter(decisionLists)

	code, body := postUnban(t, r, url.Values{"ua": {" curl/7.68.0 "}})

	assert.Equal(t, 200, code)
	assert.Equal(t, "curl/7.68.0", body["ua"])
	assert.Equal(t, true, body["found_in_decision_list"])
	assert.Equal(t, "NginxBlock", body["decision"])
	assert.Equal(t, true, body["unban"])

	_, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.False(t, ok)
}

func TestUnban_ByUA_NotFound(t *testing.T) {
	r := newUnbanTestRouter(NewDynamicDecisionLists())

	code, body := postUnban(t, r, url.Values{"ua": {"unknown-agent"}})

	assert.Equal(t, 200, code)
	assert.Equal(t, "unknown-agent", body["ua"])
	assert.Equal(t, false, body["found_in_decision_list"])
	assert.Equal(t, false, body["unban"])
}

func TestUnban_HostTakesPrecedenceOverUAAndIp(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), NginxBlock, true, "example.com")
	r := newUnbanTestRouter(decisionLists)

	code, body := postUnban(t, r, url.Values{
		"host": {"example.com"},
		"ua":   {"curl/7.68.0"},
		"ip":   {"1.2.3.4"},
	})

	assert.Equal(t, 200, code)
	assert.Equal(t, "example.com", body["host"])
	assert.NotContains(t, body, "ua")
	assert.NotContains(t, body, "ip")

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, uaOk := decisionLists.CheckByUA("curl/7.68.0")
	_, ipOk := decisionLists.Check("", "1.2.3.4")
	assert.False(t, hostOk)
	assert.True(t, uaOk)
	assert.True(t, ipOk)
}

func TestUnban_UATakesPrecedenceOverIp(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), NginxBlock, true, "example.com")
	r := newUnbanTestRouter(decisionLists)

	code, body := postUnban(t, r, url.Values{
		"ua": {"curl/7.68.0"},
		"ip": {"1.2.3.4"},
	})

	assert.Equal(t, 200, code)
	assert.Equal(t, "curl/7.68.0", body["ua"])
	assert.NotContains(t, body, "ip")

	_, uaOk := decisionLists.CheckByUA("curl/7.68.0")
	_, ipOk := decisionLists.Check("", "1.2.3.4")
	assert.False(t, uaOk)
	assert.True(t, ipOk)
}

func TestUnban_ByIp_StillWorks(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), NginxBlock, true, "example.com")
	r := newUnbanTestRouter(decisionLists)

	code, body := postUnban(t, r, url.Values{"ip": {"1.2.3.4"}})

	assert.Equal(t, 200, code)
	assert.Equal(t, "1.2.3.4", body["ip"])
	assert.Equal(t, true, body["found_in_decision_list"])
	assert.Equal(t, "NginxBlock", body["decision"])
	assert.Equal(t, true, body["unban"])

	_, ok := decisionLists.Check("", "1.2.3.4")
	assert.False(t, ok)
}

func TestUnban_MissingIpHostAndUA(t *testing.T) {
	r := newUnbanTestRouter(NewDynamicDecisionLists())

	code, body := postUnban(t, r, url.Values{"host": {"   "}, "ua": {""}})

	assert.Equal(t, 400, code)
	assert.Equal(t, "ip, host, or ua in post form is required", body["error"])
}
