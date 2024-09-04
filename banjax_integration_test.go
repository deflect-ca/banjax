//go:build integration

package main

import (
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	setUp()
	exit_code := m.Run()
	tearDown()
	os.Exit(exit_code)
}

func TestPathWithChallengeCookies(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 1)

	prefix := "/auth_request?path="
	httpTesterWithCookie(t, []TestResource{
		{"GET", prefix + "/wp-admin", 401, nil, []string{"deflect_password3"}},
		{"GET", prefix + "/wp-admin", 401, nil, []string{"deflect_password3", "3600"}}, // testing max-age
		{"GET", prefix + "/global_mask_64_ban", 429, ClientIP("192.168.1.64"), []string{"deflect_challenge3"}},
	})

	// reload without per site max age, test if default value 14400 present
	reloadConfig(fixtureConfigTestReloadCIDR, 1)
	httpTesterWithCookie(t, []TestResource{
		{"GET", prefix + "/wp-admin", 401, nil, []string{"deflect_password3", "14400"}}, // testing max-age
	})
}

func TestGlobalPerSiteDecisionListsMask(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 1)

	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		// we should not treat CIDR as normal IP, will be skipped in map
		{"GET", prefix + "/global_mask_noban", 200, ClientIP("192.168.1.0/24"), nil},
		// test if CIDR 192.168.1.0/24 is working
		{"GET", prefix + "/global_mask_64_ban", 429, ClientIP("192.168.1.64"), nil},
		{"GET", prefix + "/global_mask_bypass", 200, ClientIP("192.168.87.87"), nil},
	})
	httpTester(t, []TestResource{
		{"GET", prefix + "/per_site_mask_noban", 200, ClientIP("192.168.0.0/24"), nil},
		{"GET", prefix + "/per_site_mask_128_ban", 429, ClientIP("192.168.0.128"), nil},
	})

	reloadConfig(fixtureConfigTestReloadCIDR, 1)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-03-02"}},
		{"GET", prefix + "/global_mask_64_nginx_block", 403, ClientIP("192.168.2.64"), nil},
		{"GET", prefix + "/global_mask_64_no_cha", 200, ClientIP("192.168.1.64"), nil},
		{"GET", prefix + "/per_site_mask_noban_128", 200, ClientIP("192.168.0.128"), nil},
		{"GET", prefix + "/per_site_mask_noban_128", 403, ClientIP("192.168.3.128"), nil},
	})
}

func TestTooManyFailedChallenge(t *testing.T) {
	/*
		too_many_failed_challenges_interval_seconds: 10
		too_many_failed_challenges_threshold: 6
	*/
	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		{"GET", prefix + "/too_many", 429, ClientIP("60.60.60.60"), nil},
		{"GET", prefix + "/too_many", 429, ClientIP("60.60.60.60"), nil},
		{"GET", prefix + "/too_many", 429, ClientIP("60.60.60.60"), nil},
		{"GET", prefix + "/too_many", 429, ClientIP("60.60.60.60"), nil},
		{"GET", prefix + "/too_many", 429, ClientIP("60.60.60.60"), nil},
		{"GET", prefix + "/too_many", 429, ClientIP("60.60.60.60"), nil},
		{"GET", prefix + "/too_many", 403, ClientIP("60.60.60.60"), nil},
	})
}

func TestBanjaxEndpoint(t *testing.T) {
	banjax_resources := []TestResource{
		{"GET", "/auth_request", 200, randomXClientIP(), nil},
		{"POST", "/auth_request", 200, randomXClientIP(), nil},
		{"PUT", "/auth_request", 200, randomXClientIP(), nil},
		{"PATCH", "/auth_request", 200, randomXClientIP(), nil},
		{"HEAD", "/auth_request", 200, randomXClientIP(), nil},
		{"OPTIONS", "/auth_request", 200, randomXClientIP(), nil},
		{"DELETE", "/auth_request", 200, randomXClientIP(), nil},
		{"CONNECT", "/auth_request", 200, randomXClientIP(), nil},
		{"TRACE", "/auth_request", 200, randomXClientIP(), nil},
		{"GET", "/info", 200, randomXClientIP(), nil},
		{"GET", "/decision_lists", 200, randomXClientIP(), nil},
		{"GET", "/rate_limit_states", 200, randomXClientIP(), nil},
	}
	httpTester(t, banjax_resources)
}

func TestProtectedResources(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 50)

	/*
		password_protected_paths:
			"localhost:8081":
				- wp-admin_a
				- wp-admin_b
				- wp-admin_c
				- wp-admin_d
				- wp-admin_e
				- wp-admin_f
				- wp-admin_g
				- wp-admin
	*/
	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-01-02"}},
		// this variation shouldn't be protected
		{"GET", prefix + "wp-adm/in", 200, randomXClientIP(), nil},
		// protected resources
		{"GET", prefix + "wp-admin", 401, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin", 401, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin//", 401, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin.php", 401, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin.php#test", 401, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin.php?a=1&b=2", 401, randomXClientIP(), nil},
		// exceptions
		{"GET", prefix + "wp-admin/admin-ajax.php", 200, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php", 200, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php?a=1", 200, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php?a=1&b=2", 200, randomXClientIP(), nil},
		{"GET", prefix + "/wp-admin/admin-ajax.php#test", 200, randomXClientIP(), nil},
		{"GET", prefix + "wp-admin/admin-ajax.php/", 200, randomXClientIP(), nil},
	})

	/*
		password_protected_paths:
			"localhost:8081":
				- wp-admin
				- wp-admin2
				- app/admin
			"localhost":
				- wp-admin
	*/
	reloadConfig(fixtureConfigTestReload, 50)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// protected resources
		{"GET", prefix + "wp-admin2", 401, randomXClientIP(), nil},
	})
}

func TestGlobalDecisionLists(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 50)

	/*
		global_decision_lists:
			allow:
				- 20.20.20.20
			iptables_block:
				- 30.40.50.60
			nginx_block:
				- 70.80.90.100
			challenge:
				- 8.8.8.8
	*/
	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		// global_decision_lists
		{"GET", prefix + "/global_allow20", 200, ClientIP("20.20.20.20"), nil},
		{"GET", prefix + "/global_challenge_8", 429, ClientIP("8.8.8.8"), nil},
	})

	/*
		global_decision_lists:
			allow: []  # test remove
			iptables_block:
				- 30.40.50.60
			nginx_block:
				- 70.80.90.100
			challenge:
				- 20.20.20.20  # test value change
	*/
	reloadConfig(fixtureConfigTestReload, 50)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// global_decision_lists
		{"GET", prefix + "/global_allow8", 200, ClientIP("8.8.8.8"), nil},
		{"GET", prefix + "/global_challenge_20", 429, ClientIP("20.20.20.20"), nil},
	})
}

func TestPerSiteDecisionLists(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 50)

	/*
		per_site_decision_lists:
			"localhost:8081":
				allow:
				- 90.90.90.90
				challenge:
				- 91.91.91.91
				block:
				- 92.92.92.92
	*/
	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		// per_site_decision_lists
		{"GET", prefix + "/", 200, ClientIP("90.90.90.90"), nil},
		{"GET", prefix + "/", 429, ClientIP("91.91.91.91"), nil},
	})

	/*
		per_site_decision_lists:
			"localhost:8081":
				allow:
				- 91.91.91.91  # test change
				challenge: []  # test remove
				block:
				- 92.92.92.92
	*/
	reloadConfig(fixtureConfigTestReload, 50)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// per_site_decision_lists
		{"GET", prefix + "/", 200, ClientIP("91.91.91.91"), nil},
	})

	// test if return 403 after too many failed password page, after it should see 401 immediately
	reloadConfig(fixtureConfigTestPersiteFail, 1)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2023-08-23"}},
		{"GET", prefix + "/wp-admin", 401, ClientIP("92.92.92.92"), nil},
		{"GET", prefix + "/wp-admin", 401, ClientIP("92.92.92.92"), nil},
		{"GET", prefix + "/wp-admin", 401, ClientIP("92.92.92.92"), nil},
		{"GET", prefix + "/wp-admin", 403, ClientIP("92.92.92.92"), nil},
		{"GET", prefix + "/wp-admin", 401, ClientIP("92.92.92.92"), nil},
	})

	// test CIDR format (192.168.1.0/24)
	httpTester(t, []TestResource{
		{"GET", prefix + "/wp-admin", 401, ClientIP("192.168.1.87"), nil},
		{"GET", prefix + "/wp-admin", 401, ClientIP("192.168.1.87"), nil},
		{"GET", prefix + "/wp-admin", 401, ClientIP("192.168.1.87"), nil},
		{"GET", prefix + "/wp-admin", 403, ClientIP("192.168.1.87"), nil},
		{"GET", prefix + "/wp-admin", 401, ClientIP("192.168.1.87"), nil},
	})
}

func TestSitewideShaInvList(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 50)

	/*
		sitewide_sha_inv_list:
			example.com: block
			foobar.com: no_block
	*/
	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		// sitewide_sha_inv_list off
		{"GET", prefix + "/1", 200, randomXClientIP(), nil},
	})

	/*
		sitewide_sha_inv_list:
			example.com: block
			foobar.com: no_block
			"localhost:8081": block
	*/
	reloadConfig(fixtureConfigTestShaInv, 50)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// sitewide_sha_inv_list on
		{"GET", prefix + "/2", 429, randomXClientIP(), nil},
	})

	/*
		sitewide_sha_inv_list:
			example.com: block
			foobar.com: no_block
	*/
	reloadConfig(fixtureConfigTest, 50)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-01-02"}},
		// sitewide_sha_inv_list off
		{"GET", prefix + "/3", 200, randomXClientIP(), nil},
	})
}

func TestRegexesWithRatesChallengeme(t *testing.T) {
	defer reloadConfig(fixtureConfigTestRegexBanner, 1) // prepare for next test

	/*
		- decision: challenge
			hits_per_interval: 0
			interval: 1
			regex: .*challengeme.*
			rule: "instant challenge"
	*/
	prefix := "/auth_request?path="
	httpTester(t, []TestResource{
		// first test should pass
		{"GET", prefix + "/1?challengeme", 200, ClientIP("9.9.9.9"), nil},
	})

	time.Sleep(2 * time.Second)
	httpTester(t, []TestResource{
		// later should fail
		{"GET", prefix + "/2?challengeme", 429, ClientIP("9.9.9.9"), nil},
	})

	/*
		removed
	*/
	reloadConfig(fixtureConfigTestReload, 1)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// regexes_with_rates (rule removed)
		{"GET", prefix + "/3?challengeme", 200, ClientIP("9.9.9.9"), nil},
		{"GET", prefix + "/4?challengeme", 200, ClientIP("9.9.9.9"), nil},
	})
}

func TestRegexesWithRates(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 1)

	/* (fixtureConfigTestRegexBanner)
	# test target 1
	- decision: challenge
		hits_per_interval: 0
		interval: 1
		regex: .*
		rule: "Challenge all but skip localhost:8081"
		hosts_to_skip:
			"localhost:8081": true
	# test target 2
	- decision: nginx_block
		hits_per_interval: 45
		interval: 60
		regex: "GET .* /"
		rule: "All sites/GET: 45 req/60 sec"
	*/
	prefix := "/auth_request?path="

	// test target 1
	httpTester(t, []TestResource{
		// first test should pass
		{"GET", prefix + "/1", 200, ClientIP("10.10.10.10"), nil},
	})

	time.Sleep(2 * time.Second)
	httpTester(t, []TestResource{
		// later should also pass since host is skipped
		{"GET", prefix + "/2", 200, ClientIP("10.10.10.10"), nil},
	})

	// test target 2, make 45 req
	httpStress(
		[]TestResource{{"GET", prefix + "/45in60", 200, ClientIP("11.11.11.11"), nil}},
		45)

	time.Sleep(2 * time.Second)
	httpTester(t, []TestResource{
		// should be banned (nginx_block = 403)
		{"GET", prefix + "/45in60", 403, ClientIP("11.11.11.11"), nil},
	})

	// test target 3, make 45 req
	httpStress(
		[]TestResource{{"GET", prefix + "/45in60-whitelist", 200, ClientIP("12.12.12.12"), nil}},
		45)

	time.Sleep(2 * time.Second)
	httpTester(t, []TestResource{
		// should not be banned due to global whitelist
		{"GET", prefix + "/45in60-whitelist", 200, ClientIP("12.12.12.12"), nil},
	})
}

func TestRegexesWithRatesAllowList(t *testing.T) {
	defer reloadConfig(fixtureConfigTest, 1)

	prefix := "/auth_request?path="

	// test per-site allow list for regex banner
	httpTester(t, []TestResource{
		// should be exempted from regex banner
		{"GET", prefix + "/block_local", 200, ClientIP("171.171.171.171"), nil},
		{"GET", prefix + "/block_local", 200, ClientIP("171.171.171.171"), nil},
		{"GET", prefix + "/block_local", 200, ClientIP("171.171.171.171"), nil},
	})

	// test global allow list for regex banner
	httpTester(t, []TestResource{
		// should be exempted from regex banner
		{"GET", prefix + "/blockme/", 200, ClientIP("20.20.20.20"), nil},
		{"GET", prefix + "/blockme/", 200, ClientIP("20.20.20.20"), nil},
		{"GET", prefix + "/blockme/", 200, ClientIP("20.20.20.20"), nil},
	})
}
