//go:build integration

package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	setUp()
	exit_code := m.Run()
	tearDown()
	os.Exit(exit_code)
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
	defer reloadConfig(fixtureConfigTest)

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
	reloadConfig(fixtureConfigTestReload)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// protected resources
		{"GET", prefix + "wp-admin2", 401, randomXClientIP(), nil},
	})
}

func TestGlobalDecisionLists(t *testing.T) {
	defer reloadConfig(fixtureConfigTest)

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
		{"GET", prefix + "/global_challenge_8", 401, ClientIP("8.8.8.8"), nil},
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
	reloadConfig(fixtureConfigTestReload)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// global_decision_lists
		{"GET", prefix + "/global_allow8", 200, ClientIP("8.8.8.8"), nil},
		{"GET", prefix + "/global_challenge_20", 401, ClientIP("20.20.20.20"), nil},
	})
}

func TestPerSiteDecisionLists(t *testing.T) {
	defer reloadConfig(fixtureConfigTest)

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
		{"GET", prefix + "/", 401, ClientIP("91.91.91.91"), nil},
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
	reloadConfig(fixtureConfigTestReload)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// per_site_decision_lists
		{"GET", prefix + "/", 200, ClientIP("91.91.91.91"), nil},
	})
}

func TestSitewideShaInvList(t *testing.T) {
	defer reloadConfig(fixtureConfigTest)

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
	reloadConfig(fixtureConfigTestShaInv)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-02-03"}},
		// sitewide_sha_inv_list on
		{"GET", prefix + "/2", 401, randomXClientIP(), nil},
	})

	/*
		sitewide_sha_inv_list:
			example.com: block
			foobar.com: no_block
	*/
	reloadConfig(fixtureConfigTest)
	httpTester(t, []TestResource{
		{"GET", "/info", 200, nil, []string{"2022-01-02"}},
		// sitewide_sha_inv_list off
		{"GET", prefix + "/3", 200, randomXClientIP(), nil},
	})
}
