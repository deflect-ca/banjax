// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"log"
)

// HotReload is what banjax does on SIGHUP: re-read the config file and rebuild the state
// derived from it. It lives here rather than in main so tests can run the real reload.
//
// The expiring decisions (DynamicDecisionLists) are deliberately left alone. Edges get a
// SIGHUP on every config push, and clearing on reload dropped every Baskerville command,
// regex ban and failed-challenge ban on the dnet hours before its ttl. Each decision ends
// at its own expiry, or earlier through POST /unban or the Kafka clear_rules command. The
// config-driven exemptions (protected_ips, per-site allowlists, and
// sites_to_disable_baskerville for Baskerville decisions) are applied per request, so kept
// decisions follow the reloaded config.
func HotReload(
	configHolder *ConfigHolder,
	staticDecisionLists *StaticDecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	deflectChallengeKeys *DeflectChallengeKeys,
	banner BannerInterface,
) error {
	if err := configHolder.Reload(); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	config := configHolder.Get()

	if err := staticDecisionLists.UpdateFromConfig(config); err != nil {
		log.Println("HOT-RELOAD: static decision lists update failed, keeping the previous ones:", err)
	}
	UnbanProtectedIPs(config, banner)
	// On error the previous paths stay in force, so nothing that was protected
	// becomes reachable because of a bad edit.
	if err := passwordProtectedPaths.UpdateFromConfig(config); err != nil {
		log.Println("HOT-RELOAD: password protected paths update failed, keeping the previous ones:", err)
	}
	// This is what mints a keypair for a domain that has just turned the
	// deflect challenge on. Non-fatal for the same reason as above.
	if err := deflectChallengeKeys.UpdateFromConfig(config); err != nil {
		log.Println("HOT-RELOAD: deflect challenge key update failed:", err)
	}
	return nil
}
