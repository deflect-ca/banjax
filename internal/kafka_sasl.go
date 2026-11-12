// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"strings"

	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// KafkaDefaultSASLMechanism applies when credentials are set without kafka_sasl_mechanism.
const KafkaDefaultSASLMechanism = "SCRAM-SHA-512"

// KafkaSASLMechanism builds the SASL mechanism for the kafka dialer. No mechanism
// and no credentials means no SASL (TLS client certs only, or plaintext); credentials
// without a mechanism use KafkaDefaultSASLMechanism. Mechanism "none" turns SASL off
// even with credentials set, so one deployment whose broker has no password yet can
// override the credentials in a shared config file (an empty .env value cannot).
// Exported so supporting-containers/kafka-cmd-tester authenticates the same way.
func KafkaSASLMechanism(mechanism, username, password string) (sasl.Mechanism, error) {
	if strings.EqualFold(mechanism, "none") {
		return nil, nil
	}
	if mechanism == "" {
		if username == "" && password == "" {
			return nil, nil
		}
		mechanism = KafkaDefaultSASLMechanism
	}
	if username == "" || password == "" {
		return nil, fmt.Errorf("kafka_sasl_mechanism %q needs both kafka_sasl_username and kafka_sasl_password", mechanism)
	}

	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		return plain.Mechanism{Username: username, Password: password}, nil
	case "SCRAM-SHA-256":
		m, err := scram.Mechanism(scram.SHA256, username, password)
		if err != nil {
			return nil, fmt.Errorf("kafka sasl SCRAM-SHA-256: %w", err)
		}
		return m, nil
	case "SCRAM-SHA-512":
		m, err := scram.Mechanism(scram.SHA512, username, password)
		if err != nil {
			return nil, fmt.Errorf("kafka sasl SCRAM-SHA-512: %w", err)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported kafka_sasl_mechanism %q (PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512)", mechanism)
	}
}
