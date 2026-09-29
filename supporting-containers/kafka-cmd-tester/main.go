// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

// kafka-cmd-tester sends a single simulated banjax kafka command message,
// matching the commandMessage struct that internal/kafka.go unmarshals.
// It is a debugging tool, not part of the banjax binary.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

// mirrors commandMessage in internal/kafka.go, so the JSON on the wire is
// exactly what banjax's kafka reader expects.
type commandMessage struct {
	Name      string `json:"Name"`
	Value     string `json:"Value,omitempty"`
	Host      string `json:"host,omitempty"`
	SessionId string `json:"session_id,omitempty"`
	Source    string `json:"source,omitempty"`
	PrintLog  bool   `json:"print_log"`
	TTL       int    `json:"ttl,omitempty"`
	UA        string `json:"ua,omitempty"`
}

// commandSpec describes what a command name needs and how it is validated,
// so adding a new banjax command name only means adding an entry here.
type commandSpec struct {
	requireValue     bool
	requireSessionId bool
	requireHost      bool
	requireUA        bool
}

var commandSpecs = map[string]commandSpec{
	"block_ip":          {requireValue: true},
	"challenge_ip":      {requireValue: true},
	"block_session":     {requireValue: true, requireSessionId: true},
	"challenge_session": {requireValue: true, requireSessionId: true},
	"challenge_all":     {requireHost: true},
	"block_ua":          {requireUA: true},
	"challenge_ua":      {requireUA: true},
	// clear_rules takes any combination of host/value/session-id/ua (each one
	// clears independently), so it can't be expressed with requireX above;
	// see the at-least-one check below instead.
	"clear_rules": {},
}

func supportedCommandNames() []string {
	names := make([]string, 0, len(commandSpecs))
	for name := range commandSpecs {
		names = append(names, name)
	}
	return names
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func main() {
	cmdName := flag.String("cmd", "", "command name, one of: "+strings.Join(supportedCommandNames(), ", "))
	host := flag.String("host", "", "host (site), required for challenge_all, optional for clear_rules")
	value := flag.String("value", "", "IP address, required for *_ip and *_session commands, optional for clear_rules")
	sessionId := flag.String("session-id", "", "session id, required for *_session commands, optional for clear_rules")
	ua := flag.String("ua", "", "exact User-Agent string, required for block_ua/challenge_ua, optional for clear_rules")
	ttl := flag.Int("ttl", 0, "TTL override in seconds (0 omits the field, banjax uses its own default)")
	source := flag.String("source", "kafka-cmd-tester", "value for the command's source field")
	printLog := flag.Bool("print-log", true, "set print_log on the command, so banjax logs it even without debug mode")

	brokers := flag.String("brokers", envOr("KAFKA_BROKERS", "kafkadev0.prod.deflect.network:9094,kafkadev1.prod.deflect.network:9094,kafkadev2.prod.deflect.network:9094"), "comma-separated kafka broker list")
	topic := flag.String("topic", envOr("KAFKA_TOPIC", "banjax_command_topic_dev"), "kafka topic")
	partition := flag.Int("partition", 0, "kafka partition to write to (banjax's reader listens on one partition per dnet)")

	sslCa := flag.String("ssl-ca", envOr("KAFKA_SSL_CA", "/etc/banjax/caroot.pem"), "path to CA cert")
	sslCert := flag.String("ssl-cert", envOr("KAFKA_SSL_CERT", "/etc/banjax/certificate.pem"), "path to client cert")
	sslKey := flag.String("ssl-key", envOr("KAFKA_SSL_KEY", "/etc/banjax/key.pem"), "path to client key")
	insecure := flag.Bool("insecure", false, "connect without TLS (for a local, unauthenticated kafka)")

	count := flag.Int("count", 1, "number of times to send the message")
	interval := flag.Duration("interval", 0, "delay between sends when -count > 1, e.g. 2s")
	dryRun := flag.Bool("dry-run", false, "print the message instead of sending it")

	flag.Parse()

	if *cmdName == "" {
		fmt.Fprintln(os.Stderr, "error: -cmd is required")
		flag.Usage()
		os.Exit(2)
	}

	spec, ok := commandSpecs[*cmdName]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unrecognized -cmd %q, must be one of: %s\n", *cmdName, strings.Join(supportedCommandNames(), ", "))
		os.Exit(2)
	}
	if spec.requireValue && *value == "" {
		fmt.Fprintf(os.Stderr, "error: -value is required for %s\n", *cmdName)
		os.Exit(2)
	}
	if spec.requireSessionId && *sessionId == "" {
		fmt.Fprintf(os.Stderr, "error: -session-id is required for %s\n", *cmdName)
		os.Exit(2)
	}
	if spec.requireHost && *host == "" {
		fmt.Fprintf(os.Stderr, "error: -host is required for %s\n", *cmdName)
		os.Exit(2)
	}
	if spec.requireUA && *ua == "" {
		fmt.Fprintf(os.Stderr, "error: -ua is required for %s\n", *cmdName)
		os.Exit(2)
	}
	if *cmdName == "clear_rules" && *host == "" && *value == "" && *sessionId == "" && *ua == "" {
		fmt.Fprintln(os.Stderr, "error: clear_rules requires at least one of -host, -value, -session-id, or -ua")
		os.Exit(2)
	}

	message := commandMessage{
		Name:      *cmdName,
		Value:     *value,
		Host:      *host,
		SessionId: *sessionId,
		Source:    *source,
		PrintLog:  *printLog,
		TTL:       *ttl,
		UA:        *ua,
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Fatalf("failed to marshal command: %s", err)
	}

	if *dryRun {
		fmt.Printf("topic=%s partition=%d\n%s\n", *topic, *partition, string(messageBytes))
		return
	}

	var tlsConfig *tls.Config
	if !*insecure {
		tlsConfig = buildTLSConfig(*sslCa, *sslCert, *sslKey)
	}

	brokerList := strings.Split(*brokers, ",")
	writer := &kafka.Writer{
		Addr:      kafka.TCP(brokerList...),
		Topic:     *topic,
		Balancer:  &fixedPartitionBalancer{partition: *partition},
		Transport: &kafka.Transport{TLS: tlsConfig},
	}
	defer writer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < *count; i++ {
		if i > 0 && *interval > 0 {
			time.Sleep(*interval)
		}

		err := writer.WriteMessages(ctx, kafka.Message{Value: messageBytes})
		if err != nil {
			log.Fatalf("failed to send message %d/%d: %s", i+1, *count, err)
		}
		log.Printf("sent %d/%d: %s\n", i+1, *count, string(messageBytes))
	}
}

// fixedPartitionBalancer always routes to the configured partition, so the
// message lands wherever banjax's reader (kafka.go's getDNetPartition) is
// actually listening, instead of wherever kafka-go's default balancer picks.
type fixedPartitionBalancer struct {
	partition int
}

func (b *fixedPartitionBalancer) Balance(msg kafka.Message, partitions ...int) int {
	return b.partition
}

func buildTLSConfig(caPath, certPath, keyPath string) *tls.Config {
	keypair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("failed to load cert + key pair: %s", err)
	}

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("failed to read CA root: %s", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to parse CA root %s", caPath)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{keypair},
		RootCAs:      caCertPool,
		// matches internal/kafka.go's getDialer: the broker certs don't line
		// up with the hostnames we dial, so hostname verification is skipped.
		InsecureSkipVerify: true,
	}
}
