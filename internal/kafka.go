// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

/*
sample baskerville message:

	{
		"Value": "0.0.0.0",
		"Name": "challenge_ip",
		"duration": 15.0,
		"session_id": "ID",
		"source": "behave",
		"start": "2023-09-27 08:04:43",
		"host": "example.com",
		"end": "2023-09-27 08:04:58",
		"urls": "[[\"2023-09-27 08:04:43\", \"/some/url\"], [\"2023-09-27 08:04:58\", \"/another/url\"]]"
	}
*/
type commandMessage struct {
	Name      string
	Value     string
	Host      string `json:"host"`
	SessionId string `json:"session_id"`
	Source    string `json:"source"`
}

func getDialer(config *Config) *kafka.Dialer {
	tlsConfig := tls.Config{}

	if config.KafkaSslCert != "" {
		keypair, err := tls.LoadX509KeyPair(config.KafkaSslCert, config.KafkaSslKey)
		if err != nil {
			log.Fatalf("KAFKA: failed to load cert + key pair: %s", err)
		}

		caCert, err := os.ReadFile(config.KafkaSslCa)
		if err != nil {
			log.Fatalf("KAFKA: failed to read CA root: %s", err)
		}

		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			log.Fatalf("KAFKA: failed to parse CA root: %s", err)
		}

		tlsConfig = tls.Config{
			Certificates:       []tls.Certificate{keypair},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true, // XXX is this ok?
		}
	}

	dialer := &kafka.Dialer{
		Timeout:   10 * time.Second,
		DualStack: true,
		TLS:       &tlsConfig,
	}
	return dialer
}

func RunKafkaReader(
	config *Config,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	// XXX this infinite loop is so we reconnect if we get dropped.
	for {
		r := kafka.NewReader(kafka.ReaderConfig{
			Brokers:        config.KafkaBrokers,
			GroupID:        uuid.New().String(),
			StartOffset:    kafka.LastOffset,
			Topic:          config.KafkaCommandTopic,
			Dialer:         getDialer(config),
			CommitInterval: time.Second * 10,
		})
		defer r.Close()

		log.Printf("KAFKA: NewReader started")

		for {
			// XXX read about go contexts
			// ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
			// defer cancel()
			ctx := context.Background()
			m, err := r.ReadMessage(ctx)
			if err != nil {
				log.Println("KAFKA: r.ReadMessage() failed")
				log.Println(err.Error())
				continue // XXX what to do here?
			}

			// log.Printf("KAFKA: message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))

			command := commandMessage{}
			err = json.Unmarshal(m.Value, &command)
			if err != nil {
				log.Printf("KAFKA: Unmarshal failed %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))
				continue
			}

			log.Printf("KAFKA: message %s (%d/%d) = N: %s, V: %s, S: %s: Src: %s\n",
				string(m.Key), m.Offset, m.Partition, command.Name, command.Value, command.SessionId, command.Source)

			handleCommand(
				config,
				command,
				decisionListsMutex,
				decisionLists,
			)
		}

		time.Sleep(5 * time.Second)
	}
}

func getBlockIpTtl(config *Config, host string) (blockIpTtl int) {
	blockIpTtl = config.BlockSessionTtlSeconds
	if ttl, ok := config.SitesToBlockIPTtlSeconds[host]; ok {
		log.Printf("KAFKA: found site-specific block_ip ttl %s %d\n", host, ttl)
		blockIpTtl = ttl
	}
	return
}

func getBlockSessionTtl(config *Config, host string) (blockSessionTtl int) {
	blockSessionTtl = config.BlockIPTtlSeconds
	if ttl, ok := config.SitesToBlockSessionTtlSeconds[host]; ok {
		log.Printf("KAFKA: found site-specific block_session ttl %s %d\n", host, ttl)
		blockSessionTtl = ttl
	}
	return
}

func handleCommand(
	config *Config,
	command commandMessage,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
) {
	// exempt a site from baskerville according to config
	if _, disabled := config.SitesToDisableBaskerville[command.Host]; disabled {
		log.Printf("KAFKA: %s disabled baskerville, skipping %s\n", command.Host, command.Name)
		return
	}

	// handle commands
	switch command.Name {
	case "challenge_ip":
		handleIPCommand(config, command, decisionListsMutex, decisionLists, Challenge, config.ExpiringDecisionTtlSeconds)
		break
	case "block_ip":
		ttl := getBlockIpTtl(config, command.Host)
		handleIPCommand(config, command, decisionListsMutex, decisionLists, NginxBlock, ttl)
		break
	case "challenge_session":
		handleSessionCommand(config, command, decisionListsMutex, decisionLists, Challenge, config.ExpiringDecisionTtlSeconds)
		break
	case "block_session":
		ttl := getBlockSessionTtl(config, command.Host)
		handleSessionCommand(config, command, decisionListsMutex, decisionLists, NginxBlock, ttl)
		break
	default:
		log.Printf("KAFKA: unrecognized command name: %s\n", command.Name)
	}
}

func handleIPCommand(
	config *Config,
	command commandMessage,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	decision Decision,
	expireDuration int,
) {
	if len(command.Value) <= 4 {
		log.Printf("KAFKA: command value looks malformed: %s\n", command.Value)
		return
	}

	log.Printf("KAFKA: handleIPCommand %s %s %s %d\n",
		command.Host, command.Value, decision, expireDuration)

	updateExpiringDecisionLists(
		config,
		command.Value,
		decisionListsMutex,
		decisionLists,
		time.Now().Add(time.Duration(expireDuration)*time.Second),
		decision,
		true, // from baskerville, provide to http_server to distinguish from regex
		command.Host,
	)
}

func handleSessionCommand(
	config *Config,
	command commandMessage,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	decision Decision,
	expireDuration int,
) {
	// gin does urldecode on cookie, so we decode any possible urlencoded session id from kafka
	sessionIdDecoded, decodeErr := url.QueryUnescape(command.SessionId)
	if decodeErr != nil {
		log.Printf("KAFKA: fail to urldecode session_id %s, skip command\n", command.SessionId)
		return
	}

	log.Printf("KAFKA: handleSessionCommand %s %s %s %s %d\n",
		command.Host, command.Value, sessionIdDecoded, decision, expireDuration)

	updateExpiringDecisionListsSessionId(
		config,
		command.Value,
		sessionIdDecoded,
		decisionListsMutex,
		decisionLists,
		time.Now().Add(time.Duration(expireDuration)*time.Second),
		decision,
		true, // from baskerville, provide to http_server to distinguish from regex
		command.Host,
	)
}

type StatusMessage struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Timestamp int    `json:"timestamp"`
}

func ReportStatusMessage(
	config *Config,
) {
	message := StatusMessage{
		Id:        config.Hostname,
		Name:      "status",
		Timestamp: int(time.Now().Unix()), // XXX
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("KAFKA: error marshalling status message\n")
		return
	}
	sendBytesToMessageChan(bytes)
}

type PassedFailedBannedMessage struct {
	Id        string `json:"id"`
	Name      string `json:"name"` // XXX make this an enum
	ValueIp   string `json:"value_ip"`
	ValueSite string `json:"value_site"`
	Timestamp int    `json:"timestamp"`
}

// XXX gross. name is ip_passed_challenge, ip_failed_challenge, or ip_banned
func ReportPassedFailedBannedMessage(config *Config, name string, ip string, site string) {
	message := PassedFailedBannedMessage{
		Id:        config.Hostname,
		Name:      name,
		ValueIp:   ip,
		ValueSite: site,
		Timestamp: int(time.Now().Unix()), // XXX
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("KAFKA: error marshalling %s message\n", name)
		return
	}
	sendBytesToMessageChan(bytes)
}

func sendBytesToMessageChan(bytes []byte) {
	// XXX seems weird
	once.Do(func() {
		messageChan = make(chan []byte)
	})
	// non-blocking send in case the RunKafkaWriter loop isn't receiving
	select {
	case messageChan <- bytes:
		// log.Println("put message on channel")
	default:
		log.Println("KAFKA: did not put message on channel")
	}
}

// XXX weird?
var once sync.Once
var messageChan chan []byte

// current commands: status, ip_{passed,failed}_challenge, ip_banned, ip_in_database
func RunKafkaWriter(
	config *Config,
	wg *sync.WaitGroup,
) {
	// XXX this infinite loop is so we reconnect if we get dropped.
	for {
		w := kafka.NewWriter(kafka.WriterConfig{
			Brokers: config.KafkaBrokers,
			Topic:   config.KafkaReportTopic,
			Dialer:  getDialer(config),
		})
		defer w.Close()

		log.Printf("KAFKA: NewWriter started")

		// XXX weird?
		once.Do(func() {
			messageChan = make(chan []byte)
		})

		for {
			msgBytes := <-messageChan
			// log.Println("got message from messageChan")

			err := w.WriteMessages(context.Background(),
				kafka.Message{
					Key:   []byte("some-key"),
					Value: msgBytes,
				},
			)
			if err != nil {
				log.Println("KAFKA: WriteMessages() failed")
				log.Println(err)
				break
			}

			// log.Println("WriteMessages() succeeded")

			// time.Sleep(2 * time.Second) // XXX just for testing at the moment
		}

		time.Sleep(5 * time.Second) // try to reconnect if we get dropped
	}
}
