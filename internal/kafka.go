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

func handleCommand(
	config *Config,
	command commandMessage,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
) {
	switch command.Name {
	case "challenge_ip":
		// exempt a site from challenge according to config
		_, disabled := config.SitesToDisableBaskerville[command.Host]

		// XXX do a real valid IP check?
		if len(command.Value) > 4 && !disabled {
			updateExpiringDecisionLists(
				config,
				command.Value,
				decisionListsMutex,
				decisionLists,
				time.Now(),
				Challenge,
				true, // from baskerville, provide to http_server to distinguish from regex
				command.Host,
			)
			log.Printf("KAFKA: challenge_ip: %s\n", command.Value)
		} else if disabled {
			log.Printf("KAFKA: DIS-BASK: not challenge %s, site %s disabled baskerville\n", command.Value, command.Host)
		} else {
			log.Printf("KAFKA: command value looks malformed: %s\n", command.Value)
		}
		break
	case "challenge_session", "block_session":
		if command.SessionId == "" {
			log.Printf("KAFKA: session_id is EMPTY, break\n")
			break
		}
		// exempt a site from challenge according to config
		_, disabled := config.SitesToDisableBaskerville[command.Host]

		if !disabled {
			// gin does urldecode or cookie, so we decode any possible urlencoded session id from kafka
			sessionIdDecoded, decodeErr := url.QueryUnescape(command.SessionId)
			if decodeErr != nil {
				log.Printf("KAFKA: fail to urldecode session_id %s, break\n", command.SessionId)
				break
			}
			var decision Decision
			if command.Name == "block_session" {
				log.Printf("KAFKA: %s block_session: %s\n", command.Host, sessionIdDecoded)
				decision = NginxBlock
			} else {
				log.Printf("KAFKA: %s challenge_session: %s\n", command.Host, sessionIdDecoded)
				decision = Challenge
			}
			updateExpiringDecisionListsSessionId(
				config,
				command.Value,
				sessionIdDecoded,
				decisionListsMutex,
				decisionLists,
				time.Now(),
				decision,
				true, // from baskerville, provide to http_server to distinguish from regex
				command.Host,
			)
		} else {
			log.Printf("KAFKA: DIS-BASK: no action on %s, site %s disabled baskerville\n", command.Value, command.Host)
		}
		break
	default:
		log.Printf("KAFKA: unrecognized command name: %s\n", command.Name)
	}
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
