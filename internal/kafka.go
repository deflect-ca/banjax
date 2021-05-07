// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"log"
	"sync"
	"time"
)

type commandMessage struct {
	Name  string
	Value string
}

func RunKafkaReader(config *Config, decisionLists *DecisionLists, wg *sync.WaitGroup) {
	defer wg.Done()

	// XXX this infinite loop is so we reconnect if we get dropped.
	for {
		r := kafka.NewReader(kafka.ReaderConfig{
			Brokers: config.KafkaBrokers,
			GroupID: uuid.New().String(),
			Topic:   "banjax_next_command_topic",
		})
		r.SetOffset(kafka.LastOffset)
		defer r.Close()

		log.Printf("NewReader started")

		for {
			// XXX read about go contexts
			// ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
			// defer cancel()
			ctx := context.Background()
			m, err := r.ReadMessage(ctx)
			if err != nil {
				log.Println("r.ReadMessage() failed")
				log.Println(err.Error())
				continue // XXX what to do here?
			}

			log.Printf("message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))

			command := commandMessage{}
			err = json.Unmarshal(m.Value, &command)
			if err != nil {
				log.Println("json.Unmarshal() failed")
				continue
			}

			handleCommand(config, command, decisionLists)
		}

		time.Sleep(5 * time.Second)
	}
}

// XXX maybe make a nicer command unmarshalling thing instead of these if/else checks
func handleCommand(config *Config, command commandMessage, decisionLists *DecisionLists) {
	switch command.Name {
	case "challenge_ip":
		// XXX do a real valid IP check?
		if len(command.Value) > 4 {
			updateExpiringDecisionLists(config, command.Value, decisionLists, time.Now(), Challenge)
			log.Printf("kafka added added to global challenge lists: Challenge %s\n", command.Value)
		} else {
			log.Printf("kafka command value looks malformed: %s\n", command.Value)
		}
	case "challenge_host":
		// XXX check it's a valid host?
		if len(command.Value) > 3 {
			// (*decisionLists).PerSiteDecisionLists[command.Value] = Challenge
			log.Printf("!!! received challenge_host command, but need to implement it\n")
		} else {
			log.Printf("kafka command value looks malformed: %s\n", command.Value)
		}
	default:
		log.Println("unrecognized command name")
	}
}

type StatusMessage struct {
	Id                   string `json:"id"`
	Name                 string `json:"name"`
	NumOfHostChallenges  int    `json:num_of_host_challenges"`
	NumOfIpChallenges    int    `json:num_of_ip_challenges"`
	Timestamp            int    `json:timestamp"`
	RestartTime          int    `json:restart_time"`
	ReloadTime           int    `json:reload_time"`
	SwabberIpDbSize      int    `json:swabber_ip_db_size"`
	ChallengerIpDbSize   int    `json:challenger_ip_db_size"`
	RegexManagerIpDbSize int    `json:regex_manager_ip_db_size"`
}

func ReportStatusMessage(config *Config, decisionLists *DecisionLists) {
	message := StatusMessage{
		Id:                   config.Hostname,
		Name:                 "status",
		NumOfHostChallenges:  0,                      // XXX legacy
		NumOfIpChallenges:    0,                      // XXX legacy
		Timestamp:            int(time.Now().Unix()), // XXX
		RestartTime:          config.RestartTime,
		ReloadTime:           config.ReloadTime,
		SwabberIpDbSize:      0, // XXX legacy
		ChallengerIpDbSize:   0, // XXX legacy
		RegexManagerIpDbSize: 0, // XXX legacy
	}

    bytes, err := json.Marshal(message)
    if err != nil {
        log.Printf("error marshalling status message")
        return
    }
    sendBytesToMessageChan(bytes)
}

type ChallengePassFailMessage struct {
	Id                string `json:"id"`
	Name              string `json:"name"`
	ValueIp           string `json:"value_ip"`
	ValueSite         string `json:"value_site"`
	ValueChallengerDb int `json:"value_challenger_db"`
}

func ReportChallengePassedOrFailed(config *Config, passed bool, ip string, site string) {
    name := "ip_passed_challenge"
    if !passed {
        name = "ip_failed_challenge"
    }

    message := ChallengePassFailMessage{
        Id: config.Hostname,
        Name: name,
        ValueIp: ip,
        ValueSite: site,
        ValueChallengerDb: 0,  // XXX legacy
    }

    bytes, err := json.Marshal(message)
    if err != nil {
        log.Printf("error marshalling ip_{passed,failed}_challenge message")
        return
    }
    sendBytesToMessageChan(bytes)
}

func sendBytesToMessageChan(bytes []byte) {
    log.Println("putting message on messageChan")
    once.Do(func() {
        log.Println("once 2")
        messageChan = make(chan []byte)
    })
    messageChan <- bytes
}

// XXX weird?
var once sync.Once
var messageChan chan []byte

// current commands: status, ip_{passed,failed}_challenge, ip_banned, ip_in_database
func RunKafkaWriter(config *Config, decisionLists *DecisionLists, wg *sync.WaitGroup) {
	// XXX this infinite loop is so we reconnect if we get dropped.
	for {
		w := kafka.NewWriter(kafka.WriterConfig{
			Brokers: config.KafkaBrokers,
			Topic:   "banjax_next_command_topic", // XXX just for testing at the moment
		})
		defer w.Close()

		log.Printf("NewWriter started")

        once.Do(func() {
            log.Println("once 3")
            messageChan = make(chan []byte)
        })

		for {
            msgBytes := <-messageChan
            log.Println("got message from messageChan")

            err := w.WriteMessages(context.Background(),
				kafka.Message{
					Key:   []byte("some-key"),
					Value: msgBytes,
				},
			)
			if err != nil {
				log.Println("WriteMessages() failed")
				log.Println(err)
				break
			}

			log.Println("WriteMessages() succeeded")

			// time.Sleep(2 * time.Second) // XXX just for testing at the moment
		}

		time.Sleep(5 * time.Second) // try to reconnect if we get dropped
	}
}
