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

func RunKafkaReader(config Config, ipsToChallenge *map[string]bool, wg *sync.WaitGroup) {
	defer wg.Done()

	// XXX this infinite loop is so we reconnect if we get dropped.
	for {
		r := kafka.NewReader(kafka.ReaderConfig{
			Brokers: config.KafkaBrokers,
			GroupID: uuid.New().String(),
			Topic:   "banjax_next_command_topic",
		})
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
				break // XXX what to do here?
			}

			log.Printf("message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))

			command := commandMessage{}
			err = json.Unmarshal(m.Value, &command)
			if err != nil {
				log.Println("json.Unmarshal() failed")
			}

			handleCommand(command, ipsToChallenge)
		}

		time.Sleep(5 * time.Second)
	}
}

func handleCommand(command commandMessage, ipsToChallenge *map[string]bool) {
	if command.Name == "challenge_ip" {
		// XXX check it's a good ip here?
		if len(command.Value) > 4 {
			(*ipsToChallenge)[command.Value] = true
			log.Println("ipsToChallenge: ", ipsToChallenge)
		} else {
			log.Println("bad command value?")
		}
	} else {
		log.Println("unrecognized command name")
	}
}

func RunKafkaWriter(config Config, wg *sync.WaitGroup) {
	// XXX this infinite loop is so we reconnect if we get dropped.
	for {
		w := kafka.NewWriter(kafka.WriterConfig{
			Brokers: config.KafkaBrokers,
			Topic:   "banjax_next_command_topic", // XXX just for testing at the moment
		})
		defer w.Close()

		log.Printf("NewWriter started")

		for {
			command := commandMessage{"challenge_ip", "1.2.3.4"}
			msgBytes, err := json.Marshal(command)
			if err != nil {
				log.Println("json.Marshal() failed")
				continue
			}

			err = w.WriteMessages(context.Background(),
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

			time.Sleep(2 * time.Second) // XXX just for testing at the moment
		}

		time.Sleep(5 * time.Second) // try to reconnect if we get dropped
	}
}
