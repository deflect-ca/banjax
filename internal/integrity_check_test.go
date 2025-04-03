package internal

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestCalculateBotScore(t *testing.T) {
    cases := []struct {
        name     string
        payload  IntegrityCheckPayload
        expected float64
        expectedFactor string
    }{
        {
            name: "All checks triggering",
            payload: IntegrityCheckPayload{
                Webdriver: true,
                HasPlugins: false,
                GPURenderer: "swiftshader",
                CPU: 2,
                Memory: 2,
                Screen: IntegrityCheckScreenSize{Width: 800, Height: 600},
                Window: IntegrityCheckWindowSize{InnerWidth: 800, InnerHeight: 600},
                ColorDepth: 23,
                LangLength: 0,
            },
            expected: 1.0,
            expectedFactor: "webdriver", // Assuming webdriver has the highest single weight
        },
        {
            name: "No checks triggering",
            payload: IntegrityCheckPayload{
                Webdriver: false,
                HasPlugins: true,
                GPURenderer: "unknown",
                CPU: 4,
                Memory: 4,
                Screen: IntegrityCheckScreenSize{Width: 1920, Height: 1080},
                Window: IntegrityCheckWindowSize{InnerWidth: 1900, InnerHeight: 1000},
                ColorDepth: 24,
                LangLength: 2,
            },
            expected: 0.0,
            expectedFactor: "",
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            score, factor := integrityCheckCalcBotScore(c.payload)
            if score != c.expected {
                t.Errorf("Test %s failed: expected score %.2f, got %.2f", c.name, c.expected, score)
            }
            if factor != c.expectedFactor {
                t.Errorf("Test %s failed: expected factor %s, got %s", c.name, c.expectedFactor, factor)
            }
        })
    }
}

func TestCalculateBotScoreWrapper(t *testing.T) {
    payload := IntegrityCheckPayload{
        Webdriver: true,
        HasPlugins: false,
        GPURenderer: "swiftshader",
        CPU: 2,
        Memory: 2,
        Screen: IntegrityCheckScreenSize{Width: 800, Height: 600},
        Window: IntegrityCheckWindowSize{InnerWidth: 800, InnerHeight: 600},
        ColorDepth: 23,
        LangLength: 0,
    }
    payloadBytes, _ := json.Marshal(payload)
    encoded := base64.StdEncoding.EncodeToString(payloadBytes)

    cases := []struct {
        name        string
        base64Input string
        expectedScore float64
        expectedFactor string
    }{
        {
            name: "Valid payload",
            base64Input: encoded,
            expectedScore: 1.0,
            expectedFactor: "webdriver",
        },
        {
            name: "Invalid base64",
            base64Input: "not a base64 string",
            expectedScore: 1.0,
            expectedFactor: "err_payload",
        },
        {
            name: "No payload",
            base64Input: "",
            expectedScore: 1.0,
            expectedFactor: "no_payload",
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            score, factor := integrityCheckCalcBotScoreWrapper(c.base64Input)
            if score != c.expectedScore {
                t.Errorf("Test %s failed: expected score %.2f, got %.2f", c.name, c.expectedScore, score)
            }
            if factor != c.expectedFactor {
                t.Errorf("Test %s failed: expected factor %s, got %s", c.name, c.expectedFactor, factor)
            }
        })
    }
}
