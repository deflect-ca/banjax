package internal

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"math"
	"strings"
)

type IntegrityCheckScreenSize struct {
    Width  int `json:"width"`
    Height int `json:"height"`
}

type IntegrityCheckWindowSize struct {
    InnerWidth  int `json:"innerWidth"`
    InnerHeight int `json:"innerHeight"`
}

type IntegrityCheckPayload struct {
    Webdriver   bool       `json:"webdriver"`
    HasPlugins  bool       `json:"hasPlugins"`
    GPURenderer string     `json:"gpuRenderer"`
    CPU         int        `json:"cpu"`
    Memory      int        `json:"memory"`
    Screen      IntegrityCheckScreenSize `json:"screen"`
    Window      IntegrityCheckWindowSize `json:"window"`
    ColorDepth  int        `json:"colorDepth"`
    LangLength  int        `json:"langLength"`
}

// calculateBotScore calculates a bot score based on various payload properties
func integrityCheckCalcBotScore(p IntegrityCheckPayload) (float64, string) {
    factorWeights := map[string]int{
        "webdriver":    10,
        "no_plugins":   3,
        "gpu_renderer": 7,
        "low_cpu":      2,
        "low_memory":   2,
        "color_depth":  1,
        "zero_lang":    3,
        "fullscreen":   2,
        "small_screen": 1,
    }

    // Calculate total maxScore from all weights for normalization
    maxScore := 0
    for _, v := range factorWeights {
        maxScore += v
    }

    score := 0
    factorScores := map[string]int{}

    if p.Webdriver {
        // log.Println("Webdriver detected")
        score += factorWeights["webdriver"]
        factorScores["webdriver"] = factorWeights["webdriver"]
    }

    if !p.HasPlugins {
        // log.Println("No plugins detected")
        score += factorWeights["no_plugins"]
        factorScores["no_plugins"] = factorWeights["no_plugins"]
    }

    if strings.Contains(strings.ToLower(p.GPURenderer), "swiftshader") ||
        strings.Contains(strings.ToLower(p.GPURenderer), "llvmpipe") ||
        strings.Contains(strings.ToLower(p.GPURenderer), "mesa") {
        // log.Println("GPU renderer detected as SwiftShader or similar")
        score += factorWeights["gpu_renderer"]
        factorScores["gpu_renderer"] = factorWeights["gpu_renderer"]
    }

    if p.CPU <= 2 {
        // log.Println("Low CPU count detected")
        score += factorWeights["low_cpu"]
        factorScores["low_cpu"] = factorWeights["low_cpu"]
    }

    if p.Memory <= 2 {
        // log.Println("Low memory detected")
        score += factorWeights["low_memory"]
        factorScores["low_memory"] = factorWeights["low_memory"]
    }

    if p.ColorDepth < 24 {
        // log.Println("Low color depth detected")
        score += factorWeights["color_depth"]
        factorScores["color_depth"] = factorWeights["color_depth"]
    }

    if p.LangLength == 0 {
        // log.Println("Zero language length detected")
        score += factorWeights["zero_lang"]
        factorScores["zero_lang"] = factorWeights["zero_lang"]
    }

    if p.Screen.Width == p.Window.InnerWidth &&
        p.Screen.Height == p.Window.InnerHeight {
        // log.Println("Screen size matches window size")
        score += factorWeights["fullscreen"]
        factorScores["fullscreen"] = factorWeights["fullscreen"]
    }

    if p.Screen.Width < 1000 || p.Screen.Height < 700 {
        // log.Println("Small screen size detected")
        score += factorWeights["small_screen"]
        factorScores["small_screen"] = factorWeights["small_screen"]
    }

    // Find max contributor
    topFactor := ""
    topScore := 0
    for k, v := range factorScores {
        if v >= topScore {
            topScore = v
            topFactor = k
        }
    }

    normalized := math.Min(float64(score)/float64(maxScore), 1.0)
    return normalized, topFactor
}

func integrityCheckCalcBotScoreWrapper(base64Payload string) (float64, string) {
	// check if base64Payload is empty
    if base64Payload == "" {
        return 1.0, "no_payload" // return a high score if payload is empty
    }
    payload, err := integrityCheckDecodePayload(base64Payload)
	if err != nil {
		return 1.0, "err_payload" // return a high score if payload is invalid
	}
	return integrityCheckCalcBotScore(payload)
}

func integrityCheckDecodePayload(base64Payload string) (IntegrityCheckPayload, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		return IntegrityCheckPayload{}, err
	}

	var payload IntegrityCheckPayload
	err = json.Unmarshal(decoded, &payload)
	if err != nil {
		log.Println("integrityCheckDecodePayload: Error unmarshalling JSON:", err)
		return IntegrityCheckPayload{}, err
	}

	// log.Println("Decoded Payload:", payload)
	return payload, nil
}
