package models

import (
	captchaUtils "github.com/deflect-ca/banjax/internal/captcha-utils"
	imageUtils "github.com/deflect-ca/banjax/internal/image-utils"
)

type ClientSolutionSubmissionPayload struct {
	Solution          string                          `json:"solution"`
	GameBoard         [][]*imageUtils.Tile            `json:"game_board"`
	CaptchaProperties PayloadVerificationAndIntegrity `json:"captcha_properties"`
	ClickProperties   ClickVerificationAndIntegrity   `json:"click_properties"`
	DataCollected     DataCollected                   `json:"data_collected"`
}

type PayloadVerificationAndIntegrity struct {
	Hash                 string                                      `json:"hash"`
	IntegrityCheckFields captchaUtils.IntegrityCheckCAPTCHAChallenge `json:"integrity_check_fields"`
}

type ClickVerificationAndIntegrity struct {
	NClicksMade int                            `json:"n_clicks_made"`
	ClickChain  []captchaUtils.ClickChainEntry `json:"click_chain"`
}

type DataCollected struct{}
