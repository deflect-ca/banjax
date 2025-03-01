package captchautils

import (
	"encoding/json"
)

/*
MAKE SURE THAT THE DEFINITIONS IN GO LINE UP EXACTLY IN THE SAME ORDER AS WHAT OCCURS ON IN CLIENT SIDE OTHERWISE THE
MARSHALLING PRODUCES A DIFFERENT JSON SERIALIZED STRING WHICH RESULTS IN AN INCORRECT HMAC
*/

type IntegrityCheckCAPTCHAChallenge struct {
	//the users desired endpoint to ensure we redirect to the appropraite location on success
	UserDesiredEndpoint string `json:"users_intended_endpoint"`

	//tells us the maximum number of clicks we allowed (later compared to the click chain which admits its own integrity check)
	MaxAllowedMoves int `json:"maxNumberOfMovesAllowed"`

	// 	//time to solve and issuance date tells us whether or not it was completed in a reasonable amount of time
	TimeToSolveMS         int    `json:"timeToSolve_ms"`
	ChallengeIssuedAtDate string `json:"challenge_issued_date"`

	// 	//whether or not to collect data tells us what to expect in the collected data object
	CollectDataEnabled bool `json:"collect_data"`

	ChallengeDifficulty string `json:"challenge_difficulty"`
}

// func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) MarshalBinary() ([]byte, error) {

// 	jsonString := fmt.Sprintf(
// 		`{"users_intended_endpoint":"%s","maxNumberOfMovesAllowed":%d,"timeToSolve_ms":%d,"challenge_issued_date":%s,"collect_data":"%v","challenge_difficulty":"%s"}`,
// 		captchaIntegrity.UserDesiredEndpoint,
// 		captchaIntegrity.MaxAllowedMoves,
// 		captchaIntegrity.TimeToSolveMS,
// 		captchaIntegrity.ChallengeIssuedAtDate,
// 		captchaIntegrity.CollectDataEnabled,
// 		captchaIntegrity.ChallengeDifficulty,
// 	)
// 	return []byte(jsonString), nil
// }

func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) MarshalBinary() ([]byte, error) {
	return json.Marshal(captchaIntegrity)
}

func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, captchaIntegrity)
}

func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) JSONBytesToString(data []byte) string {
	return string(data)
}
