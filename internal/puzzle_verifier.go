package internal

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"
)

type ClientSolutionSubmissionPayload struct {
	Solution   string            `json:"solution"`
	ClickChain []ClickChainEntry `json:"click_chain"`
}

type ClickVerificationAndIntegrity struct {
	NClicksMade int               `json:"n_clicks_made"`
	ClickChain  []ClickChainEntry `json:"click_chain"`
}

type DataCollected struct{}

/*
It is important to ensure that the IntegrityCheckCAPTCHAChallenge struct matches the client side definition with respect order when serializing.
If the order does not match, then even if the data is correct, the resultant hash will not be the same.
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

func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) MarshalBinary() ([]byte, error) {
	return json.Marshal(captchaIntegrity)
}

func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, captchaIntegrity)
}

func (captchaIntegrity *IntegrityCheckCAPTCHAChallenge) JSONBytesToString(data []byte) string {
	return string(data)
}

var (
	ErrInvalidGenesisClickChainEntry    = errors.New("submitted click chain entry does not match expectation")
	ErrCookieDeleteOrNeverExisted       = errors.New("solution was either submitted too late so the cookie was deleted or never existed")
	ErrFailedClickChainIntegrity        = errors.New("failed click chain integrity check")
	ErrFailedCaptchaPropertiesIntegrity = errors.New("failed captcha properties integrity check")
	ErrFailedGameboardIntegrity         = errors.New("failed game board integrity check")
	ErrVerificationFailedTimeLimit      = errors.New("submitted solution failed time limit check")
	ErrVerificationFailedClickLimit     = errors.New("submitted solution failed click limit check")
	ErrVerificationFailedBoardTiles     = errors.New("submitted solution failed board tiles check")
	ErrVerificationFailedSolutionHash   = errors.New("submitted solution failed hash check")
)

type CAPTCHAVerifier struct {
	PuzzleSecret          string
	SolutionCache         *CAPTCHASolutionCache
	ClickChainUtils       *ClickChainController
	EnabledDataCollection bool //if it was enabled, we can verify we received the payload when validating and pass it to the prediction part
}

/*CAPTCHAVerifier verifies the solution payload submitted by the user.*/
func NewCAPTCHAVerifier(

	puzzleSecret string,
	cache *CAPTCHASolutionCache,
	clickChainController *ClickChainController,

	enabledDataCollection bool,

) *CAPTCHAVerifier {

	return &CAPTCHAVerifier{
		PuzzleSecret:          puzzleSecret,
		SolutionCache:         cache,
		ClickChainUtils:       clickChainController,
		EnabledDataCollection: enabledDataCollection,
	}
}

/*
VerifySolution verifies the solution payload submitted by the user.

The solution is a click chain (similar to how a blockchain works) that we integrity check and verify.
It's a record of the clicks made while the user was solving.

NOTE: Technically, this is just 1/2 of the solution. We are also meant to collect data about how the
game was played and make a prediction about bot or not as the hypothesis behind state the "state-space search problem"
puzzle was that bots and people would play the game differently. Regardless, we need to make sure that the solution
itself is indeed correct and we do so with a call to VerifySolution
*/
func (captchaVerifier *CAPTCHAVerifier) VerifySolution(config *Config, userChallengeCookieString string, userCaptchaSolution ClientSolutionSubmissionPayload) error {

	//get expected solution
	locallyStoredSolution, exists := captchaVerifier.SolutionCache.Get(userChallengeCookieString)
	if !exists {
		log.Printf("Challenge expired or missing for: %s", userChallengeCookieString)
		return ErrCookieDeleteOrNeverExisted
	}

	//apply integrity checks
	err := captchaVerifier.ClickChainUtils.IntegrityCheckClickChainGenesis(userCaptchaSolution.ClickChain, locallyStoredSolution.GenesisClickChainItem)
	if err != nil {
		log.Println("Failed genesis click chain entry direct comparison")
		return fmt.Errorf("%w: %v", ErrInvalidGenesisClickChainEntry, err)
	}

	err = captchaVerifier.ClickChainUtils.IntegrityCheckClickChain(userCaptchaSolution.Solution, userChallengeCookieString, userCaptchaSolution.ClickChain, locallyStoredSolution.ShuffledGameBoard, locallyStoredSolution.UnshuffledGameBoard)
	if err != nil {
		log.Println("Failed to integrity check click chain")
		return fmt.Errorf("%w: %v", ErrFailedClickChainIntegrity, err)
	}

	//solutions checks

	err = captchaVerifier.verifyTimeLimit(config, locallyStoredSolution.PuzzleIntegrityProperties, userCaptchaSolution.ClickChain)
	if err != nil {
		log.Println("Failed to verify time limit")
		return fmt.Errorf("%w: %v", ErrVerificationFailedTimeLimit, err)
	}

	err = captchaVerifier.verifyClickLimit(locallyStoredSolution.PuzzleIntegrityProperties, userCaptchaSolution.ClickChain)
	if err != nil {
		log.Println("Failed to verify click limit")
		return fmt.Errorf("%w: %v", ErrVerificationFailedClickLimit, err)
	}

	err = captchaVerifier.verifySolutionHash(userCaptchaSolution.Solution, locallyStoredSolution.PrecomputedSolution)
	if err != nil {
		log.Println("Failed to verify solution hash")
		return fmt.Errorf("%w: %v", ErrVerificationFailedBoardTiles, err)
	}

	captchaVerifier.SolutionCache.Delete(userChallengeCookieString)

	return nil
}

/*
verifyTimeLimit is to be called only AFTER having completed ALL of the following:
 1. integrity checked the click chain
 2. integrity checked the CAPTCHA properties (which include the maximum number of clicks a user is allowed to make)

We need to check the click chain because only then can we trust the date of the genesis click chain entry which is the date of the challenge issuance
We need the captcha properties integrity check since that is how we tie this current captcha challenge to when the challenge was issued (linking the properties to the click list)

The function compare the date of the properties with the date of the captcha to ensure that they are the same (as when issuing the challenge we use the genesis blocks date as the start time)
From there, we lookup the amount of time allowed by using the difficulty (which was also part of the integrity check properties) to see if nowTime exceeds startTime + max time allowed as by difficulty
*/
func (captchaVerifier *CAPTCHAVerifier) verifyTimeLimit(config *Config, locallyStoredCaptchaProperties IntegrityCheckCAPTCHAChallenge, submittedClickChain []ClickChainEntry) error {

	//every click chain will at least admit the genesis block
	if len(submittedClickChain) == 0 {
		return errors.New("ErrExpectedAtLeastGenesisBlock")
	}

	//we do not issue challenges that have not been shuffled
	if len(submittedClickChain) == 1 {
		return errors.New("ErrExpectedAtleastOneClickRequiredToSolve")
	}

	dateOfIssuanceByProperties, err := captchaVerifier.isValidISOString(locallyStoredCaptchaProperties.ChallengeIssuedAtDate)
	if err != nil {
		return fmt.Errorf("ErrFailedToParseData: Expected date of issuance from properties to be valid ISO 3399 compliant string, got: %s", locallyStoredCaptchaProperties.ChallengeIssuedAtDate)
	}

	genesisChainEntryIssuedAtTime := submittedClickChain[0].TimeStamp

	dateOfIssuanceByClickChain, err := captchaVerifier.isValidISOString(genesisChainEntryIssuedAtTime)
	if err != nil {
		return fmt.Errorf("ErrFailedToParseData: Expected date of issuance from click chain to be valid ISO 3399 compliant string, got: %s", genesisChainEntryIssuedAtTime)
	}

	if locallyStoredCaptchaProperties.ChallengeIssuedAtDate != genesisChainEntryIssuedAtTime {
		return fmt.Errorf("ErrFailedDateComparison: Expected data from genesis chain entry: %s to match in integrity checked properties %s", genesisChainEntryIssuedAtTime, locallyStoredCaptchaProperties.ChallengeIssuedAtDate)
	}

	if !dateOfIssuanceByProperties.Equal(dateOfIssuanceByClickChain) {
		return fmt.Errorf("ErrFailedDateComparison: Expected timestamp from genesis chain entry: %s to match timestamp in integrity-checked properties: %s", genesisChainEntryIssuedAtTime, locallyStoredCaptchaProperties.ChallengeIssuedAtDate)
	}

	//use the `submittedCaptchaProperties.IntegrityCheckFields.ChallengeDifficulty` to get the amount of time they were allowed to use
	//we use `false` for entropy but it doesn't matter the tile to remove isnt considered here, we only care about issuance which doesn't change
	difficultyProfile, exists := config.DifficultyProfiles.GetProfileByName(locallyStoredCaptchaProperties.ChallengeDifficulty, config.UseFreshEntropyForDynamicTileRemoval)
	if !exists {
		return fmt.Errorf("ErrFailedDifficultyProfileLookup: The difficulty submitted by user is unknown: %s", locallyStoredCaptchaProperties.ChallengeDifficulty)
	}

	//now compare the time it was issued with the time we get from the challenge difficulty to know whether or not they actually exceeded the time limit
	maxTimeAllowed := time.Duration(difficultyProfile.TimeToSolveMs) * time.Millisecond

	//adjust issuedAtDate by the allowed solving time in order to compare to nowTime
	expiryTime := dateOfIssuanceByClickChain.Add(maxTimeAllowed)

	//we account for potential network/processing delay by adding 2 seconds (2000 ms) to nowTime
	now := time.Now().Add(2 * time.Second)

	if now.After(expiryTime) {
		return fmt.Errorf("ErrTimeExpired: Expected puzzle (issued at: %s) to be solved within: %d ms (by: %s), but received result at: %s", dateOfIssuanceByClickChain, difficultyProfile.TimeToSolveMs, expiryTime, now)
	}

	return nil
}

/*
verifyClickLimit is to be called only AFTER having completed ALL of the following:
 1. integrity checked the click chain
 2. integrity checked the CAPTCHA properties (which include the maximum number of clicks a user is allowed to make)
 3. verified that the clicks made from start to finish actually result in the puzzle board that was submitted
 4. verified that the submitted puzzle board was valid

Together, all of these checks ensure that the number of clicks used did not exceed the preset maximum as well as actually returned a valid result
*/
func (captchaVerifier *CAPTCHAVerifier) verifyClickLimit(locallyStoredCaptchaProperties IntegrityCheckCAPTCHAChallenge, submittedClickChain []ClickChainEntry) error {

	//every click chain will at least admit the genesis block
	if len(submittedClickChain) == 0 {
		return errors.New("ErrExpectedAtLeastGenesisBlock")
	}

	//we do not issue challenges that have not been shuffled
	if len(submittedClickChain) == 1 {
		return errors.New("ErrExpectedAtleastOneClickRequiredToSolve")
	}

	//click chain will contain the genesis, so we account for it by subtracting by 1 to make sure that the number of clicks is indeed within allowed limit
	nClicksMade := len(submittedClickChain) - 1

	if nClicksMade > locallyStoredCaptchaProperties.MaxAllowedMoves {
		return fmt.Errorf("ErrClickLimitExceeded: expected nClicksMade: %d < maximum allowed number of clicks to solve puzzle: %d", nClicksMade, locallyStoredCaptchaProperties.MaxAllowedMoves)
	}

	return nil
}

/*
verifySolutionHash is to be called only AFTER having completed ALL of the following:
 1. integrity checked the click chain
 2. integrity checked the CAPTCHA properties (which include the maximum number of clicks a user is allowed to make)
 3. verified that the clicks made from start to finish actually result in the puzzle board that was submitted
 4. verified that the submitted puzzle board was valid
    verifySolutionHash actually checks to see that the answer is right
*/
func (captchaVerifier *CAPTCHAVerifier) verifySolutionHash(submittedSolution, locallyStoredPrecomputedSolution string) error {
	//because "==" leaks info that can be used for timing attacks (users can just keep making strings bigger and bigger to see how it behaves)
	//we use crypto.subtle's ConstantTimeCompare
	solutionA := []byte(submittedSolution)
	solutionB := []byte(locallyStoredPrecomputedSolution)

	if len(solutionA) != len(solutionB) {
		return fmt.Errorf("ErrInvalidSolution: Solutions have different lengths")
	}

	if subtle.ConstantTimeCompare(solutionA, solutionB) == 1 {
		return nil
	}
	return fmt.Errorf("ErrInvalidSolution: Expected %s, received %s", locallyStoredPrecomputedSolution, submittedSolution)
}

func (captchaVerifier *CAPTCHAVerifier) isValidISOString(dateString string) (time.Time, error) {
	parsedTime, err := time.Parse(time.RFC3339, dateString)
	if err != nil {
		return time.Time{}, errors.New("invalid ISO 8601 date string")
	}
	return parsedTime, nil
}
