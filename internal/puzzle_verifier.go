package internal

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

type ClientSolutionSubmissionPayload struct {
	Solution   string            `json:"solution"`
	ClickChain []ClickChainEntry `json:"click_chain"`
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
	ErrRecreatingTileMap                = errors.New("failed to recreate tile map for validation")
	ErrRecreating                       = errors.New("failed to recreate the puzzle that gave rise to the solution")
)

/*
VerifySolution verifies the solution payload submitted by the user.

The solution is a hash and integrity/anti-cheat is a click chain (similar to how a blockchain works) that we integrity check and verify.

After the integrity check of the click chain is complete we can trust the timestamp embedded into the genesis click chain item
as well as the users challenge cookie string value being the one we issued to them to complete this challenge in particular because:
 1. The genesis click chain item was created using the challenge cookie and
 2. their original TileIDs were re-computed using their cookie value which would not produce the correct tileIDs and subsequently solution otherwise

NOTE:
Technically, this is just 1/2 of the solution. We are also meant to collect data about how the
game was played and make a prediction about bot or not as the hypothesis behind state the "state-space search problem"
puzzle was that bots and people would play the game differently. Regardless, we need to make sure that the solution
itself is indeed correct and we do so with a call to VerifySolution
*/
func ValidatePuzzleCAPTCHASolution(config *Config, userChallengeCookieString string, userCaptchaSolution ClientSolutionSubmissionPayload) error {

	//we need to derive a solution to their challenge, and recompute their shuffled & unshuffled board
	var shuffledBoard [][]*TileWithoutImage
	var unshuffledBoard [][]*TileWithoutImage
	var expectedSolution string
	var err error
	shuffledBoard, unshuffledBoard, expectedSolution, err = GenerateExpectedSolution(config, userChallengeCookieString)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecreating, err)
	}

	if shuffledBoard == nil || unshuffledBoard == nil || expectedSolution == "" {
		return fmt.Errorf("%w: %v", ErrRecreating, errors.New("one or more generated outputs were invalid"))
	}

	//at this point we have recomputed everything, we can now perform the integrity check on the click chain as well as the time limit, click limit and solution checks

	//integrity checks

	err = IntegrityCheckClickChain(userCaptchaSolution.Solution, userChallengeCookieString, config.ClickChainEntropySecret, userCaptchaSolution.ClickChain, shuffledBoard, unshuffledBoard)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedClickChainIntegrity, err)
	}

	//constraints & solutions checks

	err = verifyTimeLimit(config, userCaptchaSolution.ClickChain, userChallengeCookieString)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationFailedTimeLimit, err)
	}

	err = verifyClickLimit(config, userCaptchaSolution.ClickChain, userChallengeCookieString)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationFailedClickLimit, err)
	}

	err = VerifySolutionHash(userCaptchaSolution.Solution, expectedSolution)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationFailedBoardTiles, err)
	}

	return nil
}

func GenerateExpectedSolution(config *Config, userChallengeCookieString string) (shuffledBoard [][]*TileWithoutImage, unshuffledBoard [][]*TileWithoutImage, expectedSolution string, err error) {

	includeB64ImageData := false // dont need b64 image data when verifying the solution
	var tileMap TileMap[TileWithoutImage]

	tileMap, err = TileMapFromImage[TileWithoutImage](config, userChallengeCookieString, includeB64ImageData)
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrRecreatingTileMap, err)
		return
	}

	var exists bool
	targetDifficulty, exists := config.DifficultyProfiles.GetProfileByName(config.DifficultyProfiles.Target, userChallengeCookieString)
	if !exists {
		err = ErrTargetDifficultyDoesNotExist
		return
	}

	shuffledBoard, err = NewCAPTCHABoard(tileMap, targetDifficulty)
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrFailedNewCAPTCHAGeneration, err)
		return
	}

	// Note: We need to remove the tile prior to making a deep copy such that both shuffled and unshuffled boards have the null tile as needed for validation.
	if err = RemoveTileFromBoard(shuffledBoard, targetDifficulty); err != nil {
		err = fmt.Errorf("%w: %v", ErrFailedRemovingTile, err)
		return
	}

	unshuffledBoard, err = DeepCopyTileBoard(shuffledBoard)
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrFailedNewGameboard, err)
		return
	}

	nReShuffles := 0
	if err = ShuffleBoard(shuffledBoard, unshuffledBoard, targetDifficulty, nReShuffles, config.PuzzleEntropySecret, userChallengeCookieString); err != nil {
		err = fmt.Errorf("%w: %v", ErrFailedShuffling, err)
		return
	}

	expectedSolution = CalculateExpectedSolution(unshuffledBoard, userChallengeCookieString)

	return
}

func verifyTimeLimit(config *Config, submittedClickChain []ClickChainEntry, userChallengeCookieString string) error {

	//every click chain will at least admit the genesis block
	if len(submittedClickChain) == 0 {
		return errors.New("ErrExpectedAtLeastGenesisBlock")
	}

	//we do not issue challenges that have not been shuffled
	if len(submittedClickChain) == 1 {
		return errors.New("ErrExpectedAtleastOneClickRequiredToSolve")
	}

	genesisChainEntryIssuedAtTime := submittedClickChain[0].TimeStamp

	dateOfIssuanceByClickChain, err := isValidISOString(genesisChainEntryIssuedAtTime)
	if err != nil {
		return fmt.Errorf("ErrFailedToParseData: Expected date of issuance from click chain to be valid ISO 3399 compliant string, got: %s", genesisChainEntryIssuedAtTime)
	}

	difficultyProfile, exists := config.DifficultyProfiles.GetProfileByName(config.DifficultyProfiles.Target, userChallengeCookieString)
	if !exists {
		return ErrTargetDifficultyDoesNotExist
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

func verifyClickLimit(config *Config, submittedClickChain []ClickChainEntry, userChallengeCookieString string) error {

	//every click chain will at least admit the genesis block
	if len(submittedClickChain) == 0 {
		return errors.New("ErrExpectedAtLeastGenesisBlock")
	}

	//we do not issue challenges that have not been shuffled
	if len(submittedClickChain) == 1 {
		return errors.New("ErrExpectedAtleastOneClickRequiredToSolve")
	}

	difficultyProfile, exists := config.DifficultyProfiles.GetProfileByName(config.DifficultyProfiles.Target, userChallengeCookieString)
	if !exists {
		return ErrTargetDifficultyDoesNotExist
	}

	//click chain will contain the genesis, so we account for it by subtracting by 1 to make sure that the number of clicks is indeed within allowed limit
	nClicksMade := len(submittedClickChain) - 1

	if nClicksMade > difficultyProfile.MaxNumberOfMovesAllowed {
		return fmt.Errorf("ErrClickLimitExceeded: expected nClicksMade: %d < maximum allowed number of clicks to solve puzzle: %d", nClicksMade, difficultyProfile.MaxNumberOfMovesAllowed)
	}

	return nil
}

/*
because "==" leaks info that can be used for timing attacks (users can just keep making strings bigger and bigger to see how it behaves)
we use crypto.subtle's ConstantTimeCompare
*/
func VerifySolutionHash(userSubmittedSolution, locallyStoredPrecomputedSolution string) error {

	solutionA := []byte(userSubmittedSolution)
	solutionB := []byte(locallyStoredPrecomputedSolution)

	if len(solutionA) != len(solutionB) {
		return fmt.Errorf("ErrInvalidSolution: Solutions have different lengths")
	}

	if subtle.ConstantTimeCompare(solutionA, solutionB) == 1 {
		return nil
	}

	return fmt.Errorf("ErrInvalidSolution: Expected %s, received %s", locallyStoredPrecomputedSolution, userSubmittedSolution)
}

func isValidISOString(dateString string) (time.Time, error) {
	parsedTime, err := time.Parse(time.RFC3339, dateString)
	if err != nil {
		return time.Time{}, errors.New("invalid ISO 8601 date string")
	}
	return parsedTime, nil
}
