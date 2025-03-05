package puzzleutil

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

var (
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
	PuzzleSecret               string
	SolutionCache              *CAPTCHASolutionCache
	ClickChainUtils            *ClickChainController
	difficultyConfigController *DifficultyProfileConfig
}

/*CAPTCHAVerifier verifies the solution payload submitted by the user.*/
func NewCAPTCHAVerifier(puzzleSecret string, cache *CAPTCHASolutionCache, clickChainController *ClickChainController, difficultyConfigController *DifficultyProfileConfig) *CAPTCHAVerifier {
	return &CAPTCHAVerifier{PuzzleSecret: puzzleSecret, SolutionCache: cache, ClickChainUtils: clickChainController, difficultyConfigController: difficultyConfigController}
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
func (captchaVerifier *CAPTCHAVerifier) VerifySolution(userChallengeCookieString string, userCaptchaSolution ClientSolutionSubmissionPayload) error {

	//get expected solution
	locallyStoredSolution, exists := captchaVerifier.SolutionCache.Get(userChallengeCookieString)
	if !exists {
		log.Printf("Challenge expired or missing for: %s", userChallengeCookieString)
		return ErrCookieDeleteOrNeverExisted
	}

	//apply integrity checks
	err := captchaVerifier.ClickChainUtils.IntegrityCheckClickChain(userChallengeCookieString, userCaptchaSolution.ClickProperties.ClickChain, userCaptchaSolution.GameBoard, locallyStoredSolution.ShuffledGameBoard)
	if err != nil {
		log.Println("Failed to integrity check click chain")
		return fmt.Errorf("%w: %v", ErrFailedClickChainIntegrity, err)
	}

	err = captchaVerifier.integrityCheckCaptchaProperties(userChallengeCookieString, userCaptchaSolution.CaptchaProperties)
	if err != nil {
		log.Println("Failed to integrity check initial captcha properties")
		return fmt.Errorf("%w: %v", ErrFailedCaptchaPropertiesIntegrity, err)
	}

	err = captchaVerifier.integrityCheckGameboard(userChallengeCookieString, userCaptchaSolution)
	if err != nil {
		log.Println("Failed to integrity check gameboard")
		return fmt.Errorf("%w: %v", ErrFailedGameboardIntegrity, err)
	}

	//solutions checks

	err = captchaVerifier.verifyTimeLimit(userCaptchaSolution.CaptchaProperties, userCaptchaSolution.ClickProperties)
	if err != nil {
		log.Println("Failed to verify time limit")
		return fmt.Errorf("%w: %v", ErrVerificationFailedTimeLimit, err)
	}

	err = captchaVerifier.verifyClickLimit(userCaptchaSolution.CaptchaProperties, userCaptchaSolution.ClickProperties)
	if err != nil {
		log.Println("Failed to verify click limit")
		return fmt.Errorf("%w: %v", ErrVerificationFailedClickLimit, err)
	}

	err = captchaVerifier.verifyBoardTiles(userCaptchaSolution.GameBoard, locallyStoredSolution.UnshuffledGameBoard)
	if err != nil {
		log.Println("Failed to verify board tiles")
		return fmt.Errorf("%w: %v", ErrVerificationFailedBoardTiles, err)
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
integrityCheckCaptchaProperties verifies the integrity of the properties we initially sent to the user when we created the puzzle
*/
func (captchaVerifier *CAPTCHAVerifier) integrityCheckCaptchaProperties(userChallengeCookieString string, submittedCaptchaProperties PayloadVerificationAndIntegrity) error {

	hmacPayload := IntegrityCheckCAPTCHAChallenge{
		UserDesiredEndpoint:   submittedCaptchaProperties.IntegrityCheckFields.UserDesiredEndpoint,
		MaxAllowedMoves:       submittedCaptchaProperties.IntegrityCheckFields.MaxAllowedMoves,
		TimeToSolveMS:         submittedCaptchaProperties.IntegrityCheckFields.TimeToSolveMS,
		ChallengeIssuedAtDate: submittedCaptchaProperties.IntegrityCheckFields.ChallengeIssuedAtDate,
		CollectDataEnabled:    submittedCaptchaProperties.IntegrityCheckFields.CollectDataEnabled,
		ChallengeDifficulty:   submittedCaptchaProperties.IntegrityCheckFields.ChallengeDifficulty,
	}

	hmacFromUser := submittedCaptchaProperties.Hash

	hmacPayloadAsBytes, err := hmacPayload.MarshalBinary()
	if err != nil {
		return fmt.Errorf("ErrFailedMarshalBinary: %v", err)
	}

	hmacBytesPayloadAsString := hmacPayload.JSONBytesToString(hmacPayloadAsBytes)

	challengeEntropy := fmt.Sprintf("%s%s", userChallengeCookieString, captchaVerifier.PuzzleSecret)

	expectedHmac := GenerateHMACFromString(hmacBytesPayloadAsString, challengeEntropy)

	if expectedHmac != hmacFromUser {
		return fmt.Errorf("ErrHmacMismatch: Expected %s, got %s", expectedHmac, hmacFromUser)
	}

	return nil
}

/*
integrityCheckGameboard checks the integrity of the board as well as the solution the user submitted.
This is done by recreating the gameboards tile ids which are unique to the user as they are generated using their challenge cookie string value and a secret only we know
We then re-create the solution from the gameboard sent back to make sure that they calculated their solution using the method we provided.
*/
func (captchaVerifier *CAPTCHAVerifier) integrityCheckGameboard(userChallengeCookieString string, userSubmittedCaptchaSolution ClientSolutionSubmissionPayload) error {

	challengeEntropy := fmt.Sprintf("%s%s", userChallengeCookieString, captchaVerifier.PuzzleSecret)

	gameboard := userSubmittedCaptchaSolution.GameBoard

	for rowIndex := 0; rowIndex < len(gameboard); rowIndex++ {
		rowOfTiles := gameboard[rowIndex]
		for colIndex := 0; colIndex < len(rowOfTiles); colIndex++ {
			tile := rowOfTiles[colIndex]
			if tile != nil {
				expectedID := GenerateHMACFromString(tile.Base64Image, challengeEntropy)
				if expectedID != tile.TileGridID {
					log.Printf("ErrTamperedTile: Gameboard tile ID does not match expected HMAC. Expected row:%d col:%d id to be: %s, got: %s", rowIndex, colIndex, expectedID, tile.TileGridID)
					return fmt.Errorf("ErrTamperedTile: Gameboard tile ID does not match expected HMAC. Expected row:%d col:%d id to be: %s, got: %s", rowIndex, colIndex, expectedID, tile.TileGridID)
				}
			}
		}
	}

	var boardIDHashesInOrder strings.Builder
	for _, row := range gameboard {
		for _, tile := range row {
			if tile == nil {
				boardIDHashesInOrder.WriteString("null_tile")
			} else {
				boardIDHashesInOrder.WriteString(tile.TileGridID)
			}
		}
	}

	//here we re-create the solution from the gameboard sent back to make sure that they calculated their solution using the method we provided.
	//the `expectedSolutionDerivedFromGrid` should match the users submitted hash. NOTE this is NOT the same thing as checking their answer. All this does is check that
	//the solution they submitted was actually derived from the board they submitted. The userSubmittedSolution.solution CAN be wrong. That is why we still need
	//to compare their userSubmittedSolution.solution to the actual pre-computed result we stored in the map
	expectedSolutionDerivedFromGrid := GenerateHMACFromString(boardIDHashesInOrder.String(), userChallengeCookieString)

	if expectedSolutionDerivedFromGrid != userSubmittedCaptchaSolution.Solution {
		log.Println("ErrTamperedSolution: Users submitted solution hash was NOT derived from this game board")
		return errors.New("ErrTamperedSolution: Users submitted solution hash was NOT derived from this game board")
	}

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
func (captchaVerifier *CAPTCHAVerifier) verifyTimeLimit(submittedCaptchaProperties PayloadVerificationAndIntegrity, submittedClickProperties ClickVerificationAndIntegrity) error {

	dateOfIssuanceByProperties, err := captchaVerifier.isValidISOString(submittedCaptchaProperties.IntegrityCheckFields.ChallengeIssuedAtDate)
	if err != nil {
		return fmt.Errorf("ErrFailedToParseData: Expected date of issuance from properties to be valid ISO 3399 compliant string, got: %s", submittedCaptchaProperties.IntegrityCheckFields.ChallengeIssuedAtDate)
	}

	genesisChainEntryIssuedAtTime := submittedClickProperties.ClickChain[0].TimeStamp

	dateOfIssuanceByClickChain, err := captchaVerifier.isValidISOString(genesisChainEntryIssuedAtTime)
	if err != nil {
		return fmt.Errorf("ErrFailedToParseData: Expected date of issuance from click chain to be valid ISO 3399 compliant string, got: %s", genesisChainEntryIssuedAtTime)
	}

	if submittedCaptchaProperties.IntegrityCheckFields.ChallengeIssuedAtDate != genesisChainEntryIssuedAtTime {
		return fmt.Errorf("ErrFailedDateComparison: Expected data from genesis chain entry: %s to match in integrity checked properties %s", genesisChainEntryIssuedAtTime, submittedCaptchaProperties.IntegrityCheckFields.ChallengeIssuedAtDate)
	}

	if !dateOfIssuanceByProperties.Equal(dateOfIssuanceByClickChain) {
		return fmt.Errorf("ErrFailedDateComparison: Expected timestamp from genesis chain entry: %s to match timestamp in integrity-checked properties: %s", genesisChainEntryIssuedAtTime, submittedCaptchaProperties.IntegrityCheckFields.ChallengeIssuedAtDate)
	}

	//use the `submittedCaptchaProperties.IntegrityCheckFields.ChallengeDifficulty` to get the amount of time they were allowed to use
	difficultyProfile, exists := captchaVerifier.difficultyConfigController.GetProfileByName(submittedCaptchaProperties.IntegrityCheckFields.ChallengeDifficulty)
	if !exists {
		return fmt.Errorf("ErrFailedDifficultyProfileLookup: The difficulty submitted by user is unknown: %s", submittedCaptchaProperties.IntegrityCheckFields.ChallengeDifficulty)
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
func (captchaVerifier *CAPTCHAVerifier) verifyClickLimit(submittedCaptchaProperties PayloadVerificationAndIntegrity, submittedClickProperties ClickVerificationAndIntegrity) error {

	nClicksMade := submittedClickProperties.NClicksMade
	clickChain := submittedClickProperties.ClickChain

	if nClicksMade != len(clickChain)-1 {
		return fmt.Errorf("ErrClickLimitIncorrect: Expected nClicksMade: %d to match number of clicks tracked by click chain: %d", nClicksMade, len(clickChain)-1)
	}

	if nClicksMade > submittedCaptchaProperties.IntegrityCheckFields.MaxAllowedMoves {
		return fmt.Errorf("ErrClickLimitExceeded: expected nClicksMade: %d < maximum allowed number of clicks to solve puzzle: %d", nClicksMade, submittedCaptchaProperties.IntegrityCheckFields.MaxAllowedMoves)
	}

	return nil
}

/*
verifyBoardTiles takes the original board we created as the captcha (and stored server side in cache) BEFORE it was shuffled, and compare it to the board
submitted by the user to confirm that their board is indeed unshuffled as desired
*/
func (captchaVerifier *CAPTCHAVerifier) verifyBoardTiles(userSubmittedGameboard [][]*Tile, locallyStoredUnshuffledGameBoard [][]*TileWithoutImage) error {

	if len(userSubmittedGameboard) == 0 || len(locallyStoredUnshuffledGameBoard) == 0 {
		log.Println("ErrInvalidGameboard: One or both gameboards are empty")
		return errors.New("ErrInvalidGameboard: One or both gameboards are empty")
	}

	if len(userSubmittedGameboard) != len(locallyStoredUnshuffledGameBoard) || len(userSubmittedGameboard[0]) != len(locallyStoredUnshuffledGameBoard[0]) {
		log.Printf("ErrDimensionMismatch: Expected gameboard dimensions (%dx%d) but got (%dx%d)", len(locallyStoredUnshuffledGameBoard), len(locallyStoredUnshuffledGameBoard[0]), len(userSubmittedGameboard), len(userSubmittedGameboard[0]))
		return fmt.Errorf("ErrDimensionMismatch: Expected gameboard dimensions (%dx%d) but got (%dx%d)", len(locallyStoredUnshuffledGameBoard), len(locallyStoredUnshuffledGameBoard[0]), len(userSubmittedGameboard), len(userSubmittedGameboard[0]))
	}

	// log.Println("User submitted board: ")
	// LogGameBoard(userSubmittedGameboard)

	// log.Printf("\nOriginal unshuffled board:")
	// LogCachedGameBoard(locallyStoredUnshuffledGameBoard)

	//now we need only iteratively check that the submitted board and the original board match id for id in the SAME order
	//we already confirmed the size of the game boards are the same, so the dimensions we use are guarenteed to work for both
	nRows := len(locallyStoredUnshuffledGameBoard)
	nCols := len(locallyStoredUnshuffledGameBoard[0])

	for r := 0; r < nRows; r++ {
		for c := 0; c < nCols; c++ {
			userEntry := userSubmittedGameboard[r][c]
			localEntry := locallyStoredUnshuffledGameBoard[r][c]

			//either they're both nil (ie they're the same so great) or they both not nil (so they must have the same id and if so great)
			//otherwise, they're necessarily different, so return error

			if localEntry == nil && userEntry != nil {
				log.Printf("ErrNullTilePositionMismatch: Expected null at (%d,%d), but got tile with ID: %s", r, c, userEntry.TileGridID)
				return fmt.Errorf("ErrNullTilePositionMismatch: Expected null at (%d,%d), but got tile with ID: %s", r, c, userEntry.TileGridID)
			}

			if localEntry != nil && userEntry == nil {
				log.Printf("ErrFinalBoardMismatch: Expected tile ID %s at (%d,%d) but received null", localEntry.TileGridID, r, c)
				return fmt.Errorf("ErrFinalBoardMismatch: Expected tile ID %s at (%d,%d) but received null", localEntry.TileGridID, r, c)
			}

			if localEntry != nil && userEntry != nil && localEntry.TileGridID != userEntry.TileGridID {
				log.Printf("ErrFinalBoardMismatch: Expected tile ID %s at (%d,%d) but received %s", localEntry.TileGridID, r, c, userEntry.TileGridID)
				return fmt.Errorf("ErrFinalBoardMismatch: Expected tile ID %s at (%d,%d) but received %s", localEntry.TileGridID, r, c, userEntry.TileGridID)
			}
		}
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

// func LogGameBoard(gameBoard [][]*imageutils.Tile) {
// 	log.Println("=== GAMEBOARD ===")
// 	for i, row := range gameBoard {
// 		rowStr := fmt.Sprintf("Row %d: ", i)
// 		for _, tile := range row {
// 			if tile != nil && len(tile.TileGridID) > 20 {
// 				rowStr += fmt.Sprintf("[%s...] ", tile.TileGridID[:20])
// 			} else {
// 				rowStr += "[nil] "
// 			}
// 		}
// 		log.Println(rowStr)
// 	}
// }

// func LogCachedGameBoard(gameBoard [][]*imageutils.TileWithoutImage) {
// 	log.Println("=== GAMEBOARD ===")
// 	for i, row := range gameBoard {
// 		rowStr := fmt.Sprintf("Row %d: ", i)
// 		for _, tile := range row {
// 			if tile != nil && len(tile.TileGridID) > 20 {
// 				rowStr += fmt.Sprintf("[%s...] ", tile.TileGridID[:20])
// 			} else {
// 				rowStr += "[nil] "
// 			}
// 		}
// 		log.Println(rowStr)
// 	}
// }
