package puzzleutil

import (
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"time"
)

type RowCol struct {
	Row int
	Col int
}

type CAPTCHAChallenge struct {
	GameBoard             [][]*Tile         `json:"gameBoard"`
	ThumbnailBase64       string            `json:"thumbnail_base64"`
	MaxAllowedMoves       int               `json:"maxNumberOfMovesAllowed"`
	TimeToSolveMS         int               `json:"timeToSolve_ms"`
	ShowCountdownTimer    bool              `json:"showCountdownTimer"`
	IntegrityCheckHash    string            `json:"integrity_check"`
	CollectDataEnabled    bool              `json:"collect_data"`
	UserDesiredEndpoint   string            `json:"users_intended_endpoint"`
	ChallengeIssuedAtDate string            `json:"challenge_issued_date"`
	ClickChain            []ClickChainEntry `json:"click_chain"`
	ChallengeDifficulty   string            `json:"challenge_difficulty"`
}

var (
	ErrTargetDifficultyDoesNotExist = errors.New("target difficulty profile does not exist")
	ErrFailedNewCAPTCHAGeneration   = errors.New("failed to generate CAPTCHA")
	ErrFailedNewGameboard           = errors.New("failed to create new game board")
	ErrFailedRemovingTile           = errors.New("failed to remove specified (row, col)")
	ErrFailedShuffling              = errors.New("failed to shuffle")
	ErrMissingNullTile              = errors.New("missing null tile: unable to shuffle without having removed one")
	ErrFailedNewClickChain          = errors.New("failed to generate new click chain with genesis entry")
	ErrFailedThumbnailCreation      = errors.New("failed to create thumbnail base64 representation")
)

type CAPTCHAGenerator struct {
	ThumbnailSecret            string //ensures no correlation between the noise added to thumbnail and noise added to user puzzle tiles
	PuzzleSecret               string
	ClickChainUtils            *ClickChainController
	DifficultyConfigController *DifficultyProfileConfig
	SolutionCache              *CAPTCHASolutionCache
	EnabledDataCollection      bool
}

/*CAPTCHAGenerator generates puzzles that are coded to each user such that each puzzle is unique*/
func NewCAPTCHAGenerator(

	thumbnailSecret string,
	puzzleSecret string,
	solutionCache *CAPTCHASolutionCache,
	clickChainUtls *ClickChainController,
	difficultyConfigController *DifficultyProfileConfig,

	enableDataCollection bool,

) *CAPTCHAGenerator {
	return &CAPTCHAGenerator{
		ThumbnailSecret:            thumbnailSecret,
		PuzzleSecret:               puzzleSecret,
		ClickChainUtils:            clickChainUtls,
		DifficultyConfigController: difficultyConfigController,
		SolutionCache:              solutionCache,
		EnabledDataCollection:      enableDataCollection,
	}
}

func (generateCaptcha *CAPTCHAGenerator) NewCAPTCHAChallenge(userChallengeCookie, users_intended_endpoint, b64PngImage, difficulty string) (*CAPTCHAChallenge, error) {

	challengeEntropy := fmt.Sprintf("%s%s", userChallengeCookie, generateCaptcha.PuzzleSecret)

	targetDifficulty, exists := generateCaptcha.DifficultyConfigController.GetTargetProfile()
	if !exists {
		return nil, ErrTargetDifficultyDoesNotExist
	}

	tileMap, err := TileMapFromImage(challengeEntropy, b64PngImage, targetDifficulty.NPartitions)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewCAPTCHAGeneration, err)
	}

	if len(tileMap) != targetDifficulty.NPartitions {
		return nil, fmt.Errorf("%w: expected %d partitions, got: %d", ErrFailedNewCAPTCHAGeneration, targetDifficulty.NPartitions, len(tileMap))
	}

	gameBoard, err := generateCaptcha.newCAPTCHABoard(tileMap, targetDifficulty)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewCAPTCHAGeneration, err)
	}

	deepCopyGameBoard, err := generateCaptcha.deepCopyBoard(gameBoard)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewGameboard, err)
	}

	err = generateCaptcha.removeTileFromBoard(gameBoard, targetDifficulty)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedRemovingTile, err)
	}

	sol_deepCopyOfUnshuffledBoardWithoutImage, err := generateCaptcha.newLocalGameboard(gameBoard)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewGameboard, err)
	}

	row, col := targetDifficulty.RemovedTileIndexToRowCol()
	thumbnailEntropy := GenerateHMACFromString(fmt.Sprintf("%d", time.Now().UnixNano()), generateCaptcha.ThumbnailSecret)
	thumbnailAsB64, err := ThumbnailFromImageWithTransparentTile(thumbnailEntropy, b64PngImage, targetDifficulty.NPartitions, row, col)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedThumbnailCreation, err)
	}

	//after we remove the tile from gameboard, calculate the solution the user would calculate (if they got the right answer)
	sol_ExpectedCorrectSolutionHash := generateCaptcha.calculateExpectedSolutionHash(gameBoard, userChallengeCookie)

	nReShuffles := 0
	err = generateCaptcha.shuffleBoard(gameBoard, deepCopyGameBoard, targetDifficulty, nReShuffles)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedShuffling, err)
	}

	sol_deepCopyOfShuffledBoardWithoutImage, err := generateCaptcha.newLocalGameboard(gameBoard)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewGameboard, err)
	}

	if sol_ExpectedCorrectSolutionHash == "" || len(sol_deepCopyOfUnshuffledBoardWithoutImage) == 0 || len(sol_deepCopyOfShuffledBoardWithoutImage) == 0 {
		return nil, errors.New("ErrFailedExpectation: Expected to create data required for validation, unable to proceed generating puzzle")
	}

	captchaClickChain, err := generateCaptcha.ClickChainUtils.NewClickChain(userChallengeCookie)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewClickChain, err)
	}

	captchaIssuanceTimestamp := captchaClickChain[0].TimeStamp

	hmacPayload := IntegrityCheckCAPTCHAChallenge{
		UserDesiredEndpoint:   users_intended_endpoint,
		MaxAllowedMoves:       targetDifficulty.MaxNumberOfMovesAllowed,
		TimeToSolveMS:         targetDifficulty.TimeToSolveMs,
		ChallengeIssuedAtDate: captchaIssuanceTimestamp,
		CollectDataEnabled:    generateCaptcha.EnabledDataCollection,
		ChallengeDifficulty:   difficulty,
	}
	marshaledIntegrityPayloadBytes, err := hmacPayload.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hmacForIntegrity := GenerateHMACFromString(hmacPayload.JSONBytesToString(marshaledIntegrityPayloadBytes), challengeEntropy)

	captchaToIssueToUser := &CAPTCHAChallenge{
		GameBoard:             gameBoard,
		ThumbnailBase64:       thumbnailAsB64,
		MaxAllowedMoves:       targetDifficulty.MaxNumberOfMovesAllowed,
		TimeToSolveMS:         targetDifficulty.TimeToSolveMs,
		ShowCountdownTimer:    targetDifficulty.ShowCountdownTimer,
		IntegrityCheckHash:    hmacForIntegrity,
		CollectDataEnabled:    generateCaptcha.EnabledDataCollection,
		UserDesiredEndpoint:   users_intended_endpoint,
		ChallengeIssuedAtDate: captchaIssuanceTimestamp,
		ClickChain:            captchaClickChain,
		ChallengeDifficulty:   difficulty,
	}

	cacheValue := CAPTCHASolution{
		UnshuffledGameBoard: sol_deepCopyOfUnshuffledBoardWithoutImage,
		ShuffledGameBoard:   sol_deepCopyOfShuffledBoardWithoutImage,
		PrecomputedSolution: sol_ExpectedCorrectSolutionHash,
		UserDesiredEndpoint: users_intended_endpoint,
	}

	//store the solution in cache until we receive their result such that we can use them in validation
	generateCaptcha.SolutionCache.Set(userChallengeCookie, cacheValue, &targetDifficulty.TimeToSolveMs)

	return captchaToIssueToUser, nil
}

func (generateCaptcha *CAPTCHAGenerator) newCAPTCHABoard(tileMap TileMap, difficultyProfile DifficultyProfile) ([][]*Tile, error) {
	nTiles := len(tileMap)
	size := int(math.Sqrt(float64(nTiles)))

	gameBoard := make([][]*Tile, size)
	for i := range gameBoard {
		gameBoard[i] = make([]*Tile, size)
	}
	//iterate over them in order as maps don't preserve order but we need them to initially be placed in order
	for i := 0; i < nTiles; i++ {
		tile, ok := tileMap[i]
		if !ok {
			return nil, fmt.Errorf("ErrMissingTile: %d", i)
		}
		row, col := difficultyProfile.TileIndexToRowCol(i)
		gameBoard[row][col] = &tile
	}

	return gameBoard, nil
}

/*to save memory, we store only the tileIDs without the base64 when storing the copy of the original for verification*/
func (generateCaptcha *CAPTCHAGenerator) newLocalGameboard(original [][]*Tile) ([][]*TileWithoutImage, error) {
	if len(original) == 0 || len(original[0]) == 0 {
		return nil, errors.New("deepCopyBoard: original board is empty or nil")
	}

	deepCopyGameBoard := make([][]*TileWithoutImage, len(original))

	for i := range original {
		if len(original[i]) != len(original[0]) {
			return nil, errors.New("deepCopyBoard: inconsistent row lengths in original board")
		}
		deepCopyGameBoard[i] = make([]*TileWithoutImage, len(original[i]))

		for j, tile := range original[i] {
			if tile != nil { //protect against nil ptr deref
				newTile := *tile //copy value
				deepCopyGameBoard[i][j] = &TileWithoutImage{TileGridID: newTile.TileGridID}
			} else {
				deepCopyGameBoard[i][j] = nil //keeps `nil` for missing tiles
			}
		}
	}

	return deepCopyGameBoard, nil
}

func (generateCaptcha *CAPTCHAGenerator) deepCopyBoard(original [][]*Tile) ([][]*Tile, error) {
	if len(original) == 0 || len(original[0]) == 0 {
		return nil, errors.New("deepCopyBoard: original board is empty or nil")
	}

	deepCopyGameBoard := make([][]*Tile, len(original))

	for i := range original {
		if len(original[i]) != len(original[0]) {
			return nil, errors.New("deepCopyBoard: inconsistent row lengths in original board")
		}
		deepCopyGameBoard[i] = make([]*Tile, len(original[i]))

		for j, tile := range original[i] {
			if tile != nil { //protect against nil ptr deref
				newTile := *tile                   //copy value
				deepCopyGameBoard[i][j] = &newTile //pointer to new copy
			} else {
				deepCopyGameBoard[i][j] = nil //keeps `nil` for missing tiles
			}
		}
	}

	return deepCopyGameBoard, nil
}

func (generateCaptcha *CAPTCHAGenerator) removeTileFromBoard(boardRef [][]*Tile, targetDifficulty DifficultyProfile) error {
	row, col := targetDifficulty.RemovedTileIndexToRowCol()
	boardRef[row][col] = nil //JSON will serialize this as `null`
	return nil
}

func (generateCaptcha *CAPTCHAGenerator) shuffleBoard(boardRef [][]*Tile, boardCopy [][]*Tile, targetDifficulty DifficultyProfile, nReShuffles int) error {

	MAX_RESHUFFLES := 5

	if nReShuffles > MAX_RESHUFFLES {
		return errors.New("ErrExceededMaxReshuffleAttempts")
	}

	foundNil := false
	rowNil := -1
	colNil := -1

	for r, row := range boardRef {
		for c, tile := range row {
			if tile == nil {
				foundNil = true
				rowNil = r
				colNil = c
				break
			}
		}
	}

	if !foundNil || rowNil == -1 || colNil == -1 {
		return ErrMissingNullTile
	}

	//floor(random * (max-min+1)) + min
	maxNShuffles := targetDifficulty.NShuffles[1]
	minNShuffles := targetDifficulty.NShuffles[0]
	numberOfShufflesToPerform := rng.Intn(maxNShuffles-minNShuffles+1) + minNShuffles

	//now we just apply numberOfShufflesToPerform valid puzzle moves to shuffle!

	var lastRow int
	var lastCol int

	for numberOfShufflesToPerform > 0 {
		nextMove, err := generateCaptcha.getNextValidShuffleMove(boardRef, rowNil, colNil, lastRow, lastCol)
		if err != nil {
			return err
		}
		generateCaptcha.swap(boardRef, rowNil, colNil, nextMove.Row, nextMove.Col)
		lastRow = rowNil
		lastCol = colNil
		rowNil = nextMove.Row
		colNil = nextMove.Col
		numberOfShufflesToPerform--
	}

	if generateCaptcha.isBoardIdentical(boardRef, boardCopy) {
		if nReShuffles >= MAX_RESHUFFLES {
			return errors.New("ErrExceededMaxReshuffleAttempts: Unable to generate a sufficiently shuffled board")
		}

		log.Printf("Detected identical board, reshuffling... %d/%d", nReShuffles, MAX_RESHUFFLES)
		return generateCaptcha.shuffleBoard(boardRef, boardCopy, targetDifficulty, nReShuffles+1)
	}

	return nil
}

func (generateCaptcha *CAPTCHAGenerator) getNextValidShuffleMove(boardRef [][]*Tile, rowNil, colNil, lastRow, lastCol int) (RowCol, error) {
	valid_X_Moves := []int{1, -1, 0, 0}
	valid_Y_Moves := []int{0, 0, 1, -1}
	var possible_valid_moves []RowCol //starts empty

	for i := 0; i < 4; i++ {
		potential_x := rowNil + valid_X_Moves[i]
		potential_y := colNil + valid_Y_Moves[i]

		if 0 <= potential_x && potential_x < len(boardRef) && 0 <= potential_y && potential_y < len(boardRef[0]) && !(lastRow == potential_x && lastCol == potential_y) {
			possible_valid_moves = append(possible_valid_moves, RowCol{Row: potential_x, Col: potential_y})
		}
	}

	if len(possible_valid_moves) == 0 {
		return RowCol{}, errors.New("ErrFailedExpectation: Expected at least one valid move, got none")
	}

	randomChoice := rng.Intn(len(possible_valid_moves))
	return possible_valid_moves[randomChoice], nil
}

func (generateCaptcha *CAPTCHAGenerator) swap(boardRef [][]*Tile, rowNil, colNil, row2, col2 int) {
	nilValue := boardRef[rowNil][colNil]
	boardRef[rowNil][colNil] = boardRef[row2][col2]
	boardRef[row2][col2] = nilValue
}

/*returns "not identical" (ie false) if theres at least one difference between the two boards*/
func (generateCaptcha *CAPTCHAGenerator) isBoardIdentical(boardRef, copyOfBoard [][]*Tile) bool {
	for row := 0; row < len(boardRef); row++ {
		for col := 0; col < len(boardRef[row]); col++ {
			if (boardRef[row][col] == nil) != (copyOfBoard[row][col] == nil) { // Nil mismatch check
				return false
			}
			if boardRef[row][col] != nil && copyOfBoard[row][col] != nil && *boardRef[row][col] != *copyOfBoard[row][col] {
				return false
			}
		}
	}
	return true
}

func (generateCaptcha *CAPTCHAGenerator) calculateExpectedSolutionHash(boardRef [][]*Tile, userChallengeCookie string) string {
	//when the users computes THEIR solution, they will do so using the challenge cookie value as the key against which they calculate their hmac
	//so, we recreate this procedure in order to recreate the solution that they will make:

	var boardIDHashesInOrder strings.Builder
	for _, row := range boardRef {
		for _, tile := range row {
			if tile == nil {
				boardIDHashesInOrder.WriteString("null_tile")
			} else {
				boardIDHashesInOrder.WriteString(tile.TileGridID)
			}
		}
	}

	userCorrectSolution := GenerateHMACFromString(boardIDHashesInOrder.String(), userChallengeCookie)

	//so at this point if the user arranges the baord and submits their solution, they would send us the hash we currently have in: userCorrectSolution
	//so we store this in a map locally using their challenge cookie as the key and the value being the solution. Then on submit we compare them!
	return userCorrectSolution
}

func LogGameBoard(gameBoard [][]*Tile) {
	log.Println("=== GAMEBOARD ===")
	for i, row := range gameBoard {
		rowStr := fmt.Sprintf("Row %d: ", i)
		for _, tile := range row {
			if tile != nil && len(tile.Base64Image) > 20 {
				rowStr += fmt.Sprintf("[%s...] ", tile.Base64Image[:20]) // Preview first 20 chars
			} else {
				rowStr += "[nil] "
			}
		}
		log.Println(rowStr)
	}
}
