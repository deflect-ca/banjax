package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
)

type PuzzleCAPTCHAChallenge struct {
	GameBoard          [][]*PuzzleTile   `json:"gameBoard"`
	ThumbnailBase64    string            `json:"thumbnail_base64"`
	MaxAllowedMoves    int               `json:"maxNumberOfMovesAllowed"`
	TimeToSolveMS      int               `json:"timeToSolve_ms"`
	CollectDataEnabled bool              `json:"collect_data"`
	ClickChain         []ClickChainEntry `json:"click_chain"`
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
	ErrFailedMarhsalingChallenge    = errors.New("failed to marshal new CAPTCHAChallenge struct")
)

func GeneratePuzzleCAPTCHA(config *Config, puzzleImageController *PuzzleImageController, userChallengeCookie string) ([]byte, error) {

	targetDifficulty, exists := PuzzleDifficultyProfileByName(config, config.PuzzleDifficultyTarget, userChallengeCookie)
	if !exists {
		return nil, ErrTargetDifficultyDoesNotExist
	}

	includeB64ImageData := true
	tileMap, err := PuzzleTileMapFromImage[PuzzleTile](config, puzzleImageController, userChallengeCookie, includeB64ImageData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewCAPTCHAGeneration, err)
	}

	if len(tileMap) != targetDifficulty.NPartitions {
		return nil, fmt.Errorf("%w: expected %d partitions, got: %d", ErrFailedNewCAPTCHAGeneration, targetDifficulty.NPartitions, len(tileMap))
	}

	gameBoard, err := NewPuzzleCAPTCHABoard(tileMap, targetDifficulty)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewCAPTCHAGeneration, err)
	}

	deepCopyGameBoard, err := DeepCopyPuzzleTileBoard(gameBoard)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewGameboard, err)
	}

	err = RemovePuzzleTileFromBoard(gameBoard, targetDifficulty)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedRemovingTile, err)
	}

	row, col := PuzzleTileIndexToRowCol(targetDifficulty.RemoveTileIndex, targetDifficulty.NPartitions)
	thumbnailAsB64, err := PuzzleThumbnailFromImage(config, puzzleImageController, config.PuzzleThumbnailEntropySecret, row, col)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedThumbnailCreation, err)
	}

	nReShuffles := 0
	err = ShufflePuzzleBoard(gameBoard, deepCopyGameBoard, targetDifficulty, nReShuffles, config.PuzzleEntropySecret, userChallengeCookie)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedShuffling, err)
	}

	captchaClickChain, err := NewPuzzleClickChain(userChallengeCookie, config.PuzzleClickChainEntropySecret)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedNewClickChain, err)
	}

	captchaToIssueToUser := &PuzzleCAPTCHAChallenge{
		GameBoard:          gameBoard,
		ThumbnailBase64:    thumbnailAsB64,
		MaxAllowedMoves:    targetDifficulty.MaxNumberOfMovesAllowed,
		TimeToSolveMS:      targetDifficulty.TimeToSolveMs,
		CollectDataEnabled: config.PuzzleEnableGameplayDataCollection,
		ClickChain:         captchaClickChain,
	}

	serializedCAPTCHAChallenge, err := json.Marshal(captchaToIssueToUser)
	if err != nil {
		return nil, fmt.Errorf("%w, %v", ErrFailedMarhsalingChallenge, err)
	}

	return serializedCAPTCHAChallenge, nil
}

var (
	ErrMissingTile              = errors.New("gamboard controller expected a tile to exist")
	ErrBoardEmpty               = errors.New("board is empty or nil")
	ErrBoardHieghtWidthMismatch = errors.New("gameboard must be a perfect square")
)

func NewPuzzleCAPTCHABoard[T PuzzleTileIdentifier](tileMap PuzzleTileMap[T], difficultyProfile PuzzleDifficultyProfile) ([][]*T, error) {
	nTiles := len(tileMap)
	size := int(math.Sqrt(float64(nTiles)))

	gameBoard := make([][]*T, size)
	for i := range gameBoard {
		gameBoard[i] = make([]*T, size)
	}

	//iterate over them in order as maps don't preserve order but we need them to initially be placed in order
	for i := 0; i < nTiles; i++ {
		tile, ok := tileMap[i]
		if !ok {
			return nil, fmt.Errorf("%w: Expected: %d", ErrMissingTile, i)
		}
		row, col := PuzzleTileIndexToRowCol(i, difficultyProfile.NPartitions)
		gameBoard[row][col] = &tile
	}

	return gameBoard, nil
}

/* Returns a deep copy of a game board for any type implementing TileIdentifier */
func DeepCopyPuzzleTileBoard[T PuzzleTileIdentifier](original [][]*T) ([][]*T, error) {
	if len(original) == 0 || len(original[0]) == 0 {
		return nil, fmt.Errorf("%w: deepCopyBoard: original board is empty or nil", ErrBoardEmpty)
	}

	deepCopyGameBoard := make([][]*T, len(original))

	for i := range original {
		if len(original[i]) != len(original[0]) {
			return nil, fmt.Errorf("%w: deepCopyBoard: inconsistent row lengths in original board", ErrBoardHieghtWidthMismatch)
		}
		deepCopyGameBoard[i] = make([]*T, len(original[i]))

		for j, tile := range original[i] {
			if tile != nil { // protect against nil ptr deref
				newTile := *tile                   // copy value
				deepCopyGameBoard[i][j] = &newTile // pointer to new copy
			} else {
				deepCopyGameBoard[i][j] = nil // keeps `nil` for missing tiles
			}
		}
	}

	return deepCopyGameBoard, nil
}

/*
shuffleBoard will shuffle the board in a deterministically random way. NOTE: the shuffling procedure amounts to playing the game backward.

Ie, provided the SAME userChallengeCookie (and puzzleSecret as this is called directly from inside of the deriveEntropyInRange() func),
we will always be able to re-shuffle a board in exactly the same way. This is an essential part of being able to verify the solution
of the user by recreating the board we provided them without needing to store anything server side.

So, if a request comes in on a different server instance (or after a restart), as long as userChallengeCookie and puzzleSecret are unchanged, the board will
be reconstructed exactly as it was when the challenge was issued.
*/
func ShufflePuzzleBoard[T PuzzleTileIdentifier](boardRef [][]*T, boardCopy [][]*T, targetDifficulty PuzzleDifficultyProfile, nReShuffles int, puzzleSecret, userChallengeCookie string) error {

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
	numberOfShufflesToPerform := PuzzleEntropyFromRange(puzzleSecret, userChallengeCookie, minNShuffles, maxNShuffles)

	//now we just apply numberOfShufflesToPerform valid puzzle moves to shuffle!

	var lastRow int
	var lastCol int

	for numberOfShufflesToPerform > 0 {
		row, col, err := getNextValidPuzzleShuffleMove(boardRef, rowNil, colNil, lastRow, lastCol, puzzleSecret, userChallengeCookie)
		if err != nil {
			return err
		}
		SwapPuzzleTile(boardRef, rowNil, colNil, row, col)
		lastRow = rowNil
		lastCol = colNil
		rowNil = row
		colNil = col
		numberOfShufflesToPerform--
	}

	if IsPuzzleBoardIdentical(boardRef, boardCopy) {
		if nReShuffles >= MAX_RESHUFFLES {
			return errors.New("ErrExceededMaxReshuffleAttempts: Unable to generate a sufficiently shuffled board")
		}

		log.Printf("Detected identical board, reshuffling... %d/%d", nReShuffles, MAX_RESHUFFLES)
		return ShufflePuzzleBoard(boardRef, boardCopy, targetDifficulty, nReShuffles+1, puzzleSecret, userChallengeCookie)
	}

	return nil
}

/*
getNextValidShuffleMove is used when shuffling to check whether the next move is valid as the entire shuffling procedure amounts
to playing the game backward.

The important thing to note is that again, the randomness is dependent on the users challenge cookie as its source of entropy. This is
an essential part of how we verify solutions during runtime without needing to store anything in memory on a per challenge basis.

So, if a request comes in on a different server instance (or after a restart), as long as userChallengeCookie and puzzleSecret are unchanged, the board will
be reconstructed exactly as it was when the challenge was issued.
*/
func getNextValidPuzzleShuffleMove[T PuzzleTileIdentifier](boardRef [][]*T, rowNil, colNil, lastRow, lastCol int, puzzleSecret, userChallengeCookie string) (row int, col int, err error) {
	valid_X_Moves := []int{1, -1, 0, 0}
	valid_Y_Moves := []int{0, 0, 1, -1}
	var possible_valid_moves [][2]int

	for i := 0; i < 4; i++ {
		potential_x := rowNil + valid_X_Moves[i]
		potential_y := colNil + valid_Y_Moves[i]

		if 0 <= potential_x && potential_x < len(boardRef) && 0 <= potential_y && potential_y < len(boardRef[0]) && !(lastRow == potential_x && lastCol == potential_y) {
			possible_valid_moves = append(possible_valid_moves, [2]int{potential_x, potential_y})
		}
	}

	if len(possible_valid_moves) == 0 {
		err = errors.New("ErrFailedExpectation: Expected at least one valid move, got none")
		return
	}

	/*
		It is really important that we derive the randomness from a deterministic source (the users challenge cookie)
		this way when it comes to validating, we can reconstruct their map as desired
	*/
	randomChoice := PuzzleEntropyFromRange(puzzleSecret, userChallengeCookie, 0, len(possible_valid_moves))

	next_valid_move := possible_valid_moves[randomChoice]

	row = next_valid_move[0]
	col = next_valid_move[1]

	return
}

func SwapPuzzleTile[T PuzzleTileIdentifier](boardRef [][]*T, rowNil, colNil, row2, col2 int) {
	nilValue := boardRef[rowNil][colNil]
	boardRef[rowNil][colNil] = boardRef[row2][col2]
	boardRef[row2][col2] = nilValue
}

/*returns "not identical" (ie false) if theres at least one difference between the two boards*/
func IsPuzzleBoardIdentical[T PuzzleTileIdentifier](boardRef, copyOfBoard [][]*T) bool {
	for row := 0; row < len(boardRef); row++ {
		for col := 0; col < len(boardRef[row]); col++ {
			if (boardRef[row][col] == nil) != (copyOfBoard[row][col] == nil) { // Nil mismatch check
				return false
			}
			/*goes does not automatically deref it because its an interface method*/
			if boardRef[row][col] != nil && copyOfBoard[row][col] != nil && (*boardRef[row][col]).GetTileGridID() != (*copyOfBoard[row][col]).GetTileGridID() {
				return false
			}
		}
	}
	return true
}

func RemovePuzzleTileFromBoard[T PuzzleTileIdentifier](boardRef [][]*T, targetDifficulty PuzzleDifficultyProfile) error {
	row, col := PuzzleTileIndexToRowCol(targetDifficulty.RemoveTileIndex, targetDifficulty.NPartitions)
	boardRef[row][col] = nil //JSON will serialize this as `null`
	return nil
}

/*
converts a specific index of a perfect square number of partitions into a (row, col)
is required due to the possibility of a 'random' RemoveTileIndex being supplied, requiring the ability
to recalculate a (row, col) pair for any given difficulty profile
*/
func PuzzleTileIndexToRowCol(index, nPartitions int) (row int, col int) {
	square := int(math.Sqrt(float64(nPartitions)))
	row = index / square
	col = index % square
	return
}
