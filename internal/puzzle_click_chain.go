package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

/*
It is important to ensure that the ChainTile and ClickChainEntry match the client side definition with respect order when serializing. If their orders
do not match, then even if the data is correct, the resultant hash will not be the same.
*/

type ClickChainTile struct {
	Row int    `json:"row"`
	Col int    `json:"col"`
	Id  string `json:"id"`
}

func (ct *ClickChainTile) MarshalBinary() ([]byte, error) {
	return json.Marshal(ct)
}

func (ct *ClickChainTile) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, ct)
}

type ClickChainEntry struct {
	TimeStamp       string         `json:"time_stamp"`
	TileClicked     ClickChainTile `json:"tile_clicked"`
	TileSwappedWith ClickChainTile `json:"tile_swapped_with"`

	ClickCount int    `json:"click_count"`
	Hash       string `json:"hash"`
}

func (chainEntry *ClickChainEntry) MarshalBinary() ([]byte, error) {
	return json.Marshal(chainEntry)
}

func (chainEntry *ClickChainEntry) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, chainEntry)
}

func (chainEntry *ClickChainEntry) JSONBytesToString(data []byte) string {
	return string(data)
}

var (
	ErrFailedClickChainIntegrityCheck                 = errors.New("failed click chain integrity check")
	ErrFailedClickChainMoveIntegrityCheck             = errors.New("failed click chain moves sequence validation")
	ErrFailedClickChainMoveToBoardStateIntegrityCheck = errors.New("failed to recreate successfully solved puzzle using users submitted steps")
	ErrClickChainEmpty                                = errors.New("click chain empty, expected at least genesis + 1 valid operation to solve")
	ErrGenesisFailedMarshalBinary                     = errors.New("failed to marshal genesis click chain item")
	ErrFailedClickChainItemMarshalBinary              = errors.New("failed to marshal click chain item")
	ErrGenesisEntryVerification                       = errors.New("failed genesis click chain verification")
	ErrChainVerification                              = errors.New("failed click chain verification")
)

/*
NewClickChain is used to create a ClickChain which is a mini blockchain of clicks (clickChainEntries) that a user makes as they try to solve the captcha
where each block references the previous and we create the genesis with a secret initialization vector the user doesn't have access to
*/
func NewPuzzleClickChain(userChallengeCookieString, clickChainEntroy string) ([]ClickChainEntry, error) {

	clickChain := make([]ClickChainEntry, 0)

	genesis := ClickChainEntry{
		TimeStamp:       time.Now().UTC().Format(time.RFC3339),
		ClickCount:      0,
		TileClicked:     ClickChainTile{Id: "", Row: -1, Col: -1},
		TileSwappedWith: ClickChainTile{Id: "", Row: -1, Col: -1},
		Hash:            "",
	}

	genesisChainEntryAsBytes, err := genesis.MarshalBinary()
	if err != nil {
		return nil, err
	}

	challengeEntroy := fmt.Sprintf("%s%s", clickChainEntroy, userChallengeCookieString)
	genesis.Hash = GenerateHMACFromString(genesis.JSONBytesToString(genesisChainEntryAsBytes), challengeEntroy)
	clickChain = append(clickChain, genesis)

	return clickChain, nil
}

/*
IntegrityCheckClickChain checks the integrity of the click chain starting from the genesis entry until the last move to make sure that the click chain
is not a replay of a past chain that happens to match the same initial configuration of the board. Then we check that the operations of the click chain
follow the rulles and that the click start operations actually lead to the submitted board.

We start by verifying that the entire chain is valid. This ensures the entire chain is unaltered before trusting timestamps, counts, or moves.
We then check that each of the moves of the click chain are valid as by the rules of the game
finally, we recreate their submitted board using the steps they took to see that it does result in the outcome board proving that this chain of clicks did indeed create the resultant board.

NOTE: This does NOT prove their answer was right. ONLY that given the initial board they started with it was THIS series of steps in particular that got them to the final result they submitted.
*/
func IntegrityCheckPuzzleClickChain(

	userSubmittedSolutionHash, userChallengeCookieString, clickChainEntroy string,
	userSubmittedClickChain []ClickChainEntry,
	locallyStoredShuffledGameBoard [][]*PuzzleTileWithoutImage,
	locallyStoredUnShuffledGamboard [][]*PuzzleTileWithoutImage,

) error {

	err := verifyPuzzleClickChainIntegrity(userChallengeCookieString, clickChainEntroy, userSubmittedClickChain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedClickChainIntegrityCheck, err)
	}

	err = verifyPuzzleClickChainMoveValidity(userSubmittedClickChain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedClickChainMoveIntegrityCheck, err)
	}

	err = recreateAndIntegrityCheckFinalPuzzleBoardFromClickChain(userSubmittedClickChain, locallyStoredShuffledGameBoard, locallyStoredUnShuffledGamboard, userSubmittedSolutionHash, userChallengeCookieString)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedClickChainMoveToBoardStateIntegrityCheck, err)
	}

	return nil
}

/*
verifyClickChainIntegrity verifies the integrity of the entire payload itself by recreating each hash ourselves using what we expect and the secret info required to make the genesis entry.
This requires iterating over their map, taking the data they presented in the time, tile_clicked and tile_swapped
fields putting them into a new entry, setting the current count ourselves and setting the current hash ourselves by taking the previous
items hash as the initial hash field value of the current object, producing the hash of that object and storing that item to be the hash and then hashing that object
to produce the hash of that object in particular.
*/
func verifyPuzzleClickChainIntegrity(

	userChallengeCookieString, clickChainEntroy string,
	userClickChain []ClickChainEntry,

) error {

	copiedClickChain := make([]ClickChainEntry, len(userClickChain))
	copy(copiedClickChain, userClickChain)

	if len(copiedClickChain) == 0 {
		return fmt.Errorf("%w: No entries in click chain", ErrClickChainEmpty)
	}

	if len(copiedClickChain) == 1 {
		return fmt.Errorf("%w: Only the genesis is in the click chain, solution cannot be valid", ErrClickChainEmpty)
	}

	isValidGenesisHash, err := verifyPuzzleClickChainGenesisHash(userChallengeCookieString, clickChainEntroy, copiedClickChain[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGenesisFailedMarshalBinary, err)
	}

	if !isValidGenesisHash {
		return fmt.Errorf("%w: Invalid genesis block", ErrGenesisEntryVerification)
	}

	previousHash := copiedClickChain[0].Hash

	//at this point we know that the genesis entry is valid, so we can continue to verify every other entry is valid using "i" as the click count
	//starting at 1 since that would have been the first click
	for i := 1; i < len(copiedClickChain); i++ {
		expectedHash, err := verifyPuzzleClickChainEntry(userChallengeCookieString, i, previousHash, copiedClickChain[i])
		if err != nil {
			return fmt.Errorf("%w: Entry %d, expected hash: %s, got: %s", ErrChainVerification, i, expectedHash, copiedClickChain[i].Hash)
		}
		previousHash = copiedClickChain[i].Hash
	}

	return nil
}

/*
since the user does not know our initialization vector, they are not able to forge their own genesis. Note, this is different
from the direct match comparison as it is meant to also tie the user challenge cookie string and confirm the first hash in the
entire click chain which is necessary for being able to confirm all subsequent hashes
*/
func verifyPuzzleClickChainGenesisHash(

	userChallengeCookieString, clickChainEntroy string,
	userGenesisEntry ClickChainEntry,

) (bool, error) {

	submittedHash := userGenesisEntry.Hash
	userGenesisEntry.Hash = "" //in order to recreate how the genesis entry was created

	challengeEntropy := fmt.Sprintf("%s%s", clickChainEntroy, userChallengeCookieString)

	genesisBytes, err := userGenesisEntry.MarshalBinary()
	if err != nil {
		return false, err
	}

	expectedHash := GenerateHMACFromString(userGenesisEntry.JSONBytesToString(genesisBytes), challengeEntropy)
	userGenesisEntry.Hash = submittedHash //reset to be able to use it for verifying the next

	return expectedHash == submittedHash, nil
}

/*
we remove the hash and index user provided for this entry, and replace them with the previous entry hash and expected index respectively
we produce the hash of this entry and compare it to what they actually had to confirm it was indeed correct
*/
func verifyPuzzleClickChainEntry(

	userChallengeCookieString string,
	expectedIndex int,
	previousHash string,
	userSubmittedChainEntry ClickChainEntry,

) (string, error) {

	recreatedEntry := ClickChainEntry{
		TimeStamp:       userSubmittedChainEntry.TimeStamp,
		TileClicked:     userSubmittedChainEntry.TileClicked,
		TileSwappedWith: userSubmittedChainEntry.TileSwappedWith,
		ClickCount:      expectedIndex,
		Hash:            previousHash,
	}

	asBytes, err := recreatedEntry.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFailedClickChainItemMarshalBinary, err)
	}

	marshaledBytesAsString := recreatedEntry.JSONBytesToString(asBytes)
	expectedHash := GenerateHMACFromString(marshaledBytesAsString, userChallengeCookieString)

	if expectedHash != userSubmittedChainEntry.Hash {
		return expectedHash, fmt.Errorf("%w: %v", ErrChainVerification, errors.New("hash mismatch"))
	}

	return expectedHash, nil
}

func verifyPuzzleClickChainMoveValidity(userClickChainWithGenesis []ClickChainEntry) error {

	if len(userClickChainWithGenesis) == 0 {
		return fmt.Errorf("%w: %v", ErrChainVerification, errors.New("ErrInvalidClickChain: Missing genesis"))
	}

	//since we integrity checked the userClickChainWithGenesis, we start by removing the genesis entry as its not one of the users entries
	copiedClickChain := make([]ClickChainEntry, len(userClickChainWithGenesis))
	copy(copiedClickChain, userClickChainWithGenesis)

	userClickChain := copiedClickChain[1:]

	if len(userClickChain) == 0 {
		return fmt.Errorf("%w: %v", ErrChainVerification, errors.New("ErrInvalidClickChain: Expected at least one move for a valid answer, puzzles are not issued already solved"))
	}

	for userMove := 0; userMove < len(userClickChain); userMove++ {
		currentTileThatWasClicked := userClickChain[userMove].TileClicked
		tileSwappedWith := userClickChain[userMove].TileSwappedWith
		if tileSwappedWith.Id != "null_tile" {
			return fmt.Errorf("%w: ErrInvalidMove: Detected impossible swap: swapping tile clicked: %s with tile:%s", ErrChainVerification, currentTileThatWasClicked.Id, tileSwappedWith.Id)
		}

		if !isValidPuzzleMove(currentTileThatWasClicked, tileSwappedWith) {
			return fmt.Errorf("%w: ErrInvalidMove: Swap should not have been possible: tile clicked: %s with tile:%s", ErrChainVerification, currentTileThatWasClicked.Id, tileSwappedWith.Id)
		}
	}

	return nil
}

func isValidPuzzleMove(tileClicked, tileSwappedWith ClickChainTile) bool {

	validMoves_X := []int{1, -1, 0, 0}
	validMoves_Y := []int{0, 0, 1, -1}

	var isValidMove = false

	for i := 0; i < 4; i++ {
		potential_X := validMoves_X[i] + tileClicked.Row
		potential_Y := validMoves_Y[i] + tileClicked.Col

		if potential_X == tileSwappedWith.Row && potential_Y == tileSwappedWith.Col {
			//this was a valid move as there exists a possible way to swap the tile that was clicked for the null tile
			isValidMove = true
			break
		}
	}

	return isValidMove
}

/*
this will check that the solution they submitted was derived from the set of operations they performed on the gameboard we provided
them by playing back the operations on the gameboard we saved locally and seeing that it results in the state which produces the hash they would get if they applied
the operations they claim to have used via the click chain on the board we gave them. This ONLY proves that the steps they applied to the board result in the hash
they submitted. It does NOT prove that the hash they submitted is correct.
*/
func recreateAndIntegrityCheckFinalPuzzleBoardFromClickChain(

	userClickChainWithGenesis []ClickChainEntry,
	locallyStoredShuffledGameBoard, locallyStored_Un_ShuffledGamboard [][]*PuzzleTileWithoutImage,
	userSubmittedSolutionHash, userChallengeCookieString string,

) error {

	if len(locallyStoredShuffledGameBoard) == 0 {
		return errors.New("ErrInvalidGameboard: Local gameboard empty")
	}

	if len(userClickChainWithGenesis) == 0 {
		return errors.New("ErrInvalidClickChain: Missing genesis")
	}

	copiedClickChain := make([]ClickChainEntry, len(userClickChainWithGenesis))
	copy(copiedClickChain, userClickChainWithGenesis)

	userClickChain := copiedClickChain[1:]

	if len(userClickChain) == 0 {
		return errors.New("ErrInvalidClickChain: Expected at least one move for a valid answer, puzzles are not issued already solved")
	}

	//since we removed the genesis, the indexes of the clicks are off by 1 as genesis gets index 0,
	//so users first click is always 1. so i+1 will be userClickChain.ClickCount
	for i := 0; i < len(userClickChain); i++ {
		userMove := userClickChain[i]
		expectedClickChainIndex := i + 1
		if userMove.ClickCount != expectedClickChainIndex {
			return fmt.Errorf("ErrInconsistentIndex: Expected click count %d but got: %d", expectedClickChainIndex, userMove.ClickCount)
		}

		currentTileThatWasClicked := userMove.TileClicked
		tileSwappedWith := userMove.TileSwappedWith

		clickedItemOnOriginalMap := locallyStoredShuffledGameBoard[currentTileThatWasClicked.Row][currentTileThatWasClicked.Col]
		if clickedItemOnOriginalMap == nil {
			return fmt.Errorf("ErrTileNotFound: Tile at row:%d col:%d could not be found in the server-side gameboard", currentTileThatWasClicked.Row, currentTileThatWasClicked.Col)
		}

		if clickedItemOnOriginalMap.TileGridID != currentTileThatWasClicked.Id {
			return fmt.Errorf("ErrTileIDMismatch: Expected tile ID: %s, but got: %s at row:%d col:%d", clickedItemOnOriginalMap.TileGridID, currentTileThatWasClicked.Id, currentTileThatWasClicked.Row, currentTileThatWasClicked.Col)
		}

		swappedItemOnOriginalMap := locallyStoredShuffledGameBoard[tileSwappedWith.Row][tileSwappedWith.Col]
		if tileSwappedWith.Id != "null_tile" || swappedItemOnOriginalMap != nil {
			return fmt.Errorf("ErrInvalidNullTileSwap: Attempted swap with non-null tile at row:%d col:%d. Expected null tile with id: 'null_tile'", tileSwappedWith.Row, tileSwappedWith.Col)
		}

		SwapPuzzleTile(locallyStoredShuffledGameBoard, currentTileThatWasClicked.Row, currentTileThatWasClicked.Col, tileSwappedWith.Row, tileSwappedWith.Col)
	}

	/*
		here we are recreating the solution that the user found. We start with the shuffled gameboard that we stored locally. We playback the users steps (from their click chain)
		we check that the final solution that THEY submitted to us MATCHES what they WOULD have calculated GIVEN the click chain they submitted.

		NOTE this is NOT the same thing as checking their answer. All this does is check that the solution they submitted was actually derived from the click
		chain steps they submitted. Their solution MAY STILL be wrong, HOWEVER at this stage we know for a fact that they started with the board we gave them, they applied the steps
		and got their solution as a result of these steps. This is why we still need to compare their submitted solution to the precomputed solution we saved locally
	*/
	expectedSolutionDerivedFromGrid := CalculateExpectedPuzzleSolution(locallyStoredShuffledGameBoard, userChallengeCookieString)

	if expectedSolutionDerivedFromGrid != userSubmittedSolutionHash {
		return errors.New("ErrTamperedSolution: Users submitted solution hash was NOT derived from this game board")
	}

	/*
		since we are now confident that the users steps match the board they submitted, we apply a comparison to the UN-shuffled version (ie the FINAL solution) board, to confirm that these match ID by ID
		if so, what remains is integrity checking properties (ie completed within the time and clicks allowed) and subsequently confirming that the hash is a match. This is the first confirmation that the
		board ITSELF was in a correct state when submitted because we applied the steps the user took to the shuffled board and ended up at the unshuffled board (as deired)

		now we need only iteratively check that the submitted board and the original board match id for id in the SAME order
		we already confirmed the size of the game boards are the same, so the dimensions we use are guarenteed to work for both
	*/
	nRows := len(locallyStoredShuffledGameBoard)
	nCols := len(locallyStoredShuffledGameBoard[0])

	for r := 0; r < nRows; r++ {
		for c := 0; c < nCols; c++ {
			userEntry := locallyStored_Un_ShuffledGamboard[r][c]
			localEntry := locallyStoredShuffledGameBoard[r][c]

			//either they're both nil (ie they're the same so great) or they both not nil otherwise, they're necessarily different, so return error

			if localEntry == nil && userEntry != nil {
				return fmt.Errorf("ErrNullTilePositionMismatch: Null tile position mismatch at (%d,%d). Expected null, but got: %s", r, c, userEntry.TileGridID)
			}

			if localEntry != nil && userEntry == nil {
				return fmt.Errorf("ErrFinalBoardMismatch: Expected tile ID %s at (%d,%d) but received null", localEntry.TileGridID, r, c)
			}

			if localEntry != nil && userEntry != nil && localEntry.TileGridID != userEntry.TileGridID {
				return fmt.Errorf("ErrFinalBoardMismatch: Expected tile ID %s at (%d,%d) but received %s", localEntry.TileGridID, r, c, userEntry.TileGridID)
			}
		}
	}

	return nil
}
