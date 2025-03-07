package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

/*
It is important to ensure that the ChainTile and ClickChainEntry match the client side definition with respect order when serializing. If their orders
do not match, then even if the data is correct, the resultant hash will not be the same.
*/

type ChainTile struct {
	Row int    `json:"row"`
	Col int    `json:"col"`
	Id  string `json:"id"`
}

func (ct *ChainTile) MarshalBinary() ([]byte, error) {
	return json.Marshal(ct)
}

func (ct *ChainTile) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, ct)
}

type ClickChainEntry struct {
	TimeStamp       string    `json:"time_stamp"`
	TileClicked     ChainTile `json:"tile_clicked"`
	TileSwappedWith ChainTile `json:"tile_swapped_with"`

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

/*
ClickChainController is the main click chain tool
it is used to generate a new click chain as well as verify click chains
on solution submission
*/
type ClickChainController struct {
	InitVector string
}

func NewClickChainController(initVector string) *ClickChainController {
	return &ClickChainController{InitVector: initVector}
}

func (cc *ClickChainController) RotateInitVector(newInitVector string) {
	/*
		TODO:
			since there may be challenges already issued with the previous, I suggest we use like a map to track times challenges were issued, then
			from that deduce what vector to use. Then since we know the max puzzle length is 20 minutes, once that time frame expires you can just delete it since no matter what their
			answer is necessarily not valid as by the time constraint
	*/
	cc.InitVector = newInitVector
}

/*
NewClickChain is used to create a ClickChain which is a mini blockchain of clicks (clickChainEntries) that a user makes as they try to solve the captcha
where each block references the previous and we create the genesis with a secret initialization vector the user doesn't have access to
*/
func (cc *ClickChainController) NewClickChain(userChallengeCookieString string) ([]ClickChainEntry, error) {

	clickChain := make([]ClickChainEntry, 0)

	genesis := ClickChainEntry{
		TimeStamp:       time.Now().UTC().Format(time.RFC3339),
		ClickCount:      0,
		TileClicked:     ChainTile{Id: "", Row: -1, Col: -1},
		TileSwappedWith: ChainTile{Id: "", Row: -1, Col: -1},
		Hash:            "",
	}

	genesisChainEntryAsBytes, err := genesis.MarshalBinary()
	if err != nil {
		return nil, err
	}

	challengeEntroy := fmt.Sprintf("%s%s", cc.InitVector, userChallengeCookieString)
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
func (cc *ClickChainController) IntegrityCheckClickChain(

	userSubmittedSolutionHash, userChallengeCookieString string,
	userSubmittedClickChain []ClickChainEntry,
	// userSubmittedGamboard [][]*Tile,
	locallyStoredShuffledGameBoard [][]*TileWithoutImage,
	locallyStoredUnShuffledGamboard [][]*TileWithoutImage,

) error {

	err := cc.verifyClickChainIntegrity(userChallengeCookieString, userSubmittedClickChain)
	if err != nil {
		log.Println("Failed click chain integrity check")
		return fmt.Errorf("ErrFailedClickChainIntegrityCheck: %v", err)
	}

	err = cc.verifyClickChainMoveValidity(userSubmittedClickChain)
	if err != nil {
		log.Println("Failed click chain move integrity check")
		return fmt.Errorf("ErrFailedClickChainMoveIntegrityCheck: %v", err)
	}

	err = cc.recreateAndIntegrityCheckFinalBoardFromClickChain(userSubmittedClickChain, locallyStoredShuffledGameBoard, locallyStoredUnShuffledGamboard, userSubmittedSolutionHash, userChallengeCookieString)
	if err != nil {
		log.Println("Failed click chain move to board state integrity check")
		return fmt.Errorf("ErrFailedClickChainMoveToBoardStateIntegrityCheck: %v", err)
	}

	return nil
}

/*
We compare the genesis block stored locally against the submitted directly in order to confirm that they match. This is done in case
the initVector secret was discovered, the user may forge the rest of the chain. Directly comparing helps mitigate this
*/
func (cc *ClickChainController) IntegrityCheckClickChainGenesis(userSubmittedClickChain []ClickChainEntry, localCopyGenesisClickChainItem ClickChainEntry) error {

	if len(userSubmittedClickChain) == 0 {
		return errors.New("ErrDetectedTampering: Missing genesis click chain item")
	}

	userSubmittedGenesisEntry := userSubmittedClickChain[0]

	if userSubmittedGenesisEntry.Hash != localCopyGenesisClickChainItem.Hash {
		return errors.New("ErrDetectedTampering: Hash does not match local copy")
	}

	if userSubmittedGenesisEntry.TimeStamp != localCopyGenesisClickChainItem.TimeStamp {
		return errors.New("ErrDetectedTampering: TimeStamp does not match local copy")
	}

	if userSubmittedGenesisEntry.ClickCount != localCopyGenesisClickChainItem.ClickCount {
		return errors.New("ErrDetectedTampering: ClickCount does not match local copy")
	}

	if userSubmittedGenesisEntry.TileClicked.Col != localCopyGenesisClickChainItem.TileClicked.Col {
		return errors.New("ErrDetectedTampering: TileClicked.Col does not match local copy")
	}

	if userSubmittedGenesisEntry.TileClicked.Row != localCopyGenesisClickChainItem.TileClicked.Row {
		return errors.New("ErrDetectedTampering: TileClicked.Row does not match local copy")
	}

	if userSubmittedGenesisEntry.TileClicked.Id != localCopyGenesisClickChainItem.TileClicked.Id {
		return errors.New("ErrDetectedTampering: TileClicked.Id does not match local copy")
	}

	if userSubmittedGenesisEntry.TileSwappedWith.Col != localCopyGenesisClickChainItem.TileSwappedWith.Col {
		return errors.New("ErrDetectedTampering: TileSwappedWith.Col does not match local copy")
	}

	if userSubmittedGenesisEntry.TileSwappedWith.Row != localCopyGenesisClickChainItem.TileSwappedWith.Row {
		return errors.New("ErrDetectedTampering: TileSwappedWith.Row does not match local copy")
	}

	if userSubmittedGenesisEntry.TileSwappedWith.Id != localCopyGenesisClickChainItem.TileSwappedWith.Id {
		return errors.New("ErrDetectedTampering: TileSwappedWith.Id does not match local copy")
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
func (cc *ClickChainController) verifyClickChainIntegrity(userChallengeCookieString string, userClickChain []ClickChainEntry) error {
	copiedClickChain := make([]ClickChainEntry, len(userClickChain))
	copy(copiedClickChain, userClickChain)

	if len(copiedClickChain) == 0 {
		log.Println("ErrClickChainEmpty: No entries in click chain")
		return errors.New("ErrClickChainEmpty: No entries in click chain")
	}

	if len(copiedClickChain) == 1 {
		log.Println("ErrClickChainEmpty: Only the genesis is in the click chain, solution cannot be valid")
		return errors.New("ErrClickChainEmpty: Only the genesis is in the click chain, solution cannot be valid")
	}

	isValidGenesis, err := cc.verifyGenesisHash(userChallengeCookieString, copiedClickChain[0])
	if err != nil {
		log.Printf("ErrGenesisFailedMarshalBinary: %v", err)
		return fmt.Errorf("ErrGenesisFailedMarshalBinary: %v", err)
	}

	if !isValidGenesis {
		log.Println("ErrGenesisEntryVerification: Invalid genesis block")
		return errors.New("ErrGenesisEntryVerification: Invalid genesis block")
	}

	previousHash := copiedClickChain[0].Hash

	//at this point we know that the genesis entry is valid, so we can continue to verify every other entry is valid using "i" as the click count
	//starting at 1 since that would have been the first click
	for i := 1; i < len(copiedClickChain); i++ {
		expectedHash, err := cc.verifyClickChainEntry(userChallengeCookieString, i, previousHash, copiedClickChain[i])
		if err != nil {
			log.Printf("ErrChainVerification: Entry %d, expected hash: %s, got: %s", i, expectedHash, copiedClickChain[i].Hash)
			return fmt.Errorf("ErrChainVerification: Entry %d, expected hash: %s, got: %s", i, expectedHash, copiedClickChain[i].Hash)
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
func (cc *ClickChainController) verifyGenesisHash(userChallengeCookieString string, userGenesisEntry ClickChainEntry) (bool, error) {

	submittedHash := userGenesisEntry.Hash
	userGenesisEntry.Hash = "" //in order to recreate how the genesis entry was created

	challengeEntropy := fmt.Sprintf("%s%s", cc.InitVector, userChallengeCookieString)

	genesisBytes, err := userGenesisEntry.MarshalBinary()
	if err != nil {
		return false, err
	}

	expectedHash := GenerateHMACFromString(userGenesisEntry.JSONBytesToString(genesisBytes), challengeEntropy)
	userGenesisEntry.Hash = submittedHash //reset to be able to use it for verifying the next

	return expectedHash == submittedHash, nil
}

// we remove the hash and index user provided for this entry, and replace them with the previous entry hash and expected index respectively
// we produce the hash of this entry and compare it to what they actually had to confirm it was indeed correct
func (cc *ClickChainController) verifyClickChainEntry(userChallengeCookieString string, expectedIndex int, previousHash string, userSubmittedChainEntry ClickChainEntry) (string, error) {

	recreatedEntry := ClickChainEntry{
		TimeStamp:       userSubmittedChainEntry.TimeStamp,
		TileClicked:     userSubmittedChainEntry.TileClicked,
		TileSwappedWith: userSubmittedChainEntry.TileSwappedWith,
		ClickCount:      expectedIndex,
		Hash:            previousHash,
	}

	asBytes, err := recreatedEntry.MarshalBinary()
	if err != nil {
		log.Printf("ErrFailedMarshalBinary: %v", err)
		return "", fmt.Errorf("ErrFailedMarshalBinary: %v", err)
	}

	marshaledBytesAsString := recreatedEntry.JSONBytesToString(asBytes)
	expectedHash := GenerateHMACFromString(marshaledBytesAsString, userChallengeCookieString)

	if expectedHash != userSubmittedChainEntry.Hash {
		log.Println("expected hash versus submitted hash mismatch!")
		return expectedHash, errors.New("hash mismatch")
	}

	return expectedHash, nil
}

func (cc *ClickChainController) verifyClickChainMoveValidity(userClickChainWithGenesis []ClickChainEntry) error {

	if len(userClickChainWithGenesis) == 0 {
		log.Println("ErrInvalidClickChain: Missing genesis")
		return errors.New("ErrInvalidClickChain: Missing genesis")
	}

	//since we integrity checked the userClickChainWithGenesis, we start by removing the genesis entry as its not one of the users entries
	copiedClickChain := make([]ClickChainEntry, len(userClickChainWithGenesis))
	copy(copiedClickChain, userClickChainWithGenesis)

	userClickChain := copiedClickChain[1:]

	if len(userClickChain) == 0 {
		log.Println("ErrInvalidClickChain: Expected at least one move for a valid answer, puzzles are not issued already solved")
		return errors.New("ErrInvalidClickChain: Expected at least one move for a valid answer, puzzles are not issued already solved")
	}

	for userMove := 0; userMove < len(userClickChain); userMove++ {
		currentTileThatWasClicked := userClickChain[userMove].TileClicked
		tileSwappedWith := userClickChain[userMove].TileSwappedWith
		if tileSwappedWith.Id != "null_tile" {
			log.Printf("ErrInvalidMove: Detected impossible swap: swapping tile clicked: %s with tile:%s", currentTileThatWasClicked.Id, tileSwappedWith.Id)
			return fmt.Errorf("ErrInvalidMove: Detected impossible swap: swapping tile clicked: %s with tile:%s", currentTileThatWasClicked.Id, tileSwappedWith.Id)
		}

		if !cc.isValidMove(currentTileThatWasClicked, tileSwappedWith) {
			log.Printf("ErrInvalidMove: Swap should not have been possible: tile clicked: %s with tile:%s", currentTileThatWasClicked.Id, tileSwappedWith.Id)
			return fmt.Errorf("ErrInvalidMove: Swap should not have been possible: tile clicked: %s with tile:%s", currentTileThatWasClicked.Id, tileSwappedWith.Id)
		}
	}

	return nil
}

func (cc *ClickChainController) isValidMove(tileClicked, tileSwappedWith ChainTile) bool {

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

// this will check that the solution they submitted was derived from the set of operations they performed on the gameboard we provided them by playing back the operations on the gameboard we saved locally and seeing that it results
// in the state which produces the hash they would get if they applied the operations they claim to have used via the click chain on the board we gave them. This ONLY proves that the steps they applied to the board result in the hash
// they submitted. It does NOT prove that the hash they submitted is correct. For this we juxtapose the precomputed solution to the one they submitted. This happens later in the validation procedure.
func (cc *ClickChainController) recreateAndIntegrityCheckFinalBoardFromClickChain(userClickChainWithGenesis []ClickChainEntry, locallyStoredShuffledGameBoard, locallyStored_Un_ShuffledGamboard [][]*TileWithoutImage, userSubmittedSolutionHash, userChallengeCookieString string) error {

	if len(locallyStoredShuffledGameBoard) == 0 {
		log.Printf("ErrInvalidGameboard: Local gameboard empty")
		return errors.New("ErrInvalidGameboard: Local gameboard empty")
	}

	if len(userClickChainWithGenesis) == 0 {
		log.Println("ErrInvalidClickChain: Missing genesis")
		return errors.New("ErrInvalidClickChain: Missing genesis")
	}

	copiedClickChain := make([]ClickChainEntry, len(userClickChainWithGenesis))
	copy(copiedClickChain, userClickChainWithGenesis)

	userClickChain := copiedClickChain[1:]

	if len(userClickChain) == 0 {
		log.Println("ErrInvalidClickChain: Expected at least one move for a valid answer, puzzles are not issued already solved")
		return errors.New("ErrInvalidClickChain: Expected at least one move for a valid answer, puzzles are not issued already solved")
	}

	//since we removed the genesis, the indexes of the clicks are off by 1 as genesis gets index 0, so users first click is always 1. so i+1 will be userClickChain.ClickCount
	for i := 0; i < len(userClickChain); i++ {
		userMove := userClickChain[i]
		expectedClickChainIndex := i + 1
		if userMove.ClickCount != expectedClickChainIndex {
			log.Printf("ErrInconsistentIndex: Expected click count %d but got: %d", expectedClickChainIndex, userMove.ClickCount)
			return fmt.Errorf("ErrInconsistentIndex: Expected click count %d but got: %d", expectedClickChainIndex, userMove.ClickCount)
		}

		currentTileThatWasClicked := userMove.TileClicked
		tileSwappedWith := userMove.TileSwappedWith

		//the locally stored shuffled game board is the gameboard they initially received, so playing back their steps means
		//that its not possible for anything they ever clicked on to have been the null tile
		clickedItemOnOriginalMap := locallyStoredShuffledGameBoard[currentTileThatWasClicked.Row][currentTileThatWasClicked.Col]
		//how would we guard against row/col not being in the array?
		if clickedItemOnOriginalMap == nil {
			log.Printf("ErrTileNotFound: Tile at row:%d col:%d could not be found in the server-side gameboard", currentTileThatWasClicked.Row, currentTileThatWasClicked.Col)
			return fmt.Errorf("ErrTileNotFound: Tile at row:%d col:%d could not be found in the server-side gameboard", currentTileThatWasClicked.Row, currentTileThatWasClicked.Col)
		}

		//this is the KEY check confirming the ID of the tile clicked as we follow the users clicks on the map we initially sent them
		if clickedItemOnOriginalMap.TileGridID != currentTileThatWasClicked.Id {
			log.Printf("ErrTileIDMismatch: Expected tile ID: %s, but got: %s at row:%d col:%d", clickedItemOnOriginalMap.TileGridID, currentTileThatWasClicked.Id, currentTileThatWasClicked.Row, currentTileThatWasClicked.Col)
			return fmt.Errorf("ErrTileIDMismatch: Expected tile ID: %s, but got: %s at row:%d col:%d", clickedItemOnOriginalMap.TileGridID, currentTileThatWasClicked.Id, currentTileThatWasClicked.Row, currentTileThatWasClicked.Col)
		}

		swappedItemOnOriginalMap := locallyStoredShuffledGameBoard[tileSwappedWith.Row][tileSwappedWith.Col]
		//how would we guard against row/col not being in the array?
		if tileSwappedWith.Id != "null_tile" || swappedItemOnOriginalMap != nil {
			log.Printf("ErrInvalidNullTileSwap: Attempted swap with non-null tile at row:%d col:%d. Expected null tile with id: 'null_tile'", tileSwappedWith.Row, tileSwappedWith.Col)
			return fmt.Errorf("ErrInvalidNullTileSwap: Attempted swap with non-null tile at row:%d col:%d. Expected null tile with id: 'null_tile'", tileSwappedWith.Row, tileSwappedWith.Col)
		}

		cc.swap(locallyStoredShuffledGameBoard, currentTileThatWasClicked.Row, currentTileThatWasClicked.Col, tileSwappedWith.Row, tileSwappedWith.Col)
	}

	var boardIDHashesInOrder strings.Builder
	for _, row := range locallyStoredShuffledGameBoard {
		for _, tile := range row {
			if tile == nil {
				boardIDHashesInOrder.WriteString("null_tile")
			} else {
				boardIDHashesInOrder.WriteString(tile.TileGridID) //since we saved this locally and its coded to this user, the result will match unless the user tried to forge their cookie
			}
		}
	}

	//here we are recreating the solution that the user found. We start with the shuffled gameboard that we stored locally. We playback the users steps (from their click chain)
	//we check that the final solution that THEY submitted to us MATCHES what they WOULD have calculated GIVEN the click chain they submitted.
	//NOTE this is NOT the same thing as checking their answer. All this does is check that the solution they submitted was actually derived from the click
	//chain steps they submitted. Their solution MAY STILL be wrong, HOWEVER at this stage we know for a fact that they started with the board we gave them, they applied the steps
	//and got their solution as a result of these steps. This is why we still need to compare their submitted solution to the precomputed solution we saved locally
	expectedSolutionDerivedFromGrid := GenerateHMACFromString(boardIDHashesInOrder.String(), userChallengeCookieString)

	if expectedSolutionDerivedFromGrid != userSubmittedSolutionHash {
		log.Println("ErrTamperedSolution: Users submitted solution hash was NOT derived from this game board")
		return errors.New("ErrTamperedSolution: Users submitted solution hash was NOT derived from this game board")
	}

	//since we are now confident that the users steps match the board they submitted, we apply a comparison to the UN-shuffled version (ie the FINAL solution) board, to confirm that these match ID by ID
	//if so, what remains is integrity checking properties (ie completed within the time and clicks allowed) and subsequently confirming that the hash is a match. This is the first confirmation that the
	//board ITSELF was in a correct state when submitted because we applied the steps the user took to the shuffled board and ended up at the unshuffled board (as deired)

	//now we need only iteratively check that the submitted board and the original board match id for id in the SAME order
	//we already confirmed the size of the game boards are the same, so the dimensions we use are guarenteed to work for both
	nRows := len(locallyStoredShuffledGameBoard)
	nCols := len(locallyStoredShuffledGameBoard[0])

	for r := 0; r < nRows; r++ {
		for c := 0; c < nCols; c++ {
			userEntry := locallyStored_Un_ShuffledGamboard[r][c]
			localEntry := locallyStoredShuffledGameBoard[r][c]

			//either they're both nil (ie they're the same so great) or they both not nil (so they must have the same id and if so great)
			//otherwise, they're necessarily different, so return error

			if localEntry == nil && userEntry != nil {
				log.Printf("ErrNullTilePositionMismatch: Null tile position mismatch at (%d,%d). Expected null, but got: %s", r, c, userEntry.TileGridID)
				return fmt.Errorf("ErrNullTilePositionMismatch: Null tile position mismatch at (%d,%d). Expected null, but got: %s", r, c, userEntry.TileGridID)
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

func (cc *ClickChainController) swap(locallyStoredShuffledGameBoard [][]*TileWithoutImage, currentTileThatWasClickedRow, currentTileThatWasClickedCol, tileSwappedWithRow, tileSwappedWithCol int) {
	temp := locallyStoredShuffledGameBoard[currentTileThatWasClickedRow][currentTileThatWasClickedCol]
	locallyStoredShuffledGameBoard[currentTileThatWasClickedRow][currentTileThatWasClickedCol] = locallyStoredShuffledGameBoard[tileSwappedWithRow][tileSwappedWithCol]
	locallyStoredShuffledGameBoard[tileSwappedWithRow][tileSwappedWithCol] = temp
}
