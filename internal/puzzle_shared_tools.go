package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func LoadDefaultPuzzleImageBase64() string {
	relativePath := "internal/static/images/default_baskerville_logo.png"
	absolutePath, err := getAbsolutePath(relativePath)
	if err != nil {
		log.Fatalf("Failed to create absolute path: %v", err)
	}

	imageData, err := os.ReadFile(absolutePath)
	if err != nil {
		log.Fatal("Error loading default image:", err)
	}
	return base64.StdEncoding.EncodeToString(imageData)
}

func getAbsolutePath(relativePath string) (string, error) {
	basePath, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	return filepath.Join(basePath, relativePath), nil
}

/*
GenerateHMACFromString is used across the generator & verifier because it matches the behaviour
of the client side (written in typescript). If we use go idiomatic function signatures for this,
it can result in hashing being incosistent and since the validation strategy relies on verifying a blockchain
it is really important to consistently use this function in particular when generating hashes
*/
func GenerateHMACFromString(message string, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))              //msg is a string, converted to bytes
	return hex.EncodeToString(h.Sum(nil)) //ensures no padding
}

/*
EntropyFromRange is used to generate entropy anytime we need a soure of randomness across any of the
CAPTCHA puzzle components.

WARNING: It is really important that we derive the randomness from a deterministic source (the users challenge cookie)
since validation requires recreating parts of the initial challenge we issued. In order to guarentee this type of
deterministic psuedo reandomness by taking, as arugment, key properties such as:

  - `entropyInitalizationVector` (like a `puzzleSecret`)
    Where `puzzleSecret` is a secret only we know that allows us to ensure no one can cheat/forge/replay

  - `entropyContext` (like a `userChallengeCookieString`)
    Where `userChallengeCookieString` allows generating a different challenge for each user, wrt tileRemoved, noise, etc

and use them AS the source of entropy enabling generation of pseudo-random numbers for verifiying solutions
by recreating the initial challenge we issued at runtime. Anytime the same info is passed in, it will generate
the same "random" sequence.
*/
func PuzzleEntropyFromRange(entropyInitalizationVector, entropyContext string, minValue, maxValue int) int {

	// log.Printf("EntropyFromRange called: minValue:%d, maxValue:%d", minValue, maxValue)

	h := hmac.New(sha256.New, []byte(entropyInitalizationVector))
	h.Write([]byte(entropyContext))
	hash := h.Sum(nil)

	hashInt := new(big.Int).SetBytes(hash)

	//ensure we get a number in the range [minValue, maxValue]
	rangeSize := maxValue - minValue // WARNING: DO NOT add +1, maxValue is already inclusive!

	// if rangeSize <= 0 {
	// 	log.Printf("FATAL: Invalid range detected in EntropyFromRange. minValue: %d, maxValue: %d", minValue, maxValue)
	// }

	return int(new(big.Int).Mod(hashInt, big.NewInt(int64(rangeSize))).Int64()) + minValue
}

/*
same as the function on the client side such that the user can submit their sol to us and we
can compute our expectation of that sol for comparison
*/
func CalculateExpectedPuzzleSolution[T PuzzleTileIdentifier](boardRef [][]*T, userChallengeCookie string) string {

	var boardIDHashesInOrder strings.Builder
	for _, row := range boardRef {
		for _, tile := range row {
			if tile == nil {
				boardIDHashesInOrder.WriteString("null_tile")
			} else {
				boardIDHashesInOrder.WriteString((*tile).GetTileGridID()) //dereferencing needed
			}
		}
	}

	//this is the part of the solution that the user computes on their end
	expectedSolution := GenerateHMACFromString(boardIDHashesInOrder.String(), userChallengeCookie)
	return expectedSolution
}

// func LogPuzzleGameBoard[T TileIdentifier](gameBoard [][]*T) {
// 	log.Println("=== GAMEBOARD ===")
// 	for i, row := range gameBoard {
// 		rowStr := fmt.Sprintf("Row %d: ", i)
// 		for _, tile := range row {
// 			if tile != nil {
// 				rowStr += fmt.Sprintf("[%s...] ", (*tile).GetTileGridID()) // Preview first 20 chars
// 			} else {
// 				rowStr += "[nil] "
// 			}
// 		}
// 		log.Println(rowStr)
// 	}
// }

func ParsePuzzleSolutionCookie(c *gin.Context, cookiesToDelete *[]string) (userSolutionSubmission *ClientPuzzleSolutionSubmissionPayload, err error) {

	defer func() {
		if err != nil {
			// log.Println("stripping solution cookies due to error while parsing solution cookie")
			StripPuzzleSolutionCookieIfExist(c, *cookiesToDelete)
			*cookiesToDelete = make([]string, 0)
		}
	}()

	userSolutionAsB64EncodedCookieString, err := c.Cookie("__banjax_sol")
	if err != nil {
		return nil, err
	}
	*cookiesToDelete = append(*cookiesToDelete, "__banjax_sol")

	cookies := c.Request.Cookies()
	userJSONSerializedClickChain, cookieNames, err := extractPuzzleClickChainFromCookies(cookies)
	//the cookieNames are always guarenteed to return at least empty array
	*cookiesToDelete = append(*cookiesToDelete, cookieNames...)
	if err != nil {
		// log.Println("Unable to verify solution without users click chain cookie(s)")
		return nil, err
	}

	var userSubmittedClickChain []ClickChainEntry
	err = json.Unmarshal(userJSONSerializedClickChain, &userSubmittedClickChain)
	if err != nil {
		// log.Printf("Failed to unmarshal user click chain from cookies due to error: %v", err)
		return nil, err
	}

	userSolutionString, err := base64.StdEncoding.DecodeString(userSolutionAsB64EncodedCookieString)
	if err != nil {
		// log.Printf("Failed to decode user solution string due to error: %v", err)
		return nil, err
	}

	userSolutionSubmission = &ClientPuzzleSolutionSubmissionPayload{
		Solution:   string(userSolutionString),
		ClickChain: userSubmittedClickChain,
	}

	return

}

/*
ExtractClickChainFromCookies parses the cookies available in the requests cookies header
to recreate the click chain bytes. The ClickChain is written into cookies when the user submits
a solution. Because there is a 4096 byte limit per cookie, the click chain itself is initially
encoded into base64, then parsed into segments < 4096 bytes. In order to ensure we can recreate the
solution in order, the cookies are written with metadata that tells us how many to expect:

For example, suppose the click chain needs 3 cookies to be sent, then we will receive cookies with names:
__banjax_cc_1_3, __banjax_cc_2_3, __banjax_cc_3_3

In order to guarentee always being able to receive user solutions, we cap the number of moves required
for any puzzle solution at < 80. This ensures that at most 8 cookies will be attached. In practice, most puzzles are
solvable in < 10 moves so it should only require attaching a single __banjax_cc_1_1 cookie
*/
func extractPuzzleClickChainFromCookies(cookies []*http.Cookie) ([]byte, []string, error) {

	clickChainParts := make(map[int]string)
	cookieNames := make([]string, 0)
	totalParts := 0

	for _, cookie := range cookies {
		//match only __banjax_cc_x_y format since we know that is guarenteed to be there, we just dont know
		//what will come after. If there are 2 then it will be __banjax_cc_1_2, but if only 1 it will be __banjax_cc_1_1
		if strings.HasPrefix(cookie.Name, "__banjax_cc_") {
			//get the indices from the name "__banjax_cc_x_y"
			parts := strings.Split(cookie.Name, "_")
			//which should produce: ['', '', 'banjax', 'cc', '1', '2']
			if len(parts) != 6 {
				log.Printf("skipping malformed click chain cookie: %s", cookie.Name)
				continue
			}

			parts = parts[2:]

			partIndex, err1 := strconv.Atoi(parts[2]) // x (current part)
			total, err2 := strconv.Atoi(parts[3])     // y (total parts)

			if err1 != nil || err2 != nil || partIndex < 1 || total < 1 || partIndex > total {
				continue
			}

			cookieNames = append(cookieNames, cookie.Name)
			clickChainParts[partIndex] = cookie.Value

			//this way we know the highest seen
			if partIndex > totalParts {
				totalParts = partIndex
			}
		}
	}

	if len(clickChainParts) == 0 {
		return nil, cookieNames, fmt.Errorf("no valid click chain cookies found")
	}

	if len(clickChainParts) != totalParts {
		return nil, cookieNames, fmt.Errorf("incomplete click chain cookies")
	}

	var clickChainPartsInOrder []string
	//now we can look for any missing parts explicitly
	for i := 1; i <= totalParts; i++ {
		_, exists := clickChainParts[i]
		if !exists {
			return nil, cookieNames, fmt.Errorf("missing click chain part: %d", i)
		}
		clickChainPartsInOrder = append(clickChainPartsInOrder, clickChainParts[i])
	}

	clickChainBase64 := strings.Join(clickChainPartsInOrder, "")
	clickChainJSON, err := base64.StdEncoding.DecodeString(clickChainBase64)
	if err != nil {
		return nil, cookieNames, fmt.Errorf("failed to decode Base64 click chain: %w", err)
	}

	return clickChainJSON, cookieNames, nil
}

func StripPuzzleSolutionCookieIfExist(c *gin.Context, cookieNamesToDelete []string) {
	for _, name := range cookieNamesToDelete {
		_, err := c.Cookie(name)
		if err == nil {
			c.SetCookie(name, "", -1, "/", "", false, false)
		}
	}
}

/*
ValidatePuzzleCAPTCHACookie is used to validate captcha puzzle cookies. The goal is simiilar to how the ValidateShaInvCookie works in the
context of sendOrValidateShaInvChallenge: We need to distinguish between whether the cookie is is a challenge cookie or a solution cookie.
If it is a solution, we need to check the validity of the solution.

Validity of a solution:

In the puzzle captcha flow, a "challenge cookie" is a the same as the shaChallenge. This is because this cookie format is reliable, admits
integrity checking as well as built in expiry and IP Address / user agent which ties the cookie to a specific user (network). However since
we are not issuing a proof of work challenge, the expected zero bits is hardcoded to 0

The users solution submission has 2 parts:

 1. Click Chain
    As the user is solving the puzzle they are adding to their click chain by using the challenge cookie to calculate hashes starting with the
    reference hash we provided initially when issueing the challenge (the genesis click chain item). This ties their solution to a specific puzzle.

 2. Solution hash
    On click submit, the tile IDs of the users board are concatinated in the order the user positioned them, and they are signed using the
    users challenge cookie

When we receive the submission, we validate the click chain for integrity proving they actually did work to get the solution hash and used the
challenge cookie to perform all of the operations. Then we compare the solution hash to the expected solution by recreating the challenge we
initially issued them and calculate the solution ourselves using their cookie.

If both of these steps were valid, then the user passed the challenge. So, we generate the solution cookie and return it to them. This solution
cookie is comprised of 2 parts: The initial challenge cookie we provided and the solution hash they provided after solving delimited by "[sol]".

ie the solution cookie is:

	base64(original_challenge_cookie[sol]solution_hash_from_submission)

In order to verify that the user did work (ie the proof of work) to earn this cookie, whenever we receive a request, we parse out the original cookie
as well as the solution hash. We first start by validating the original cookie (as mentioned before because it is tied to the IP address, has integrity
checking built it etc). As long as that is valid, we use this challenge cookie to recreate the puzzle we initially issued to the user and recalculate
the expected solution hash. As long as this solution hash matches the only provided, we know that this solution could have only been generated from
this original challenge cookie.

NOTE: It is important to note that by base 64 encoding the entire solution cookie, the original_challenge_cookie (which is already base64) gets encoded again
and as a result, needs to be base64 decoded in order to get it back to the form that would be parsed properly by validateShaInvCookie. This is an essential
part of how we distinguish a refresh request from a request made by a user who has passed as a refresh request will have sent the original challenge cookie,
whereas a user who has the solution cookie will send a cookie not parsable by the validateShaInvCookie until it reaches this function.
*/
func ValidatePuzzleCAPTCHACookie(config *Config, puzzleImageController *PuzzleImageController, cookieString string, nowTime time.Time, clientIp string) error {

	decodedCookieValue, err := base64.StdEncoding.DecodeString(cookieString)
	if err != nil {
		return errors.New("failed to decode CAPTCHA cookie")
	}

	parts := strings.Split(string(decodedCookieValue), "[sol]")

	if len(parts) == 1 {
		//no solution submitted yet, validate only the original challenge portion
		return ValidateShaInvCookie(config.HmacSecret, parts[0], nowTime, clientIp, 0)

	} else if len(parts) == 2 {

		originalCookiePortion := parts[0]
		puzzleSolutionPortion := strings.TrimSpace(parts[1])

		//if no solution portion is provided, treat as missing solution
		if len(puzzleSolutionPortion) == 0 {
			return ValidateShaInvCookie(config.HmacSecret, originalCookiePortion, nowTime, clientIp, 0)
		}

		//validate the original challenge first
		err := ValidateShaInvCookie(config.HmacSecret, originalCookiePortion, nowTime, clientIp, 0)
		if err != nil {
			return err // If the challenge is expired/invalid, we don't care about the solution
		}

		//validate the solution against the original challenge portion
		var expectedSolution string
		_, _, expectedSolution, err = GeneratePuzzleExpectedSolution(config, puzzleImageController, originalCookiePortion)

		if err != nil {
			return fmt.Errorf("ErrRecreatingExpectedSolution: %v", err)
		}

		if expectedSolution == "" {
			return errors.New("failed to calculate existing solution")
		}

		return VerifyPuzzleSolutionHash(puzzleSolutionPortion, expectedSolution)

	} else {
		//malformed cookie (too many `[sol]` delimiters)
		return errors.New("malformed CAPTCHA cookie")
	}
}

type PuzzleErrorLogger struct {
	mu     sync.Mutex
	file   *os.File
	logger *log.Logger
}

func NewPuzzleErrorLogger(logFilePath string) (*PuzzleErrorLogger, error) {
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &PuzzleErrorLogger{
		file:   file,
		logger: log.New(file, "", log.LstdFlags),
	}, nil
}

func (l *PuzzleErrorLogger) WritePuzzleErrorLog(format string, v ...interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logger == nil {
		return fmt.Errorf("ErrLoggerNil")
	}

	_, err := l.logger.Writer().Write([]byte(fmt.Sprintf(format+"\n", v...)))
	return err
}

func (l *PuzzleErrorLogger) Close() error {
	return l.file.Close()
}

/*
Returns the profile associated with "difficulty" key in the yaml
NOTE: You can access the target using configs.PuzzleDifficultyProfiles.Target and use that as the "difficulty" argument

accepts userChallengeCookie as argument such that if the profile specifies a random index,
the source of entropy used is the users challenge cookie
*/
func PuzzleDifficultyProfileByName(config *Config, difficulty string, userChallengeCookie string) (PuzzleDifficultyProfile, bool) {
	// profileConfig.configLock.RLock()
	difficultyProfile, exists := config.PuzzleDifficultyProfiles[difficulty]

	//if dne return early
	if !exists {
		// profileConfig.configLock.RUnlock()
		return PuzzleDifficultyProfile{}, false
	}

	//if we need not make changes, return the valid profile
	if difficultyProfile.RemoveTileIndex != -1 {
		// profileConfig.configLock.RUnlock()
		return difficultyProfile, true
	}

	//if we need to pick a random tile to remove, we need to upgrade locks
	// profileConfig.configLock.RUnlock()
	// profileConfig.configLock.Lock()
	// defer profileConfig.configLock.Unlock()

	if difficultyProfile.RemoveTileIndex == -1 { //check again just in case another thread in the time we upgraded changed it...
		/*
			We use the users challenge cookie so that we can guarentee given the same cookie we can
			produce the exact same result. This is required for validation!

			NOTE on initVector:
				- I would use profileConfig.Target as opposed to "tile_index_noise", but we first need to
				confirm we are going to be selecting difficulty that way and not dynamically otherwise we risk not being able to
				recreate their solution if it changes while the puzzle was being solved by a user
		*/
		initVector := "tile_index_noise"
		difficultyProfile.RemoveTileIndex = PuzzleEntropyFromRange(initVector, userChallengeCookie, 0, difficultyProfile.NPartitions)
	}

	return difficultyProfile, true
}

/*Loads the profiles from the yaml file and stores them in a map for user when the unmarshal is called by config_holder*/
// func (profileConfig *PuzzleDifficultyProfileConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	profileConfig.configLock.Lock()
// 	defer profileConfig.configLock.Unlock()

// 	var loadedConfig struct {
// 		Target   string                             `yaml:"target"`
// 		Profiles map[string]PuzzleDifficultyProfile `yaml:"profiles"`
// 	}

// 	if err := unmarshal(&loadedConfig); err != nil {
// 		return fmt.Errorf("failed to unmarshal difficulty profiles: %w", err)
// 	}

// 	validProfiles := make(map[string]PuzzleDifficultyProfile)
// 	for profileName, difficultyProfile := range loadedConfig.Profiles {
// 		if !profileConfig.isValidProfile(difficultyProfile, profileName) {
// 			continue
// 		}
// 		validProfiles[profileName] = difficultyProfile
// 	}

// 	if len(validProfiles) == 0 {
// 		log.Println("Requires at least one valid profile!")
// 		return errors.New("ErrInvalidDifficultyProfileSettings: Require at least one valid profile")
// 	}

// 	if _, ok := validProfiles[loadedConfig.Target]; !ok {
// 		log.Printf("Target profile '%s' does not exist in valid profiles. Aborting config load.", loadedConfig.Target)
// 		return fmt.Errorf("ErrTargetProfileDoesNotExist: %s", loadedConfig.Target)
// 	}

// 	profileConfig.Profiles = validProfiles
// 	profileConfig.Target = loadedConfig.Target

// 	return nil
// }

/*
checks to see if the properties specified in the profile definitions are valid. In order to avoid
unnecessarily breaking due to a misconfiguration, the function returns boolean. However, this functionality
is tightly coupled with the calling function (UnmarshalYAML) as it will only return an error if none of the
profiles are valid or if the target profile difficulty you are issuing was invalid and therefore not registered
*/
// func (profileConfig *PuzzleDifficultyProfileConfig) isValidProfile(difficultyProfile PuzzleDifficultyProfile, profileName string) bool {
// 	//check to see if profile nPartitions are perfect square
// 	sqrt := math.Sqrt(float64(difficultyProfile.NPartitions))
// 	if sqrt != float64(int(sqrt)) {
// 		log.Printf("Detected invalid nPartition specification. Expected perfect square, %d is not a perfect square. Skipping profile: %s", difficultyProfile.NPartitions, profileName)
// 		return false
// 	}

// 	//check to see if the difficulty is either -1 (meaning randomly choose what tile to remove), or is ∈ [0, nPartitions]
// 	if difficultyProfile.RemoveTileIndex < -1 || difficultyProfile.RemoveTileIndex >= difficultyProfile.NPartitions {
// 		log.Printf("Invalid RemoveTileIndex (%d) for profile %s. Must be in range [0, %d) or -1 (for random selection). Skipping profile.",
// 			difficultyProfile.RemoveTileIndex, profileName, difficultyProfile.NPartitions)
// 		return false
// 	}

// 	/*
// 		- Each click chain entry requires approx 350 bytes
// 		- with a cap of 4096 per cookie, we have 11 click chain entries per cookie
// 		- most browsers allow 50 cookies, but some stricter browsers (mobile in particular) allow only 25 and chrome caps aat 180kb
// 			=> at most 300 clicks before hitting limits of even the stricter browsers.
// 		- To avoid any issues of other domain cookies being evicted as well as latency issues, we set a cap for our puzzles to 100 clicks
// 			as its well within the safe limits of even the strictest browsers

// 		- however in order to avoid needing to allow nginx to accept 4 64k headers, we reduce this to 80 clicks max such we are guarenteed that nginx
// 		can handle it with no issue
// 	*/

// 	if difficultyProfile.MaxNumberOfMovesAllowed > 80 {
// 		log.Printf("Maximum number of clicks for any profile CANNOT exceed 80 due to cookie constraints. Got: %d", difficultyProfile.MaxNumberOfMovesAllowed)
// 		return false
// 	}

// 	//other validations as needed
// 	return true
// }
