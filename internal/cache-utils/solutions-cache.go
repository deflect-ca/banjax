package verificationutils

import (
	"sync"
	"time"

	imageUtils "github.com/deflect-ca/banjax/internal/image-utils"
)

type CAPTCHASolution struct {
	UnshuffledGameBoard [][]*imageUtils.TileWithoutImage
	ShuffledGameBoard   [][]*imageUtils.TileWithoutImage
	PrecomputedSolution string
	UserDesiredEndpoint string
}

type CAPTCHASolutionCache struct {
	solutions sync.Map // map[string]CAPTCHASolution
}

/*CAPTCHASolutionCache stores the minimum required data in cache until we get a response, purges on challenge expiry*/
func NewCAPTCHASolutionCache() *CAPTCHASolutionCache {
	cache := &CAPTCHASolutionCache{} // This should NEVER be nil
	return cache
}

func (cache *CAPTCHASolutionCache) Set(userChallengeCookie string, solution CAPTCHASolution, purgeAfterMS *int) {

	cache.solutions.Store(userChallengeCookie, solution)

	// auto delete after `purgeAfterMS` milliseconds + 2 seconds buffer (magic number to account for latency over the wire)
	if purgeAfterMS != nil {
		duration := time.Duration(*purgeAfterMS+2000) * time.Millisecond
		go func() {
			time.Sleep(duration)
			cache.solutions.Delete(userChallengeCookie)
		}()
	}
}

/* returns deep copy of the solution so we can run through the validation making modifications with worry if its wrong, they can try again*/
func (cache *CAPTCHASolutionCache) Get(userChallengeCookie string) (*CAPTCHASolution, bool) {
	value, exists := cache.solutions.Load(userChallengeCookie)
	if !exists {
		return nil, false
	}

	originalSolution, ok := value.(CAPTCHASolution)
	if !ok {
		return nil, false
	}

	captchaSol := &CAPTCHASolution{
		UnshuffledGameBoard: deepCopyBoardWithoutImage(originalSolution.UnshuffledGameBoard),
		ShuffledGameBoard:   deepCopyBoardWithoutImage(originalSolution.ShuffledGameBoard),
		//no deep copy needed (string is primitive and go passes primitives by value)
		PrecomputedSolution: originalSolution.PrecomputedSolution,
		UserDesiredEndpoint: originalSolution.UserDesiredEndpoint,
	}

	return captchaSol, true
}

/*idempotent will not get upset if already deleted*/
func (cache *CAPTCHASolutionCache) Delete(userChallengeCookie string) {
	cache.solutions.Delete(userChallengeCookie)
}

func deepCopyBoardWithoutImage(original [][]*imageUtils.TileWithoutImage) [][]*imageUtils.TileWithoutImage {
	copyBoard := make([][]*imageUtils.TileWithoutImage, len(original))

	for i := range original {
		copyBoard[i] = make([]*imageUtils.TileWithoutImage, len(original[i]))

		for j, tile := range original[i] {
			if tile != nil {
				copyBoard[i][j] = &imageUtils.TileWithoutImage{TileGridID: tile.TileGridID}
			} else {
				copyBoard[i][j] = nil
			}
		}
	}
	return copyBoard
}
