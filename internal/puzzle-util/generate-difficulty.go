package puzzleutil

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fsnotify/fsnotify"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

type DifficultyProfile struct {
	NPartitions             int    `yaml:"nPartitions"`
	NShuffles               [2]int `yaml:"nShuffles"`
	MaxNumberOfMovesAllowed int    `yaml:"maxNumberOfMovesAllowed"`
	RemoveTileIndex         int    `yaml:"removeTileIndex"`
	TimeToSolveMs           int    `yaml:"timeToSolve_ms"`
	ShowCountdownTimer      bool   `yaml:"showCountdownTimer"`
}

/*converts the tile index to remove into a (row, col)*/
func (difficultyProfile DifficultyProfile) RemovedTileIndexToRowCol() (row int, col int) {
	square := int(math.Sqrt(float64(difficultyProfile.NPartitions)))
	row = difficultyProfile.RemoveTileIndex / square
	col = difficultyProfile.RemoveTileIndex % square
	return
}

/*converts a specific index into a (row, col) */
func (difficultyProfile DifficultyProfile) TileIndexToRowCol(index int) (row int, col int) {
	square := int(math.Sqrt(float64(difficultyProfile.NPartitions)))
	row = index / square
	col = index % square
	return
}

type DifficultyProfileConfig struct {
	Profiles   map[string]DifficultyProfile `yaml:"profiles"`
	Target     string                       `yaml:"target"`
	configLock sync.RWMutex
}

/*
Returns the profile associated with "target" key in the yaml
*/
func (profileConfig *DifficultyProfileConfig) GetTargetProfile() (DifficultyProfile, bool) {
	profileConfig.configLock.RLock()
	defer profileConfig.configLock.RUnlock()
	difficultyProfile, exists := profileConfig.Profiles[profileConfig.Target]
	if !exists {
		return difficultyProfile, false
	}
	return difficultyProfile, true
}

/*
Returns the difficulty profile by name. Useful if you imlpement a dynamic
means of determining the type of challenge to issue
*/
func (profileConfig *DifficultyProfileConfig) GetProfileByName(difficulty string) (DifficultyProfile, bool) {
	profileConfig.configLock.RLock()
	defer profileConfig.configLock.RUnlock()
	difficultyProfile, exists := profileConfig.Profiles[difficulty]
	if !exists {
		return difficultyProfile, false
	}
	return difficultyProfile, true
}

/*getRandomTileIndex returns a random tile index based on the board size (nPartitions) [0, nPartitions-1]*/
func getRandomTileIndex(nPartitions int) int {
	return rng.Intn(nPartitions)
}

/*
Loads the profiles from the yaml file and stores them in a map for user
Useful if you want to be able to modify the profiles during runtime
*/
func (profileConfig *DifficultyProfileConfig) LoadDifficultyConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var loadedConfig DifficultyProfileConfig
	err = yaml.Unmarshal(data, &loadedConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	profileConfig.configLock.Lock()
	locked := true
	defer func() {
		//incase we exit early while validating the profiles
		if locked {
			profileConfig.configLock.Unlock()
		}
	}()

	validProfiles := make(map[string]DifficultyProfile)
	for profileName, difficultyProfile := range loadedConfig.Profiles {
		if !profileConfig.isValidProfile(difficultyProfile, profileName) {
			continue
		}

		//handle dynamic tile index randomization if RemoveTileIndex == -1
		if difficultyProfile.RemoveTileIndex == -1 {
			difficultyProfile.RemoveTileIndex = getRandomTileIndex(difficultyProfile.NPartitions)
			log.Printf("Profile %s had RemoveTileIndex = -1. Assigned random index: %d", profileName, difficultyProfile.RemoveTileIndex)
		}

		validProfiles[profileName] = difficultyProfile
	}

	if len(validProfiles) == 0 {
		log.Println("Requires at least one valid profile!")
		return errors.New("ErrInvalidDifficultyProfileSettings: Require at least one valid profile")
	}

	if !profileConfig.isValidTarget(validProfiles, loadedConfig.Target) {
		log.Printf("Target profile '%s' does not exist in valid profiles. Aborting config load.", loadedConfig.Target)
		return fmt.Errorf("ErrTargetProfileDoesNotExist: %s", loadedConfig.Target)
	}

	profileConfig.Profiles = validProfiles // Update the current instance
	profileConfig.Target = loadedConfig.Target
	profileConfig.configLock.Unlock()
	locked = false
	log.Println("Config reloaded successfully!")
	return nil
}

func (profileConfig *DifficultyProfileConfig) isValidProfile(difficultyProfile DifficultyProfile, profileName string) bool {
	//check to see if profile nPartitions are perfect square
	sqrt := math.Sqrt(float64(difficultyProfile.NPartitions))
	if sqrt != float64(int(sqrt)) {
		log.Printf("Detected invalid nPartition specification. Expected perfect square, %d is not a perfect square. Skipping profile: %s", difficultyProfile.NPartitions, profileName)
		return false
	}

	if difficultyProfile.RemoveTileIndex < -1 || difficultyProfile.RemoveTileIndex >= difficultyProfile.NPartitions {
		log.Printf("Invalid RemoveTileIndex (%d) for profile %s. Must be in range [0, %d) or -1 (for random selection). Skipping profile.",
			difficultyProfile.RemoveTileIndex, profileName, difficultyProfile.NPartitions)
		return false
	}

	//other validations as needed
	return true
}

func (profileConfig *DifficultyProfileConfig) isValidTarget(validProfiles map[string]DifficultyProfile, profileName string) bool {
	_, ok := validProfiles[profileName]
	return ok
}

/*monitors for changes to configs during runtime and reloads the configs as needed*/
func (profileConfig *DifficultyProfileConfig) WatchConfigFile(ctx context.Context, path string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	err = watcher.Add(path)
	if err != nil {
		log.Fatalf("Failed to add file to watcher: %v", err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file %s modified. Reloading...\n", event.Name)
				err := profileConfig.LoadDifficultyConfig(path)
				if err != nil {
					log.Printf("Error reloading config: %v", err)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)

		case <-ctx.Done():
			log.Println("Stopping config file watcher.")
			return
		}
	}
}
