package internal

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand"
	"sync"
	"time"

	"golang.org/x/image/draw"
)

var (
	ErrFailedInitImagePartition            = errors.New("failed to partition image during PuzzleImageController initialization")
	ErrFailedInitInvalidNumberOfPartitions = errors.New("PuzzleImageController initialization failed expected nPartitions to be a perfect square")
	ErrUnsupportedPuzzleType               = errors.New("puzzle images can be provided as either TileWithoutImage or Tile")
	ErrFailedEncoding                      = errors.New("failed to encode PNG image.Image to base64")
	ErrFailedDecoding                      = errors.New("failed to decode base64 encoded PNG to image.Image")
)

// TileNoiseMask represents a grid of RGB noise adjustments
type PuzzleTileNoiseMask struct {
	Offsets [][][3]int // [y][x][R, G, B] pixel modifications
}

const NumberOfTileNoiseMasks = 512
const thumbnailSize = 400

type PuzzleTileMetadata struct {
	RGBAImagePtr *image.RGBA
	Hash         string
}

/*to save memory, we store only the tileIDs without the base64 when storing the copy of the original for verification*/
type PuzzleTileWithoutImage struct {
	TileGridID string `json:"tile_grid_id"`
}

type PuzzleTile struct {
	Base64Image string `json:"base64_image"`
	TileGridID  string `json:"tile_grid_id"`
}

/*
for generics on functions that can apply to both TileWithoutImage and Tile types
this is particularly important for functions that are used to recreate the gameboard
when validating a users solution without needing to store state server side
*/
type PuzzleTileIdentifier interface {
	GetTileGridID() string
}

func (t PuzzleTile) GetTileGridID() string {
	return t.TileGridID
}

func (t PuzzleTileWithoutImage) GetTileGridID() string {
	return t.TileGridID
}

type PuzzleTileMap[T PuzzleTileIdentifier] map[int]T

/*
Init
- Load & partition image once	O(N) (one-time)
- Convert tiles to RGBA once	O(N) (one-time)
- Precompute 128 noise masks	O(N^2) (one-time)
- Precompute tile pixel hashes	O(N^2) (one-time)

Runtime
- Lookup stored RGBA tile	O(1)
- Lookup stored tile hash	O(1)
- Select noise mask (HMAC)	O(1)
- Apply precomputed noise	O(1) ***
- Encode Base64 & hash	O(1)

*** technically this is N^2 BUT we are applying the operation to a fixed size tile that is never going to grow -
it does not scale dynamically, its always made up of the same number of pixels. So I argue its constant and the conventional
Big-O N^2 notation is misleading—this is a constant-time operation in practice.

Despite adding noise to the thumbnail so users cannot just partition the thumbnail and recreate the solution
on their own by matching the b64 hashes directly, we could still be vulnerable to replays if the user has seen
"this" image in particular. If they knew the final order and recorded the b64 of the images, they could just
map the b64 of each tile and then look up the IDs. To beat this vector, we now add noise to the tiles themselves.

HOWEVER, one really important thing is that some tiles may be blank. Adding noise to blank tiles might seem problematic,
but since identical tiles (like blanks) always have the **same b64 representation** AND are passed the same **entropy**,
they receive the **exact same noise**, keeping them interchangeable.

Previously, we avoided adding noise to blank tiles to ensure interchangeability, but with deterministic noise application,
we can now apply noise to **all tiles**, making **every puzzle unique across all tiles while maintaining interchangeability** where needed.

For example, if a puzzle solution consists of tiles [A, B, A], the hash calculation remains the same whether the first and last tiles are swapped:

	hash(A, B, A) == hash(A, B, A)

Since blank tiles are identical, they will always be given the same noise, ensuring their interchangeability is preserved,
while every puzzle remains uniquely coded to each user, destroying any replay attack vectors.

Additionally, since we now use a separate **thumbnail entropy**, even the thumbnail cannot be used as a reference to map tile hashes,
further ensuring that previously seen solutions **cannot be reused**.

To guarantee full security, noise is applied **before computing HMAC hashes**, ensuring each puzzle is cryptographically distinct
and resistant to brute-force attacks.

Even with dedicated attacks attempting to brute-force noise values, using the rate limiting strategy explain in docs and
simply rotating images periodically further mitigates any long-term risks.
*/
type PuzzleImageController struct {
	tileNoiseMasks               [NumberOfTileNoiseMasks]PuzzleTileNoiseMask
	partitionedImageTileMetadata map[int]PuzzleTileMetadata
	thumbnailNoiseMasks          [NumberOfTileNoiseMasks]PuzzleTileNoiseMask
	thumbnailPtr                 *image.RGBA
	partitionTileHeight          int
	partitionTileWidth           int
	numberOfPartitions           int

	/*
		Although we are making copies for operations and never directly modifying the pointers to tile metadata or thumbnail pointers, becuase we may
		need to deal with hot reloading configs, we use an rwLock such that we acquire and release it when reading from the TileMapFromImage or ThumbnailFromImage
		functions and acquire the write lock when invoking the newPuzzleImageController at the level of the configHolder.Load()
	*/
	rwLock sync.RWMutex
}

func NewPuzzleImageController(config *Config) (*PuzzleImageController, error) {
	if config.PuzzleDifficultyProfiles == nil {
		return nil, errors.New("ErrFailedToLoadDifficultyProfiles")
	}
	/*
		right now I am assuming that there is just one image to be served for all challenges. However, if you wanted to make
		it such that each hostname has its own logo, there would need to be a map of "Image controllers" and "targets" indexed
		by hostnames such that each hostname has its own difficulty. Then modify the PuzzleDifficultyProfileByName such that it also
		takes as argument the hostname and performs the lookup to get the target before then using that to lookup the difficulty
		profile itself. The idea of having a "target" is to be able to create the difficulties ahead of time and then
		make looking up the profile more convenient by just specifying target.
	*/

	/*
		if you wanted to store multiple images for example different hostnames have different logs & you wanted to issue a puzzle
		with that organizations hostname, this would be a map[string]*PuzzleImageController such that on challenge just lookup the appropriate one to use
		at the level of the Generate Puzzle function when invoking the PuzzleTileMapFromImage() and PuzzleThumbnailFromImage() functions
	*/

	var puzzleImageController = &PuzzleImageController{}
	err := puzzleImageController.UpdateFromConfig(config)
	if err != nil {
		return nil, fmt.Errorf("ErrFailedLoadingImageControllerState: %v", err)
	}

	return puzzleImageController, nil
}

/*
NewPuzzleImageController is created one time on init with the goal of performing the most costly operations one time. After
paying this price once on init, we can simply apply O(1) operations when issueing challenges to user during runtime. This
also applies to validating solutions such that we can avoid storing precomputed results ahead of time (which does not
scale well if we are under attack as we would allocate memory for each challenge). Instead, we allocate the memory we need
one time, and subsequently reuse the tools to generate deterministically random results!
*/
func (imgController *PuzzleImageController) UpdateFromConfig(config *Config) error {

	imgController.rwLock.Lock()
	defer imgController.rwLock.Unlock()

	//not redudant as its subsequently called on hot reload directly via UpdateFromConfig so its an important check
	if config.PuzzleDifficultyProfiles == nil {
		return errors.New("ErrFailedToLoadDifficultyProfiles")
	}

	if config.PuzzleDifficultyTarget == "" {
		return errors.New("ErrMissingTargetPuzzleDifficultyProfile")
	}

	targetDifficulty, exists := PuzzleDifficultyProfileByName(config, config.PuzzleDifficultyTarget, "")
	if !exists {
		return errors.New("ErrMissingTargetPuzzleDifficultyProfile")
	}

	sqrt := int(math.Sqrt(float64(targetDifficulty.NPartitions)))
	if sqrt*sqrt != targetDifficulty.NPartitions {
		return ErrFailedInitInvalidNumberOfPartitions
	}

	b64Img := LoadDefaultPuzzleImageBase64()

	img, err := decodeBase64ToImage(b64Img)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedDecoding, err)
	}

	thumbnail := resizeToThumbnail(img)
	thumbnailRGBA := convertToRGBA(thumbnail)
	thumbnailHeight := thumbnailRGBA.Bounds().Dy()
	thumbnailWidth := thumbnailRGBA.Bounds().Dx()

	var thumbnailNoiseMasks [NumberOfTileNoiseMasks]PuzzleTileNoiseMask
	for i := 0; i < NumberOfTileNoiseMasks; i++ {
		//we use i*54321 as entropy so we get deterministic masks across restarts while maintaining pseudo random noise
		thumbnailNoiseMasks[i] = generateTileNoiseMask(thumbnailHeight, thumbnailWidth, i*54321)
	}

	imgPartitionedAsTiles, err := partitionImage(img, targetDifficulty.NPartitions)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedInitImagePartition, err)
	}

	//since each partition is the same dimension, we can create our mask for one
	//as the puzzle is always a perfect square number of tiles
	targetImg := imgPartitionedAsTiles[0]
	rgbaImgPartition := convertToRGBA(targetImg)
	tileHeight := rgbaImgPartition.Bounds().Dy()
	tileWidth := rgbaImgPartition.Bounds().Dx()

	var tileNoiseMasks [NumberOfTileNoiseMasks]PuzzleTileNoiseMask
	for i := 0; i < NumberOfTileNoiseMasks; i++ {
		//we use i*12345 as entropy so we get deterministic masks across restarts while maintaining pseudo random noise
		tileNoiseMasks[i] = generateTileNoiseMask(tileHeight, tileWidth, i*12345)
	}

	partitionedImageTiles := make(map[int]PuzzleTileMetadata)
	for i, tile := range imgPartitionedAsTiles {
		rgbaTile := convertToRGBA(tile)
		hashOfTilePixels := hashTilePixels(rgbaTile)
		partitionedImageTiles[i] = PuzzleTileMetadata{RGBAImagePtr: rgbaTile, Hash: hashOfTilePixels}
	}

	imgController.partitionedImageTileMetadata = partitionedImageTiles

	imgController.numberOfPartitions = targetDifficulty.NPartitions
	imgController.tileNoiseMasks = tileNoiseMasks
	imgController.partitionTileHeight = tileHeight
	imgController.partitionTileWidth = tileWidth

	imgController.thumbnailNoiseMasks = thumbnailNoiseMasks
	imgController.thumbnailPtr = thumbnailRGBA

	return nil
}

/*
TileMapFromImage is used to generate the tileMaps for each individual challenge at runtime.
This performs O(1) operations in order to generate the map as all costly operations were performed
on initialization.

NOTE: when invoking the applyNoiseMask function, we are making a copy inside that function so we
can modify noisedImg freely without affecting tileRGBA (which is just a pointer to the original stored image)

NOTE: set includeBase64Png to false when calculating the TileID's for validation as we need not have the image data when validating

If T == Tile, return tiles with Base64 images (Tile)
If T == TileWithoutImage, return tiles without Base64 images (TileWithoutImage)
*/
func PuzzleTileMapFromImage[T PuzzleTileIdentifier](config *Config, puzzleImageController *PuzzleImageController, userChallengeCookie string, includeBase64Png bool) (PuzzleTileMap[T], error) {

	// imgController := config.PuzzleImageController

	puzzleImageController.rwLock.RLock()
	defer puzzleImageController.rwLock.RUnlock()

	tileMap := make(PuzzleTileMap[T])
	for i := range puzzleImageController.numberOfPartitions {

		tileRGBA := puzzleImageController.partitionedImageTileMetadata[i].RGBAImagePtr
		tileHash := puzzleImageController.partitionedImageTileMetadata[i].Hash

		var noisyTileB64 string

		if includeBase64Png {

			var err error

			/*
				selectionEntropy is unique per challenge per user becuase of the cookie being different per challenge per user
				by also including the hash of the image itself, identical images get the same hashes => they use the same mask but
				different images use different masks making identifying patterns harder


				The reasons we use BOTH the users challenge cookie as well as the hash of the target tile as entropy when selecting which noise mask
				to apply are:

					1) we want to make sure that per user per challenge (ie for each challenge cookie) we get different masks so users cannot
					just find some trivial defeat mechanism like a map of b64 data and just lookup their way to the right answer.

					2) we also take into consideration the hash of the tile itself such that the same tiles get the same mask so that they preserve
					their interchangability property. That way if we have identical tiles, we can apply noise to them (to make them different per
					user per challenge) BUT have the identical tiles remain interchangeable so the user can submit them in any order as they are identical
			*/

			selectionEntropy := fmt.Sprintf("%s%s", userChallengeCookie, tileHash)
			randomIndex := PuzzleEntropyFromRange(config.PuzzleEntropySecret, selectionEntropy, 0, NumberOfTileNoiseMasks)
			tileMask := &puzzleImageController.tileNoiseMasks[randomIndex]

			// tileMask := selectNoiseMask(userChallengeCookie, tileHash, imgController.puzzleSecret, &imgController.tileNoiseMasks)
			noisyTile := applyNoiseMask(tileRGBA, tileMask, puzzleImageController.partitionTileHeight, puzzleImageController.partitionTileWidth)

			noisyTileB64, err = encodeImageToBase64(noisyTile)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to encode noisy tile: %w", ErrFailedEncoding, err)
			}
		}

		tileID := GenerateHMACFromString(tileHash, userChallengeCookie)
		/*
			notice that we get the tileID from the hash against the tileHash as opposed to against the noisyTileB64. This is done
			for several reasons, namely, using the precomputed tileHash instead of hashing the noisy b64 encoded tile is a massive
			performance improvement AND we still maintain all required security and uniqueness properties.

			In particular,

			- Since the tileHashs that were calculated on init are done so on the base64 data, identical images
			admit identical hashes. Since we are using a deterministic masking procedure to pick how to add noise, if we were
			to rehash the noisy tiles, we would notice that the hashes that were identical remain identical and the ones
			that were not again remain not. The only difference is the overhead required to compute the hmac against the cookie
			because the b64 data is much bigger.

			- Since the hash is generated using the userChallengeCookie, each of the TileIDs would STILL be unique
			per user per challenge, so we are not somehow allowing a replay, forgery or trivial mapping attacks

			- Since the tileHash is derived from the original image pixels, ensuring that identical tiles have identical hashes.
			- Because the HMAC uses tileHash as input, identical tiles will always get the same TileID across different
			challenges for the same user, preserving their interchangeability.

			so, calculating the HMAC over the b64 encoded noisy tile instead of the precomputed tileHash would yield the
			exact same results but with significantly worse performance due to the overhead of hashing large Base64 data.
		*/

		var tile T
		switch any(tile).(type) {
		case PuzzleTile:
			tile = any(PuzzleTile{Base64Image: noisyTileB64, TileGridID: tileID}).(T)
		case PuzzleTileWithoutImage:
			tile = any(PuzzleTileWithoutImage{TileGridID: tileID}).(T)
		default:
			return nil, fmt.Errorf("%w: unsupported tile type", ErrUnsupportedPuzzleType)
		}

		tileMap[i] = tile
	}

	return tileMap, nil
}

/*
Returns a copy with the changes made (removing the tile after generating puzzle) such that we do not affect the og image

NOTE: We use unix timestamp at the time we issue the challenge as part of the entropy for picking a mask because the
thumbnail itself has no effect on the users calcualted result and we need not ever recreate it. We also want to guarentee
there exists no correlation between the users current challenge grid image and the thumbnail to avoid a user trying to cheat
the puzzle by partitioning the thumbnail or trying to get cute in any other way.
*/
func PuzzleThumbnailFromImage(config *Config, puzzleImageController *PuzzleImageController, thumbnailEntropy string, removeRow, removeCol int) (string, error) {

	// imgController := config.PuzzleImageController

	puzzleImageController.rwLock.RLock()
	defer puzzleImageController.rwLock.RUnlock()

	thumbnailCopy := image.NewRGBA(puzzleImageController.thumbnailPtr.Bounds()) //copy to not affect the ptr for the next guy
	draw.Draw(thumbnailCopy, thumbnailCopy.Bounds(), puzzleImageController.thumbnailPtr, puzzleImageController.thumbnailPtr.Bounds().Min, draw.Src)

	tileWidth := thumbnailCopy.Bounds().Dx() / int(math.Sqrt(float64(puzzleImageController.numberOfPartitions)))
	tileHeight := thumbnailCopy.Bounds().Dy() / int(math.Sqrt(float64(puzzleImageController.numberOfPartitions)))

	transparencyFactor := 0.9
	for y := 0; y < tileHeight; y++ {
		for x := 0; x < tileWidth; x++ {
			idxX := removeCol*tileWidth + x
			idxY := removeRow*tileHeight + y
			origColor := thumbnailCopy.RGBAAt(idxX, idxY)
			grayValue := uint8(170)

			thumbnailCopy.SetRGBA(idxX, idxY, color.RGBA{
				R: uint8(float64(origColor.R)*(1-transparencyFactor) + float64(grayValue)*transparencyFactor),
				G: uint8(float64(origColor.G)*(1-transparencyFactor) + float64(grayValue)*transparencyFactor),
				B: uint8(float64(origColor.B)*(1-transparencyFactor) + float64(grayValue)*transparencyFactor),
				A: uint8(float64(origColor.A)*(1-transparencyFactor) + 120*transparencyFactor),
			})
		}
	}

	selectionEntropy := fmt.Sprintf("%s%d", thumbnailEntropy, time.Now().UnixNano())
	randomIndex := PuzzleEntropyFromRange(config.PuzzleEntropySecret, selectionEntropy, 0, NumberOfTileNoiseMasks)
	tileMask := &puzzleImageController.thumbnailNoiseMasks[randomIndex]

	noisyThumbnail := applyNoiseMask(thumbnailCopy, tileMask, thumbnailCopy.Bounds().Dy(), thumbnailCopy.Bounds().Dx())

	thumbnailBase64, err := encodeImageToBase64(noisyThumbnail)
	if err != nil {
		return "", fmt.Errorf("%w: failed to encode thumbnail: %w", ErrFailedEncoding, err)
	}

	return thumbnailBase64, nil
}

/*
NOTE:
This is happening at runtime, although technically this is N^2 it is important to notice that we are applying the operation
to a fixed size tile that is never going to grow - it does not scale dynamically, its always made up of the same number of pixels.
So I argue the conventional Big-O N^2 notation is misleading — this is a constant-time operation in practice.

Also note that noisedImg := image.NewRGBA(img.Bounds()) creates a copy. So we are never actually changing the data in the map
so you can modify noisedImg freely without affecting tileRGBA (which is just a pointer to the original stored image)
*/
func applyNoiseMask(img *image.RGBA, mask *PuzzleTileNoiseMask, tileHeight, tileWidth int) *image.RGBA {
	noisedImg := image.NewRGBA(img.Bounds())

	for y := 0; y < tileHeight; y++ {
		for x := 0; x < tileWidth; x++ {
			origColor := img.RGBAAt(x, y)
			noise := mask.Offsets[y][x]

			//apply noise, ensuring values stay in [0,255]
			r := clampColor(int(origColor.R) + noise[0])
			g := clampColor(int(origColor.G) + noise[1])
			b := clampColor(int(origColor.B) + noise[2])

			noisedImg.SetRGBA(x, y, color.RGBA{uint8(r), uint8(g), uint8(b), origColor.A})
		}
	}
	return noisedImg
}

func clampColor(val int) uint8 {
	if val < 0 {
		return 0
	} else if val > 255 {
		return 255
	}
	return uint8(val)
}

/*
Note that here we use a maskSeed was is meant to always be the same such that
on restarts we generate the exact same masks. This ensures even if a machine crashes
while solving a puzzle, it it is back up by the time they submit their solution, we
will still be able to validate their solution and/or cookie
*/
func generateTileNoiseMask(tileHeight, tileWidth, maskSeed int) PuzzleTileNoiseMask {
	seed := int64(maskSeed)
	r := rand.New(rand.NewSource(seed))

	//anything from [16, 26] results in solid noise, doesn't disturb peoples ability to see
	minNoise := 16
	maxNoise := 26
	noiseLevel := r.Intn(maxNoise-minNoise+1) + minNoise

	mask := PuzzleTileNoiseMask{Offsets: make([][][3]int, tileHeight)}
	for y := 0; y < tileHeight; y++ {
		mask.Offsets[y] = make([][3]int, tileWidth)
		for x := 0; x < tileWidth; x++ {
			mask.Offsets[y][x] = [3]int{
				r.Intn(noiseLevel*2+1) - noiseLevel, // R offset
				r.Intn(noiseLevel*2+1) - noiseLevel, // G offset
				r.Intn(noiseLevel*2+1) - noiseLevel, // B offset
			}
		}
	}

	return mask
}

/*gets us the entropy from the tile itself which is much gaster than encoding and decoding to and from base64*/
func hashTilePixels(img *image.RGBA) string {
	h := sha256.New()
	for y := img.Bounds().Min.Y; y < img.Bounds().Max.Y; y++ {
		for x := img.Bounds().Min.X; x < img.Bounds().Max.X; x++ {
			c := img.RGBAAt(x, y)
			h.Write([]byte{c.R, c.G, c.B, c.A})
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

/*
resizes thumbnail image to specified constant. Helps to make the image different from grid tiles to mitigate
partitioning attempts at recreating the grid and also makes for less data to send
*/
func resizeToThumbnail(img image.Image) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, thumbnailSize, thumbnailSize))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
	return dst
}

/*converts image to RGBA*/
func convertToRGBA(img image.Image) *image.RGBA {
	if rgbaImg, ok := img.(*image.RGBA); ok {
		return rgbaImg
	}
	rgba := image.NewRGBA(img.Bounds())
	draw.Draw(rgba, rgba.Bounds(), img, img.Bounds().Min, draw.Src)
	return rgba
}

/*from base64 encoded png image to image.Image */
func decodeBase64ToImage(data string) (image.Image, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	img, err := png.Decode(bytes.NewReader(decoded))
	if err != nil {
		return nil, err
	}
	return img, nil
}

/*from image.Image to base64 encoded png*/
func encodeImageToBase64(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

/*
partitions an image.Image into nPartition tiles
Requires nPartitions be a perfect square as all
puzzle grids are meant to be squares
*/
func partitionImage(img image.Image, nPartitions int) ([]image.Image, error) {
	sqrt := int(math.Sqrt(float64(nPartitions)))
	if sqrt*sqrt != nPartitions {
		return nil, errors.New("nPartitions must be a perfect square")
	}
	tileWidth := img.Bounds().Dx() / sqrt
	tileHeight := img.Bounds().Dy() / sqrt
	tiles := []image.Image{}

	for row := 0; row < sqrt; row++ {
		for col := 0; col < sqrt; col++ {
			tile := image.NewRGBA(image.Rect(0, 0, tileWidth, tileHeight))
			for y := 0; y < tileHeight; y++ {
				for x := 0; x < tileWidth; x++ {
					tile.Set(x, y, img.At(col*tileWidth+x, row*tileHeight+y))
				}
			}
			tiles = append(tiles, tile)
		}
	}
	return tiles, nil
}
