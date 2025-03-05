package puzzleutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
)

/*to save memory, we store only the tileIDs without the base64 when storing the copy of the original for verification*/
type TileWithoutImage struct {
	TileGridID string `json:"tile_grid_id"`
}

type Tile struct {
	Base64Image string `json:"base64_image"`
	TileGridID  string `json:"tile_grid_id"`
}

type TileMap map[int]Tile

/*
- Dynamically partitions the image into tiles and generates a map of hash-to-index pairs.

- Suitable for real-time validation where caching is not needed.

	challengeEntropy - string assigned uniquely to this particular user we are currently challenging to create a different key unique
	to their puzzle to identify each game board piece without giving up location/index/positional information

	base64PngImage - a base64 encoded PNG image

	nPartitions - the number of partitions you want the image to be partitioned into. MUST be a perfect square
*/
func TileMapFromImage(challengeEntropy string, base64PngImage string, nPartitions int) (TileMap, error) {
	img, err := decodeBase64ToImage(base64PngImage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	imageRGBA := convertToRGBA(img)
	tiles, err := partitionImage(imageRGBA, nPartitions)
	if err != nil {
		return nil, fmt.Errorf("failed to partition image: %w", err)
	}

	tileMap := make(TileMap)
	for i, tile := range tiles {
		encodedTile, err := encodeImageToBase64(tile)
		if err != nil {
			return nil, fmt.Errorf("failed to encode tile: %w", err)
		}
		hash := GenerateHMACFromString(encodedTile, challengeEntropy)
		tileMap[i] = Tile{Base64Image: encodedTile, TileGridID: hash}
	}

	return tileMap, nil
}

/*
- generates the thumbnail image to be displayed but the thumbnails replaced tile is transparent to help users
understand what would have been there (provides a complete image making it easier to understand)

	challengeEntropy - string assigned uniquely to this particular user we are currently challenging to create a different (comprising a server secret and the users challenge cookie string)

	base64PngImageOrPathToBase64PngImage - either a base64 encoded PNG image OR a path to a base64 encoded PNG image

	nPartitions - the number of partitions you want the image to be partitioned into. MUST be a perfect square

	rowOfPartitionToRemove - row of the partition to remove

	colOfPartitionToRemove - col of the partition to remove
*/
func ThumbnailFromImageWithTransparentTile(challengeEntropy string, base64PngImage string, nPartitions, removeRow, removeCol int) (string, error) {
	img, err := decodeBase64ToImage(base64PngImage)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	imgRGBA := convertToRGBA(img)
	tileWidth := imgRGBA.Bounds().Dx() / int(math.Sqrt(float64(nPartitions)))
	tileHeight := imgRGBA.Bounds().Dy() / int(math.Sqrt(float64(nPartitions)))

	transparencyFactor := 0.9
	for y := 0; y < tileHeight; y++ {
		for x := 0; x < tileWidth; x++ {
			idxX := removeCol*tileWidth + x
			idxY := removeRow*tileHeight + y
			origColor := imgRGBA.RGBAAt(idxX, idxY)
			grayValue := uint8(170)

			imgRGBA.SetRGBA(idxX, idxY, color.RGBA{
				R: uint8(float64(origColor.R)*(1-transparencyFactor) + float64(grayValue)*transparencyFactor),
				G: uint8(float64(origColor.G)*(1-transparencyFactor) + float64(grayValue)*transparencyFactor),
				B: uint8(float64(origColor.B)*(1-transparencyFactor) + float64(grayValue)*transparencyFactor),
				A: uint8(float64(origColor.A)*(1-transparencyFactor) + 120*transparencyFactor),
			})
		}
	}

	noisyImg, err := addNoise(imgRGBA, challengeEntropy)
	if err != nil {
		return "", fmt.Errorf("failed to add noise: %w", err)
	}

	thumbnailBase64, err := encodeImageToBase64(noisyImg)
	if err != nil {
		return "", fmt.Errorf("failed to encode thumbnail: %w", err)
	}

	return thumbnailBase64, nil
}

/*
- generates the thumbnail image to be displayed

	challengeEntropy - string assigned uniquely to this particular user we are currently challenging to create a different (comprising a server secret and the users challenge cookie string)

	base64PngImageOrPathToBase64PngImage - either a base64 encoded PNG image OR a path to a base64 encoded PNG image

	nPartitions - the number of partitions you want the image to be partitioned into. MUST be a perfect square

	rowOfPartitionToRemove - row of the partition to remove

	colOfPartitionToRemove - col of the partition to remove
*/
func ThumbnailFromImage(challengeEntropy string, base64PngImage string, nPartitions, removeRow, removeCol int) (string, error) {
	img, err := decodeBase64ToImage(base64PngImage)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}
	imageRGBA := convertToRGBA(img)
	tileWidth := imageRGBA.Bounds().Dx() / int(math.Sqrt(float64(nPartitions)))
	tileHeight := imageRGBA.Bounds().Dy() / int(math.Sqrt(float64(nPartitions)))

	grayTile := image.NewRGBA(image.Rect(0, 0, tileWidth, tileHeight))
	for y := 0; y < tileHeight; y++ {
		for x := 0; x < tileWidth; x++ {
			grayTile.Set(x, y, color.RGBA{170, 170, 170, 255})
		}
	}

	offsetX := removeCol * tileWidth
	offsetY := removeRow * tileHeight
	dst := image.NewRGBA(imageRGBA.Bounds())
	copy(dst.Pix, imageRGBA.Pix)
	drawImage(dst, grayTile, offsetX, offsetY)

	noisyImg, err := addNoise(dst, challengeEntropy)
	if err != nil {
		return "", fmt.Errorf("failed to add noise: %w", err)
	}

	thumbnailBase64, err := encodeImageToBase64(noisyImg)
	if err != nil {
		return "", fmt.Errorf("failed to encode thumbnail: %w", err)
	}

	return thumbnailBase64, nil
}

// convertToRGBA converts any image.Image to *image.RGBA
func convertToRGBA(img image.Image) *image.RGBA {
	if rgbaImg, ok := img.(*image.RGBA); ok {
		return rgbaImg
	}
	rgba := image.NewRGBA(img.Bounds())
	draw.Draw(rgba, rgba.Bounds(), img, img.Bounds().Min, draw.Src)
	return rgba
}

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

func encodeImageToBase64(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

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

/*
adds invisible noise to a base64-encoded PNG image to prevent trivial reverse engineering via hash matching.
Ie, without adding noise to the thumbnail, someone can just download the thumbnail, partition it themselves, re-create the base64 encoded tiles and then
they would have the correct order. So looking at the gameBoard, they could arrange it trivially. Instead, by adding invisible noise to only the thumbnail, we make this
less easy.

Noise need not be limited to what we are currently doing (adding invisible changes), instead they can be visible. Furthermore, applying blurring or compression etc can help with this.

NOTE: Do NOT apply noise to the users tiles, ONLY do so to the thumbnail. If you add noise to user tiles, then the blank tiles are no longer "interchangeable" which isnt
fair to the user since the noise is invisible. Users would have to put tiles that look identical "in order" and thats just possible. So instead, we modify only the thumbnail since its only provided as a reference image
and the changes are subtle enough that you can't see them with the human eye but make a massive difference to the resultant base64 string. For example, a simple +-2 noiseLevel gives us:

The resulting image is identical to the human eye, the b64 strings are not same length and the strings are completely different!
So trivial statistical/hashing reverse engineering attacks become considerably harder.

NOTE however that there does exist a class of hashing algorithms called "perceptual hashing algorithms" take care more about the "look" than exact pixel values. So this change, although important
is not nearly enough. Later we would need to consider actually adding visible changes as well

Also note, this is a particularly good strategy as long as the images are "simple" like logos etc because they have a LOT of empty space. PNG compression relies on redudancy, so if the original image
has a lot of uniform regions that were compressable, you get a smaller size, BUT because we are adding a noise everywhere, the result is considerably larger but makes it much more different as desired!
So be careful about having extremely complex designs/logos because the more complex the logo, the less effective the noise strategy is at producing a massive difference between the thumbnail and the puzzle
tiles should someone try to partition the thumbnail
*/
func addNoise(img *image.RGBA, entropy string) (*image.RGBA, error) {
	seed := stringToSeed(entropy)
	r := rand.New(rand.NewSource(seed))

	//anything from [20, 36] results in solid noise, doesn't disturb peoples ability to see
	//the image, makes it different per puzzle and doesn't generate an overwhelmingly large filesize
	minNoise := 16
	maxNoise := 24
	noiseLevel := r.Intn(maxNoise-minNoise+1) + minNoise

	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			c := img.RGBAAt(x, y)
			for i := 0; i < 3; i++ {
				randomNoise := r.Intn(noiseLevel*2+1) - noiseLevel
				switch i {
				case 0:
					c.R = clampColor(int(c.R) + randomNoise)
				case 1:
					c.G = clampColor(int(c.G) + randomNoise)
				case 2:
					c.B = clampColor(int(c.B) + randomNoise)
				}
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img, nil
}

func clampColor(val int) uint8 {
	if val < 0 {
		return 0
	} else if val > 255 {
		return 255
	}
	return uint8(val)
}

func stringToSeed(entropy string) int64 {
	h := sha256.New()
	h.Write([]byte(entropy))
	sum := h.Sum(nil)
	var seed int64
	for _, b := range sum[:8] {
		seed = (seed << 8) | int64(b)
	}
	return seed
}

func drawImage(dst, src *image.RGBA, offsetX, offsetY int) {
	for y := 0; y < src.Bounds().Dy(); y++ {
		for x := 0; x < src.Bounds().Dx(); x++ {
			color := src.RGBAAt(x, y)
			dst.SetRGBA(offsetX+x, offsetY+y, color)
		}
	}
}
