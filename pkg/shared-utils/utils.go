package sharedutils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func LoadDefaultImageBase64() string {
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

// func GetCaptchaServerFromContext(ctx context.Context) (CaptchaServerContract, error) {
// 	srv, ok := ctx.Value(models.ServerCtxKey).(CaptchaServerContract)
// 	if !ok {
// 		return nil, errors.New("failed to retrieve CaptchaServer from context")
// 	}
// 	return srv, nil
// }

func getAbsolutePath(relativePath string) (string, error) {
	basePath, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	return filepath.Join(basePath, relativePath), nil
}

func GetAbsolutePath(relativePath string) (string, error) {
	return getAbsolutePath(relativePath)
}

/*
This generates a proper hmac, not a hash
usage:

	message := []byte("urmsg")
	key := []byte("superSecret")

	hmacValue := GenerateHMAC(message, key)
	fmt.Println("HMAC:", hmacValue)
*/
func GenerateHMACFromBytes(message, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateHMACFromString(message string, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))              //msg is a string, converted to bytes
	return hex.EncodeToString(h.Sum(nil)) //ensures no padding
}
