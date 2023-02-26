/*
* This file is part of EternalPatchManifestGo (https://github.com/PowerBall253/EternalPatchManifestGo).
* Copyright (C) 2023 PowerBall253
*
* EternalPatchManifestGo is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* EternalPatchManifestGo is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with EternalPatchManifestGo. If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/iancoleman/orderedmap"
	"math"
	"os"
)

// Decrypt ciphertext using AES GCM 128
func gcmDecrypt(ciphertext, additionalData, key, nonce []byte) ([]byte, error) {
	// Init AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decompress
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Encrypt plaintext using AES GCM 128
func gcmEncrypt(plaintext, additionalData, key, nonce []byte) ([]byte, error) {
	// Init AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Compress
	return aesgcm.Seal(nil, nonce, plaintext, additionalData), nil
}

// Decrypt build manifest
func decryptBuildManifest(encData, key []byte) ([]byte, error) {
	// Get nonce
	nonce := make([]byte, 0xC)
	copy(nonce, encData)

	// Decrypt
	plaintext, err := gcmDecrypt(encData[0xC:len(encData) - 0x40], []byte("build-manifest"), key, nonce)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Re-encrypt build manifest
func encryptBuildManifest(decJson, key []byte) ([]byte, error) {
	// Get random bytes for nonce
	nonce := make([]byte, 0xC)
	rand.Read(nonce)

	// Encrypt
	ciphertext, err := gcmEncrypt(decJson, []byte("build-manifest"), key, nonce)
	if err != nil {
		return nil, err
	}

	// Construct build manifest
	buildManifest := make([]byte, 0xC + len(ciphertext) + 0x40)
	copy(buildManifest, nonce)
	copy(buildManifest[0xC:], ciphertext)
	return buildManifest, nil
}

// Optimize the JSON by removing uneeded entries and using dummy data
func optimizeBuildManifest(bmJson []byte) ([]byte, error) {
	// Decode JSON
	buildManifest := orderedmap.New()
	err := json.Unmarshal(bmJson, &buildManifest)
	if err != nil {
		return nil, err
	}

	// Get files array
	filesInterface, _ := buildManifest.Get("files")
	files := filesInterface.(orderedmap.OrderedMap)

	// Iterate through files
	for _, path := range files.Keys() {
		// Get file component
		componentsInterface, _ := files.Get(path)
		components := componentsInterface.(orderedmap.OrderedMap)

		// Get file size
		fileSizeInterface, _ := components.Get("fileSize")
		fileSize := int64(fileSizeInterface.(float64))

		// Update file size
		if fileInfo, err := os.Stat(path); err == nil {
			fileSize = fileInfo.Size()
			components.Set("fileSize", fileSize)
			fmt.Printf("Found file %s, fileSize updated to: %d\n", path, fileSize)
		}

		// Get number of hashes needed
		numHashes := fileSize / math.MaxUint32
		if fileSize % math.MaxUint32 != 0 {
			numHashes += 1
		}

		// Set dummy hash
		dummyHash := "e2df1b2aa831724ec987300f0790f04ad3f5beb8"
		hashes := make([]string, numHashes)
		for i := range hashes {
			hashes[i] = dummyHash
		}
		components.Set("hashes", hashes)

		// Set chunk size
		components.Set("chunkSize", math.MaxUint32)

		// Set file component
		files.Set(path, components)
	}

	// Convert back to JSON
	optimizedBmJson, err := json.Marshal(buildManifest)
	if err != nil {
		return nil, err
	}

	return optimizedBmJson, nil
}

// Program version: to be set with -ldflags="-x 'main.Version=vX.X.X'"
var Version = "dev"

// Main function
func main() {
	fmt.Printf("EternalPatchManifestGo %s by PowerBall253 :)\n\n", Version)

	// Make sure argument length is correct
	if len(os.Args) != 2 {
		fmt.Println("Usage:")
		fmt.Printf("%s <AES key>\n\n", os.Args[0])
		fmt.Print("AES key: Hex key for AES encryption/decryption of the file.\n\n")
		fmt.Println("Example:")
		fmt.Printf("%s 8B031F6A24C5C4F3950130C57EF660E9\n", os.Args[0])
		os.Exit(1)
	}

	// Get key from argument
	key, err := hex.DecodeString(os.Args[1])
	if err != nil || len(key) != 0x10 {
		fmt.Fprintln(os.Stderr, "ERROR: Failed to get key bytes from provided key.")
		fmt.Fprintln(os.Stderr, "Make sure the key provided is a valid hex string.")
		os.Exit(1)
	}

	// Read build manifest
	buildManifest, err := os.ReadFile("build-manifest.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to read build manifest: %s\n", err.Error())
		os.Exit(1)
	}

	// Decrypt build manifest
	bmDec, err := decryptBuildManifest(buildManifest, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to decrypt build manifest: %s\n", err.Error())
		os.Exit(1)
	}

	// Optimize build manifest JSON
	bmJson, err := optimizeBuildManifest(bmDec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to optimize build manifest: %s\n", err.Error())
		os.Exit(1)
	}

	// Re-encrypt build manifest
	bmEnc, err := encryptBuildManifest(bmJson, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to re-encrypt build manifest: %s\n", err.Error())
		os.Exit(1)
	}

	// Write new build manifest
	err = os.WriteFile("build-manifest.bin", bmEnc, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to write new build manifest: %s\n", err.Error())
		os.Exit(1)
	}
}
