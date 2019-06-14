/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package sm4 transforms values for storage at rest using SM4-CBC.
package sm4

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/tjfoc/gmsm/sm4"
	"k8s.io/apiserver/pkg/storage/value"
)

const KeySize = sm4.BlockSize

// CBC implements encryption at rest of the provided values given a cipher.Block algorithm.
type CBC struct {
	block cipher.Block
}

// New takes the given SM4 key and performs encryption and decryption on the
// given data.
func New(key []byte) (value.Transformer, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &CBC{block: block}, nil
}

func (t *CBC) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	blockSize := sm4.BlockSize
	if len(data) < blockSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	iv := data[:blockSize]
	data = data[blockSize:]

	if len(data)%blockSize != 0 {
		return nil, false, fmt.Errorf("the stored data is not a multiple of the block size")
	}

	result := make([]byte, len(data))
	copy(result, data)
	mode := cipher.NewCBCDecrypter(t.block, iv)
	mode.CryptBlocks(result, result)

	// remove and verify PKCS#7 padding for CBC
	c := result[len(result)-1]
	paddingSize := int(c)
	size := len(result) - paddingSize
	if paddingSize == 0 || paddingSize > len(result) {
		return nil, false, errors.New("invalid PKCS7 data (empty or not padded)")
	}
	for i := 0; i < paddingSize; i++ {
		if result[size+i] != c {
			return nil, false, errors.New("invalid padding on input")
		}
	}

	return result[:size], false, nil
}

func (t *CBC) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	blockSize := sm4.BlockSize
	paddingSize := blockSize - (len(data) % blockSize)
	result := make([]byte, blockSize+len(data)+paddingSize)
	iv := result[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}
	copy(result[blockSize:], data)

	// add PKCS#7 padding for CBC
	copy(result[blockSize+len(data):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))

	mode := cipher.NewCBCEncrypter(t.block, iv)
	mode.CryptBlocks(result[blockSize:], result[blockSize:])
	return result, nil
}
