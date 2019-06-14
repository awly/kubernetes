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

package encryptionconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/tjfoc/gmsm/sm4"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserverconfig "k8s.io/apiserver/pkg/apis/config"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"
	"k8s.io/apiserver/pkg/storage/value/encrypt/secretbox"
	sm4transformer "k8s.io/apiserver/pkg/storage/value/encrypt/sm4"
)

const (
	aesCBCTransformerPrefixV1    = "k8s:enc:aescbc:v1:"
	aesGCMTransformerPrefixV1    = "k8s:enc:aesgcm:v1:"
	secretboxTransformerPrefixV1 = "k8s:enc:secretbox:v1:"
	kmsTransformerPrefixV1       = "k8s:enc:kms:v1:"
	sm4TransformerPrefixV1       = "k8s:enc:sm4:v1:"
	kmsPluginConnectionTimeout   = 3 * time.Second
)

// GetTransformerOverrides returns the transformer overrides by reading and parsing the encryption provider configuration file
func GetTransformerOverrides(filepath string) (map[schema.GroupResource]value.Transformer, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("error opening encryption provider configuration file %q: %v", filepath, err)
	}
	defer f.Close()

	result, err := ParseEncryptionConfiguration(f)
	if err != nil {
		return nil, fmt.Errorf("error while parsing encryption provider configuration file %q: %v", filepath, err)
	}
	return result, nil
}

// ParseEncryptionConfiguration parses configuration data and returns the transformer overrides
func ParseEncryptionConfiguration(f io.Reader) (map[schema.GroupResource]value.Transformer, error) {
	configFileContents, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read contents: %v", err)
	}

	config, err := loadConfig(configFileContents)
	if err != nil {
		return nil, fmt.Errorf("error while parsing file: %v", err)
	}

	resourceToPrefixTransformer := map[schema.GroupResource][]value.PrefixTransformer{}

	// For each entry in the configuration
	for _, resourceConfig := range config.Resources {
		transformers, err := GetPrefixTransformers(&resourceConfig)
		if err != nil {
			return nil, err
		}

		// For each resource, create a list of providers to use
		for _, resource := range resourceConfig.Resources {
			gr := schema.ParseGroupResource(resource)
			resourceToPrefixTransformer[gr] = append(
				resourceToPrefixTransformer[gr], transformers...)
		}
	}

	result := map[schema.GroupResource]value.Transformer{}
	for gr, transList := range resourceToPrefixTransformer {
		result[gr] = value.NewMutableTransformer(value.NewPrefixTransformers(fmt.Errorf("no matching prefix found"), transList...))
	}
	return result, nil

}

// loadConfig decodes data as a EncryptionConfiguration object.
func loadConfig(data []byte) (*apiserverconfig.EncryptionConfiguration, error) {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	apiserverconfig.AddToScheme(scheme)
	apiserverconfigv1.AddToScheme(scheme)

	configObj, gvk, err := codecs.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, err
	}
	config, ok := configObj.(*apiserverconfig.EncryptionConfiguration)
	if !ok {
		return nil, fmt.Errorf("got unexpected config type: %v", gvk)
	}
	return config, nil
}

// The factory to create kms service. This is to make writing test easier.
var envelopeServiceFactory = envelope.NewGRPCService

// GetPrefixTransformers constructs and returns the appropriate prefix transformers for the passed resource using its configuration.
func GetPrefixTransformers(config *apiserverconfig.ResourceConfiguration) ([]value.PrefixTransformer, error) {
	var result []value.PrefixTransformer
	for _, provider := range config.Providers {
		found := false

		var transformer value.PrefixTransformer
		var err error

		if provider.AESGCM != nil {
			transformer, err = GetAESPrefixTransformer(provider.AESGCM, aestransformer.NewGCMTransformer, aesGCMTransformerPrefixV1)
			if err != nil {
				return result, err
			}
			found = true
		}

		if provider.AESCBC != nil {
			if found == true {
				return result, fmt.Errorf("more than one provider specified in a single element, should split into different list elements")
			}
			transformer, err = GetAESPrefixTransformer(provider.AESCBC, aestransformer.NewCBCTransformer, aesCBCTransformerPrefixV1)
			found = true
		}

		if provider.Secretbox != nil {
			if found == true {
				return result, fmt.Errorf("more than one provider specified in a single element, should split into different list elements")
			}
			transformer, err = GetSecretboxPrefixTransformer(provider.Secretbox)
			found = true
		}

		if provider.Identity != nil {
			if found == true {
				return result, fmt.Errorf("more than one provider specified in a single element, should split into different list elements")
			}
			transformer = value.PrefixTransformer{
				Transformer: identity.NewEncryptCheckTransformer(),
				Prefix:      []byte{},
			}
			found = true
		}

		if provider.KMS != nil {
			if found == true {
				return nil, fmt.Errorf("more than one provider specified in a single element, should split into different list elements")
			}

			// Ensure the endpoint is provided.
			if len(provider.KMS.Endpoint) == 0 {
				return nil, fmt.Errorf("remote KMS provider can't use empty string as endpoint")
			}

			timeout := kmsPluginConnectionTimeout
			if provider.KMS.Timeout != nil {
				if provider.KMS.Timeout.Duration <= 0 {
					return nil, fmt.Errorf("could not configure KMS plugin %q, timeout should be a positive value", provider.KMS.Name)
				}
				timeout = provider.KMS.Timeout.Duration
			}

			// Get gRPC client service with endpoint.
			envelopeService, err := envelopeServiceFactory(provider.KMS.Endpoint, timeout)
			if err != nil {
				return nil, fmt.Errorf("could not configure KMS plugin %q, error: %v", provider.KMS.Name, err)
			}

			transformer, err = getEnvelopePrefixTransformer(provider.KMS, envelopeService, kmsTransformerPrefixV1)
			found = true
		}
		if provider.SM4 != nil {
			transformer, err = GetSM4PrefixTransformer(provider.SM4, sm4TransformerPrefixV1)
			if err != nil {
				return nil, err
			}
			found = true
		}

		if err != nil {
			return result, err
		}
		result = append(result, transformer)

		if found == false {
			return result, fmt.Errorf("invalid provider configuration: at least one provider must be specified")
		}
	}
	return result, nil
}

// BlockTransformerFunc takes an AES cipher block and returns a value transformer.
type BlockTransformerFunc func(cipher.Block) value.Transformer

// GetAESPrefixTransformer returns a prefix transformer from the provided configuration.
// Returns an AES transformer based on the provided prefix and block transformer.
func GetAESPrefixTransformer(config *apiserverconfig.AESConfiguration, fn BlockTransformerFunc, prefix string) (value.PrefixTransformer, error) {
	var result value.PrefixTransformer

	if len(config.Keys) == 0 {
		return result, fmt.Errorf("aes provider has no valid keys")
	}
	for _, key := range config.Keys {
		if key.Name == "" {
			return result, fmt.Errorf("key with invalid name provided")
		}
		if key.Secret == "" {
			return result, fmt.Errorf("key %v has no provided secret", key.Name)
		}
	}

	keyTransformers := []value.PrefixTransformer{}

	for _, keyData := range config.Keys {
		key, err := base64.StdEncoding.DecodeString(keyData.Secret)
		if err != nil {
			return result, fmt.Errorf("could not obtain secret for named key %s: %s", keyData.Name, err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return result, fmt.Errorf("error while creating cipher for named key %s: %s", keyData.Name, err)
		}

		// Create a new PrefixTransformer for this key
		keyTransformers = append(keyTransformers,
			value.PrefixTransformer{
				Transformer: fn(block),
				Prefix:      []byte(keyData.Name + ":"),
			})
	}

	// Create a prefixTransformer which can choose between these keys
	keyTransformer := value.NewPrefixTransformers(
		fmt.Errorf("no matching key was found for the provided AES transformer"), keyTransformers...)

	// Create a PrefixTransformer which shall later be put in a list with other providers
	result = value.PrefixTransformer{
		Transformer: keyTransformer,
		Prefix:      []byte(prefix),
	}
	return result, nil
}

// GetSecretboxPrefixTransformer returns a prefix transformer from the provided configuration
func GetSecretboxPrefixTransformer(config *apiserverconfig.SecretboxConfiguration) (value.PrefixTransformer, error) {
	var result value.PrefixTransformer

	if len(config.Keys) == 0 {
		return result, fmt.Errorf("secretbox provider has no valid keys")
	}
	for _, key := range config.Keys {
		if key.Name == "" {
			return result, fmt.Errorf("key with invalid name provided")
		}
		if key.Secret == "" {
			return result, fmt.Errorf("key %v has no provided secret", key.Name)
		}
	}

	keyTransformers := []value.PrefixTransformer{}

	for _, keyData := range config.Keys {
		key, err := base64.StdEncoding.DecodeString(keyData.Secret)
		if err != nil {
			return result, fmt.Errorf("could not obtain secret for named key %s: %s", keyData.Name, err)
		}

		if len(key) != 32 {
			return result, fmt.Errorf("expected key size 32 for secretbox provider, got %v", len(key))
		}

		keyArray := [32]byte{}
		copy(keyArray[:], key)

		// Create a new PrefixTransformer for this key
		keyTransformers = append(keyTransformers,
			value.PrefixTransformer{
				Transformer: secretbox.NewSecretboxTransformer(keyArray),
				Prefix:      []byte(keyData.Name + ":"),
			})
	}

	// Create a prefixTransformer which can choose between these keys
	keyTransformer := value.NewPrefixTransformers(
		fmt.Errorf("no matching key was found for the provided Secretbox transformer"), keyTransformers...)

	// Create a PrefixTransformer which shall later be put in a list with other providers
	result = value.PrefixTransformer{
		Transformer: keyTransformer,
		Prefix:      []byte(secretboxTransformerPrefixV1),
	}
	return result, nil
}

// GetSM4PrefixTransformer returns an SM4 transformer based on the provided
// prefix and block transformer.
func GetSM4PrefixTransformer(config *apiserverconfig.SM4Configuration, prefix string) (value.PrefixTransformer, error) {
	var result value.PrefixTransformer

	if len(config.Keys) == 0 {
		return result, fmt.Errorf("sm4 provider has no valid keys")
	}
	for _, key := range config.Keys {
		if key.Name == "" {
			return result, fmt.Errorf("sm4 key with empty name provided")
		}
		if key.Secret == "" {
			return result, fmt.Errorf("sm4 key %q has no provided secret", key.Name)
		}
	}

	var keyTransformers []value.PrefixTransformer
	for _, keyData := range config.Keys {
		key, err := base64.StdEncoding.DecodeString(keyData.Secret)
		if err != nil {
			return result, fmt.Errorf("could not obtain secret for named key %q: %s", keyData.Name, err)
		}
		block, err := sm4.NewCipher(key)
		if err != nil {
			return result, fmt.Errorf("error while creating cipher for named key %q: %s", keyData.Name, err)
		}

		// Create a new PrefixTransformer for this key
		keyTransformers = append(keyTransformers, value.PrefixTransformer{
			Transformer: sm4transformer.New(block),
			Prefix:      []byte(keyData.Name + ":"),
		})
	}

	// Create a prefixTransformer which can choose between these keys
	keyTransformer := value.NewPrefixTransformers(fmt.Errorf("no matching key was found for the provided SM4 transformer"), keyTransformers...)

	// Create a PrefixTransformer which shall later be put in a list with other providers
	return value.PrefixTransformer{
		Transformer: keyTransformer,
		Prefix:      []byte(prefix),
	}, nil
}

// getEnvelopePrefixTransformer returns a prefix transformer from the provided config.
// envelopeService is used as the root of trust.
func getEnvelopePrefixTransformer(config *apiserverconfig.KMSConfiguration, envelopeService envelope.Service, prefix string) (value.PrefixTransformer, error) {
	newCBCTransformer := func(key []byte) (value.Transformer, error) {
		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return aestransformer.NewCBCTransformer(c), nil
	}
	envelopeTransformer, err := envelope.NewEnvelopeTransformer(envelopeService, int(config.CacheSize), 32, newCBCTransformer)
	if err != nil {
		return value.PrefixTransformer{}, err
	}
	return value.PrefixTransformer{
		Transformer: envelopeTransformer,
		Prefix:      []byte(prefix + config.Name + ":"),
	}, nil
}
