/*
Copyright 2015 The Kubernetes Authors.

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

package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"k8s.io/klog"
)

const onDiskKeyReloadThreshold = time.Hour

// New returns an http.RoundTripper that will provide the authentication
// or transport level security defined by the provided Config.
func New(config *Config) (http.RoundTripper, error) {
	// Set transport level security
	if config.Transport != nil && (config.HasCA() || config.HasCertAuth() || config.HasCertCallback() || config.TLS.Insecure) {
		return nil, fmt.Errorf("using a custom transport with TLS certificate options or the insecure flag is not allowed")
	}

	var (
		rt  http.RoundTripper
		err error
	)

	if config.Transport != nil {
		rt = config.Transport
	} else {
		rt, err = tlsCache.get(config)
		if err != nil {
			return nil, err
		}
	}

	return HTTPWrappersForConfig(config, rt)
}

// TLSConfigFor returns a tls.Config that will provide the transport level security defined
// by the provided Config. Will return nil if no transport level security is requested.
func TLSConfigFor(c *Config) (*tls.Config, error) {
	if !(c.HasCA() || c.HasCertAuth() || c.HasCertCallback() || c.TLS.Insecure || len(c.TLS.ServerName) > 0) {
		return nil, nil
	}
	if c.HasCA() && c.TLS.Insecure {
		return nil, fmt.Errorf("specifying a root certificates file with the insecure flag is not allowed")
	}
	if err := loadTLSCAFile(c); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.TLS.Insecure,
		ServerName:         c.TLS.ServerName,
	}

	if c.HasCA() {
		tlsConfig.RootCAs = rootCertPool(c.TLS.CAData)
	}

	var staticCert *tls.Certificate
	if len(c.TLS.CertData) > 0 && len(c.TLS.KeyData) > 0 {
		// If key/cert were provided raw, parse them before setting up
		// tlsConfig.GetClientCertificate.
		cert, err := tls.X509KeyPair(c.TLS.CertData, c.TLS.KeyData)
		if err != nil {
			return nil, err
		}
		staticCert = &cert
	}
	if len(c.TLS.CertFile) > 0 && len(c.TLS.KeyFile) > 0 {
		// On-disk key and certificate could be rotated by an external process.
		// Reload them periodically.
		rc, err := newReloadingCert(c.TLS.CertFile, c.TLS.KeyFile, onDiskKeyReloadThreshold)
		if err != nil {
			return nil, err
		}
		c.TLS.GetCert = rc.getCert
	}

	if c.HasCertAuth() || c.HasCertCallback() {
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Note: static key/cert data always take precedence over cert
			// callback.
			if staticCert != nil {
				return staticCert, nil
			}
			if c.HasCertCallback() {
				cert, err := c.TLS.GetCert()
				if err != nil {
					return nil, err
				}
				// GetCert may return empty value, meaning no cert.
				if cert != nil {
					return cert, nil
				}
			}

			// Both c.TLS.CertData/KeyData were unset and GetCert didn't return
			// anything. Return an empty tls.Certificate, no client cert will
			// be sent to the server.
			return &tls.Certificate{}, nil
		}
	}

	return tlsConfig, nil
}

// loadTLSCAFile copies the data from the CAFile field into the CAFile field,
// or returns an error.
func loadTLSCAFile(c *Config) error {
	if len(c.TLS.CAData) > 0 {
		return nil
	}
	if len(c.TLS.CAFile) == 0 {
		return nil
	}
	data, err := ioutil.ReadFile(c.TLS.CAFile)
	if err != nil {
		return err
	}
	c.TLS.CAData = data
	return nil
}

// rootCertPool returns nil if caData is empty.  When passed along, this will mean "use system CAs".
// When caData is not empty, it will be the ONLY information used in the CertPool.
func rootCertPool(caData []byte) *x509.CertPool {
	// What we really want is a copy of x509.systemRootsPool, but that isn't exposed.  It's difficult to build (see the go
	// code for a look at the platform specific insanity), so we'll use the fact that RootCAs == nil gives us the system values
	// It doesn't allow trusting either/or, but hopefully that won't be an issue
	if len(caData) == 0 {
		return nil
	}

	// if we have caData, use it
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caData)
	return certPool
}

// WrapperFunc wraps an http.RoundTripper when a new transport
// is created for a client, allowing per connection behavior
// to be injected.
type WrapperFunc func(rt http.RoundTripper) http.RoundTripper

// Wrappers accepts any number of wrappers and returns a wrapper
// function that is the equivalent of calling each of them in order. Nil
// values are ignored, which makes this function convenient for incrementally
// wrapping a function.
func Wrappers(fns ...WrapperFunc) WrapperFunc {
	if len(fns) == 0 {
		return nil
	}
	// optimize the common case of wrapping a possibly nil transport wrapper
	// with an additional wrapper
	if len(fns) == 2 && fns[0] == nil {
		return fns[1]
	}
	return func(rt http.RoundTripper) http.RoundTripper {
		base := rt
		for _, fn := range fns {
			if fn != nil {
				base = fn(base)
			}
		}
		return base
	}
}

// ContextCanceller prevents new requests after the provided context is finished.
// err is returned when the context is closed, allowing the caller to provide a context
// appropriate error.
func ContextCanceller(ctx context.Context, err error) WrapperFunc {
	return func(rt http.RoundTripper) http.RoundTripper {
		return &contextCanceller{
			ctx: ctx,
			rt:  rt,
			err: err,
		}
	}
}

type contextCanceller struct {
	ctx context.Context
	rt  http.RoundTripper
	err error
}

func (b *contextCanceller) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-b.ctx.Done():
		return nil, b.err
	default:
		return b.rt.RoundTrip(req)
	}
}

// reloadingCert provides a tls.GetCertificate callback for on-disk key/cert
// pair. It keeps a cached certificate and attempts a reload after the
// reloadThreshold.
//
// If reload fails, last read certificate gets returned.
//
// reloadingCert does not verify loaded certificate validity or expiration.
//
// reloadingCert is thread safe.
type reloadingCert struct {
	keyPath         string
	certPath        string
	reloadThreshold time.Duration

	mu       *sync.RWMutex
	current  tls.Certificate
	lastLoad time.Time
}

func newReloadingCert(certPath, keyPath string, reloadThreshold time.Duration) (*reloadingCert, error) {
	if reloadThreshold <= 0 {
		return nil, fmt.Errorf("reloadThreshold must be positive, got %v", reloadThreshold)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed loading key/certificate from disk: %v", err)
	}

	return &reloadingCert{
		keyPath:         keyPath,
		certPath:        certPath,
		reloadThreshold: reloadThreshold,
		mu:              new(sync.RWMutex),
		current:         cert,
		lastLoad:        time.Now(),
	}, nil
}

func (c *reloadingCert) getCert() (*tls.Certificate, error) {
	c.mu.RLock()
	lastLoad := c.lastLoad
	if time.Since(lastLoad) < c.reloadThreshold {
		return &c.current, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if lastLoad != c.lastLoad {
		// Another goroutine already reloaded key/cert. Avoid unnecessary disk
		// reads.
		return &c.current, nil
	}

	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		klog.Errorf("failed reloading key/certificate from disk, re-using last-loaded values; error: %v", err)
		return &c.current, nil
	}
	c.current = cert
	c.lastLoad = time.Now()
	return &cert, nil
}
