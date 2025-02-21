// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlsp/samlsp_test.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package samlsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/golden"
)

type mockTransport func(req *http.Request) (*http.Response, error)

func (mt mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return mt(req)
}

func mustParseURL(s string) url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *rv
}

func mustParsePrivateKey(pemStr []byte) crypto.PrivateKey {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

func mustParseCertificate(pemStr []byte) *x509.Certificate {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

func TestCanParseTestshibMetadata(t *testing.T) {
	httpClient := http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			responseBody := golden.Get(t, "testshib_metadata.xml")
			return &http.Response{
				Header:     http.Header{},
				Request:    req,
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		}),
	}

	_, err := FetchMetadata(context.Background(),
		&httpClient,
		mustParseURL("https://ipa.example.com/idp/saml2/metadata"))
	assert.Check(t, err)
}
