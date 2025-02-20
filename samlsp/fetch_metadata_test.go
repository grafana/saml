// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlsp/fetch_metadata_test.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package samlsp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestFetchMetadata(t *testing.T) {
	test := NewMiddlewareTest(t)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Check(t, is.Equal("/metadata", r.URL.String()))
		_, err := w.Write(test.IDPMetadata)
		assert.Check(t, err)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.Check(t, err)
	assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", md.EntityID))
}

func TestFetchMetadataRejectsInvalid(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.IDPMetadata = bytes.ReplaceAll(test.IDPMetadata,
		[]byte("<EntityDescriptor "), []byte("<EntityDescriptor ::foo=\"bar\">]]"))

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Check(t, is.Equal("/metadata", r.URL.String()))
		_, err := w.Write(test.IDPMetadata)
		assert.Check(t, err)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.Check(t, err != nil)
	assert.Check(t, is.Nil(md))
}
