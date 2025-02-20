// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlidp/user_test.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package samlidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestUsersCrud(t *testing.T) {
	test := NewServerTest(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/users/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"users\":[]}\n", w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/users/alice",
		strings.NewReader(`{"name": "alice", "password": "hunter2"}`+"\n"))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/users/alice", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"name\":\"alice\"}\n", w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/users/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"users\":[\"alice\"]}\n", w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/users/alice", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/users/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"users\":[]}\n", w.Body.String()))
}
