// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/util.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package saml

import (
	"crypto/rand"
	"io"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// TimeNow is a function that returns the current time. The default
// value is time.Now, but it can be replaced for testing.
var TimeNow = func() time.Time { return time.Now().UTC() }

// Clock is assigned to dsig validation and signing contexts if it is
// not nil, otherwise the default clock is used.
var Clock *dsig.Clock

// RandReader is the io.Reader that produces cryptographically random
// bytes when they are need by the library. The default value is
// rand.Reader, but it can be replaced for testing.
var RandReader = rand.Reader

//nolint:unparam // This always receives 20, but we want the option to do more or less if needed.
func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}
