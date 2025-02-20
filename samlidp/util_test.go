// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlidp/util_test.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

//go:build go1.17
// +build go1.17

package samlidp

import (
	"strings"
	"testing"

	"gotest.tools/assert"
)

func TestGetSPMetadata(t *testing.T) {
	good := "" +
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2013-03-10T00:32:19.104Z\" cacheDuration=\"PT1H\" entityID=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/\">\n" +
		"</EntityDescriptor>"
	_, err := getSPMetadata(strings.NewReader(good))
	assert.Check(t, err)

	bad := "" +
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" ::attr=\"foo\" validUntil=\"2013-03-10T00:32:19.104Z\" cacheDuration=\"PT1H\" entityID=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/\">]]>\n" +
		"</EntityDescriptor>"
	_, err = getSPMetadata(strings.NewReader(bad))
	assert.Check(t, err != nil)
}
