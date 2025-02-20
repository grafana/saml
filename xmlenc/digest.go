// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/xmlenc/digest.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package xmlenc

import (
	"crypto/sha1" //nolint:gosec // required for protocol support
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck,gosec // We should support this for legacy reasons.
)

type digestMethod struct {
	algorithm string
	hash      func() hash.Hash
}

func (dm digestMethod) Algorithm() string {
	return dm.algorithm
}

func (dm digestMethod) Hash() hash.Hash {
	return dm.hash()
}

var (
	// SHA1 implements the SHA-1 digest method (which is considered insecure)
	SHA1 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
		hash:      sha1.New,
	}

	// SHA256 implements the SHA-256 digest method
	SHA256 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#sha256",
		hash:      sha256.New,
	}

	// SHA512 implements the SHA-512 digest method
	SHA512 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#sha512",
		hash:      sha512.New,
	}

	// RIPEMD160 implements the RIPEMD160 digest method
	RIPEMD160 = digestMethod{
		algorithm: "http://www.w3.org/2000/09/xmldsig#ripemd160",
		hash:      ripemd160.New,
	}
)

func init() {
	RegisterDigestMethod(SHA1)
	RegisterDigestMethod(SHA256)
	RegisterDigestMethod(SHA512)
	RegisterDigestMethod(RIPEMD160)
}
