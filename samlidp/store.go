// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlidp/store.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package samlidp

import "errors"

// ErrNotFound is returned from Store.Get() when a stored item is not present
var ErrNotFound = errors.New("not found")

// Store is an interface that describes an abstract key-value store.
type Store interface {
	// Get fetches the data stored in `key` and unmarshals it into `value`.
	Get(key string, value interface{}) error

	// Put marshals `value` and stores it in `key`.
	Put(key string, value interface{}) error

	// Delete removes `key`
	Delete(key string) error

	// List returns all the keys that start with `prefix`. The prefix is
	// stripped from each returned value. So if keys are ["aa", "ab", "cd"]
	// then List("a") would produce []string{"a", "b"}
	List(prefix string) ([]string, error)
}
