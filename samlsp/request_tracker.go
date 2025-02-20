// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlsp/request_tracker.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package samlsp

import (
	"net/http"
)

// RequestTracker tracks pending authentication requests.
//
// There are two main reasons for this:
//
//  1. When the middleware initiates an authentication request it must track the original URL
//     in order to redirect the user to the right place after the authentication completes.
//
//  2. After the authentication completes, we want to ensure that the user presenting the
//     assertion is actually the one the request it, to mitigate request forgeries.
type RequestTracker interface {
	// TrackRequest starts tracking the SAML request with the given ID. It returns an
	// `index` that should be used as the RelayState in the SAMl request flow.
	TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (index string, err error)

	// StopTrackingRequest stops tracking the SAML request given by index, which is a string
	// previously returned from TrackRequest
	StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error

	// GetTrackedRequests returns all the pending tracked requests
	GetTrackedRequests(r *http.Request) []TrackedRequest

	// GetTrackedRequest returns a pending tracked request.
	GetTrackedRequest(r *http.Request, index string) (*TrackedRequest, error)
}

// TrackedRequest holds the data we store for each pending request.
type TrackedRequest struct {
	Index         string `json:"-"`
	SAMLRequestID string `json:"id"`
	URI           string `json:"uri"`
}

// TrackedRequestCodec handles encoding and decoding of a TrackedRequest.
type TrackedRequestCodec interface {
	// Encode returns an encoded string representing the TrackedRequest.
	Encode(value TrackedRequest) (string, error)

	// Decode returns a Tracked request from an encoded string.
	Decode(signed string) (*TrackedRequest, error)
}
