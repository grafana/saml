// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/saml_gen.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

package saml

//go:generate bash -c "(cat README.md | grep -E -v '^# SAML' | sed 's|^## ||g' | sed 's|\\*\\*||g' | sed 's|^|// |g'; echo 'package saml') > saml.go"
