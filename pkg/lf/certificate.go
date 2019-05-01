/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

// TODO: this code is unfinished! It's not needed for the public network anyway.

/*
import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// Certificate wraps x509.Certificate with accessors specific to LF certificates.
type Certificate struct {
	X509 x509.Certificate
}

// NewCertificate creates a new LF certificate.
func NewCertificate(name *pkix.Name, lifeSpan time.Duration) (*Certificate, error) {
	notBefore := time.Now()
	cert := Certificate{
		X509: x509.Certificate{
			SerialNumber:          nil,
			Subject:               *name,
			NotBefore:             notBefore,
			NotAfter:              notBefore.Add(lifeSpan),
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
		},
	}

	return &cert, nil
}
*/
