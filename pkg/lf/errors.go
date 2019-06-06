/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package lf

import (
	"fmt"
)

// Err indicates a general LF error such as an invalid parameter or state.
type Err string

func (e Err) Error() string { return (string)(e) }

// ErrRecord indicates an error related to an invalid record or a record failing a check.
type ErrRecord string

func (e ErrRecord) Error() string { return (string)(e) }

// ErrTrappedPanic indicates a panic trapped by recover() and returned as an error.
type ErrTrappedPanic struct {
	PanicErr interface{}
}

func (e ErrTrappedPanic) Error() string {
	return fmt.Sprintf("trapped unexpected panic: %v", e.PanicErr)
}

// ErrDatabase contains information about a database related problem.
type ErrDatabase struct {
	// ErrCode is the error code returned by the C database module.
	ErrCode int

	// ErrMessage is an error message supplied by the C code or by Go (optional)
	ErrMessage string
}

func (e ErrDatabase) Error() string {
	return fmt.Sprintf("database error: %d (%s)", e.ErrCode, e.ErrMessage)
}

// General errors
const (
	ErrInvalidPublicKey       Err = "invalid public key"
	ErrInvalidPrivateKey      Err = "invalid private key"
	ErrInvalidParameter       Err = "invalid parameter"
	ErrInvalidObject          Err = "invalid object"
	ErrUnsupportedType        Err = "unsupported type"
	ErrUnsupportedCurve       Err = "unsupported ECC curve (for this purpose)"
	ErrOutOfRange             Err = "parameter out of range"
	ErrWharrgarblFailed       Err = "Wharrgarbl proof of work algorithm failed (out of memory?)"
	ErrIO                     Err = "I/O error"
	ErrIncorrectKey           Err = "incorrect key"
	ErrAlreadyConnected       Err = "already connected"
	ErrDuplicateRecord        Err = "duplicate record"
	ErrPrivateKeyRequired     Err = "private key required"
	ErrInvalidMessageSize     Err = "message size invalid"
	ErrQueryRequiresSelectors Err = "query requires at least one selector"
	ErrQueryInvalidSortOrder  Err = "invalid sort order value"
	ErrAlreadyMounted         Err = "mount point already mounted"
)

// Errs indicating that a record is invalid
const (
	ErrRecordInvalid                   ErrRecord = "record invalid"
	ErrRecordOwnerSignatureCheckFailed ErrRecord = "owner signature check failed"
	ErrRecordInsufficientWork          ErrRecord = "insufficient work to pay for this record"
	ErrRecordNotApproved               ErrRecord = "record not currently approved (via proof of work and/or certificates)"
	ErrRecordInsufficientLinks         ErrRecord = "insufficient links"
	ErrRecordTooManyLinks              ErrRecord = "too many links"
	ErrRecordInvalidLinks              ErrRecord = "links must be sorted and unique"
	ErrRecordTooManySelectors          ErrRecord = "too many selectors"
	ErrRecordUnsupportedAlgorithm      ErrRecord = "unsupported algorithm or type"
	ErrRecordTooLarge                  ErrRecord = "record too large"
	ErrRecordValueTooLarge             ErrRecord = "record value too large"
	ErrRecordViolatesSpecialRelativity ErrRecord = "record timestamp too far in the future"
	ErrRecordTooOld                    ErrRecord = "record older than network timestamp floor"
	ErrRecordCertificateInvalid        ErrRecord = "certificate invalid"
	ErrRecordCertificateRequired       ErrRecord = "certificate required"
	ErrRecordProhibited                ErrRecord = "record administratively prohibited"
)
