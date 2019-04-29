/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import "fmt"

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
	ErrInvalidPublicKey   Err = "invalid public key"
	ErrInvalidPrivateKey  Err = "invalid private key"
	ErrInvalidParameter   Err = "invalid parameter"
	ErrInvalidObject      Err = "invalid object"
	ErrUnsupportedType    Err = "unsupported type"
	ErrUnsupportedCurve   Err = "unsupported ECC curve (for this purpose)"
	ErrOutOfRange         Err = "parameter out of range"
	ErrWharrgarblFailed   Err = "Wharrgarbl proof of work algorithm failed (out of memory?)"
	ErrIO                 Err = "I/O error"
	ErrIncorrectKey       Err = "incorrect key"
	ErrAlreadyConnected   Err = "already connected"
	ErrDuplicateRecord    Err = "duplicate record"
	ErrPrivateKeyRequired Err = "private key required"
)

// Errs indicating that a record is invalid
const (
	ErrRecordInvalid                   ErrRecord = "record invalid"
	ErrRecordOwnerSignatureCheckFailed ErrRecord = "owner signature check failed"
	ErrRecordSelectorClaimCheckFailed  ErrRecord = "selector claim check failed"
	ErrRecordInsufficientWork          ErrRecord = "insufficient work to pay for this record"
	ErrRecordInsufficientLinks         ErrRecord = "insufficient links"
	ErrRecordUnsupportedAlgorithm      ErrRecord = "unsupported algorithm or type"
	ErrRecordTooLarge                  ErrRecord = "record too large"
	ErrRecordValueTooLarge             ErrRecord = "record value too large"
	ErrRecordViolatesSpecialRelativity ErrRecord = "record timestamp too far in the future"
	ErrRecordTooOld                    ErrRecord = "record older than network timestamp floor"
	ErrRecordCertificateInvalid        ErrRecord = "certificate invalid"
	ErrRecordCertificateRequired       ErrRecord = "certificate required"
	ErrRecordMarkedIgnore              ErrRecord = "record marked 'ignore' in file or stream"
)
