/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/binary"
	"fmt"
)

const (
	commentAssertionIDOwnedBy byte = 1

	commentReasonNone                                     byte = 0 // No reason given
	commentReasonAutomaticallyFlaggedTemporallySubjective byte = 1 // Alice's record arrived before Bob's at a node
	commentReasonManuallyFlagged                          byte = 2 // A meat sack said so
)

// comment describes a record datum in a commentary record generated by a node.
type comment struct {
	subject   []byte
	object    []byte
	assertion byte
	reason    byte
}

func (c *comment) string() string {
	var reason string
	switch c.assertion {
	case commentAssertionIDOwnedBy:
		switch c.reason {
		case commentReasonNone:
			reason = "no reason given"
		case commentReasonAutomaticallyFlaggedTemporallySubjective:
			reason = "automatically flagged, temporally subjective"
		case commentReasonManuallyFlagged:
			reason = "manually flagged"
		default:
			reason = fmt.Sprintf("unknown reason %.2x", c.reason)
		}
		return fmt.Sprintf("ID %x owned by %x (%s)", c.object, c.subject, reason)
	}
	return fmt.Sprintf("unknown assertion %.2x subject %x object %x reason %.2x", c.assertion, c.subject, c.object, c.reason)
}

func (c *comment) appendTo(b []byte) []byte {
	var tmp [10]byte
	b = append(b, c.assertion, c.reason)
	b = append(b, tmp[0:binary.PutUvarint(tmp[:], uint64(len(c.subject)))]...)
	b = append(b, c.subject...)
	b = append(b, tmp[0:binary.PutUvarint(tmp[:], uint64(len(c.object)))]...)
	b = append(b, c.object...)
	return b
}

func (c *comment) readFrom(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, ErrInvalidObject
	}

	c.assertion = b[0]
	c.reason = b[1]

	subLen, bytesRead := binary.Uvarint(b[2:])
	if bytesRead <= 0 {
		return nil, ErrInvalidObject
	}
	b = b[2+bytesRead:]
	if int(subLen) >= len(b) { // >= since at least one byte of objLen will follow subject
		return nil, ErrInvalidObject
	}
	if subLen > 0 {
		c.subject = make([]byte, uint(subLen))
		copy(c.subject, b[0:len(c.subject)])
		b = b[len(c.subject):]
	} else {
		c.subject = nil
	}

	objLen, bytesRead := binary.Uvarint(b[0:])
	if bytesRead <= 0 {
		return nil, ErrInvalidObject
	}
	b = b[bytesRead:]
	if int(objLen) > len(b) {
		return nil, ErrInvalidObject
	}
	if objLen > 0 {
		c.object = make([]byte, uint(objLen))
		copy(c.object, b[0:len(c.object)])
		b = b[len(c.object):]
	} else {
		c.object = nil
	}

	return b, nil
}